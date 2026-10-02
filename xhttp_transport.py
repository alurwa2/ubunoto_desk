# xhttp_transport.py
# ==============================================================================
# ترابرد XHTTP برای Luffy Panel - دو مد: packet-up / stream-up
# استفاده از همون quota/connections/max_connections خود main.py
# طبق max_connections خود IP - بدون هیچ محدودیت جداگانه‌ای
# (سنجیده می‌شه max_connections درخواست، فقط)
# ==============================================================================

import asyncio
import secrets
import socket
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import StreamingResponse

router = APIRouter()

XHTTP_BUF = 256 * 1024
SESSION_IDLE_TIMEOUT = 30
REAPER_INTERVAL = 10
TCP_CONNECT_TIMEOUT = 10.0
DOWNLINK_QUEUE_MAX = 512

xhttp_sessions: dict = {}
XHTTP_LOCK = asyncio.Lock()


def _tune_socket(writer: asyncio.StreamWriter):
    sock = writer.transport.get_extra_info("socket")
    if not sock:
        return
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass


async def _check_link_active(uid: str) -> dict:
    from main import LINKS, LINKS_LOCK
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None or not link.get("active"):
            raise HTTPException(status_code=403, detail="not authorized")
        return dict(link)


async def _get_or_create_session(uid: str, auth: str, mode: str, session_id: str, ip: str) -> dict:
    from main import (
        connections,
        connections_lock,
        connection_sockets,
        link_ip_map,
        _log_connection_event,
        response_prefix_for_protocol,
        count_connections_for_link,
    )
    async with XHTTP_LOCK:
        sess = xhttp_sessions.get(session_id)
        if sess is not None:
            sess["last_seen"] = time.time()
            return sess

        link = await _check_link_active(uid)
        variant = link.get("variants", {}).get(auth)
        if not variant or not variant.get("enabled") or variant.get("transport") != f"xhttp-{mode}":
            raise HTTPException(status_code=403, detail="not authorized")
        
        max_conn = link.get("max_connections", 0)
        if max_conn > 0 and await count_connections_for_link(uid) >= max_conn:
            raise HTTPException(status_code=403, detail="max connections reached")

        conn_id = secrets.token_urlsafe(8)
        async with connections_lock:
            connections[conn_id] = {
                "uuid": uid,
                "ip": ip,
                "connected_at": datetime.now(timezone.utc).isoformat(),
                "bytes": 0,
                "transport": f"xhttp-{mode}",
            }
            connection_sockets.pop(conn_id, None)
            link_ip_map[uid].add(ip)

        await _log_connection_event("connect", link.get("label", uid), uid, ip)

        sess = {
            "uid": uid,
            "auth": auth,
            "mode": mode,
            "conn_id": conn_id,
            "ip": ip,
            "writer": None,
            "tcp_open": False,
            "down_q": asyncio.Queue(maxsize=DOWNLINK_QUEUE_MAX),
            "seq_buf": {},
            "next_seq": 0,
            "last_seen": time.time(),
            "closed": False,
            "resp_prefix": response_prefix_for_protocol(auth),
        }
        xhttp_sessions[session_id] = sess
        return sess


async def _teardown(session_id: str):
    from main import (
        connections,
        connections_lock,
        connection_sockets,
        link_ip_map,
        _log_connection_event,
        LINKS,
        LINKS_LOCK,
        logger,
        fmt_bytes,
    )
    async with XHTTP_LOCK:
        sess = xhttp_sessions.pop(session_id, None)
        if not sess or sess.get("closed"):
            return
        sess["closed"] = True
        writer = sess.get("writer")

    if writer:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    conn_id = sess.get("conn_id")
    uid = sess.get("uid")
    ip = sess.get("ip")
    info = None

    async with connections_lock:
        info = connections.pop(conn_id, None)
        connection_sockets.pop(conn_id, None)
        if info and uid and ip:
            has_other = any(c.get("uuid") == uid and c.get("ip") == ip for c in connections.values())
            if not has_other and uid in link_ip_map:
                link_ip_map[uid].discard(ip)
                if not link_ip_map[uid]:
                    link_ip_map.pop(uid, None)

    dq = sess.get("down_q")
    if dq:
        try:
            dq.put_nowait(None)
        except Exception:
            pass

    if info:
        try:
            connected_at = datetime.fromisoformat(info["connected_at"])
            duration_s = max(0, int((datetime.now(timezone.utc) - connected_at).total_seconds()))
        except Exception:
            duration_s = 0

        async with LINKS_LOCK:
            label = LINKS.get(uid, {}).get("label", uid)

        extra = f"duration={duration_s}s, {fmt_bytes(info.get('bytes', 0))}"
        await _log_connection_event("disconnect", label, uid, ip, extra)
        logger.info(f"closed XHTTP({sess.get('mode')}) [{session_id[:8]}] total={len(xhttp_sessions)}")


_reaper_started = False

async def _reaper():
    while True:
        await asyncio.sleep(REAPER_INTERVAL)
        now = time.time()
        async with XHTTP_LOCK:
            stale = [
                sid for sid, s in xhttp_sessions.items()
                if now - s["last_seen"] > SESSION_IDLE_TIMEOUT and not s.get("tcp_open")
            ]
        for sid in stale:
            await _teardown(sid)


def ensure_reaper():
    global _reaper_started
    if not _reaper_started:
        asyncio.create_task(_reaper())
        _reaper_started = True


def record_traffic(size: int, conn_id: str):
    from main import stats, hourly_traffic, daily_traffic, connections, connections_lock
    stats["total_bytes"] += size
    stats["total_requests"] += 1
    now = datetime.now(timezone.utc)
    hourly_traffic[now.strftime("%Y-%m-%d %H:00")] += size
    daily_traffic[now.strftime("%Y-%m-%d")] += size
    c = connections.get(conn_id)
    if c:
        c["bytes"] += size


async def _pump_tcp_to_queue(session_id: str, uid: str, reader: asyncio.StreamReader, down_q: asyncio.Queue, resp_prefix: bytes = b"\x00\x00"):
    from main import check_and_add_usage, save_db
    first = True
    try:
        while True:
            data = await reader.read(XHTTP_BUF)
            if not data:
                break
            if not await check_and_add_usage(uid, len(data)):
                break
            async with XHTTP_LOCK:
                sess = xhttp_sessions.get(session_id)
            if sess:
                record_traffic(len(data), sess["conn_id"])
            payload = (resp_prefix + data) if (first and resp_prefix) else data
            first = False
            await down_q.put(payload)
    except (asyncio.CancelledError, Exception):
        pass
    finally:
        await _teardown(session_id)
        asyncio.create_task(save_db())


async def _open_tcp_for_session(session_id: str, uid: str, str_sess: dict, first_chunk: bytes):
    from main import parse_proxy_header, logger
    auth = str_sess.get("auth", "vless")
    command, address, port, payload = await parse_proxy_header(auth, first_chunk)
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(address, port), timeout=TCP_CONNECT_TIMEOUT
    )
    _tune_socket(writer)
    if payload:
        writer.write(payload)
        await writer.drain()
    logger.info(f"connect XHTTP[{str_sess['mode']}] [{session_id[:8]}] -> {address}:{port}")
    str_sess["writer"] = writer
    str_sess["tcp_open"] = True
    str_sess["downlink_task"] = asyncio.create_task(
        _pump_tcp_to_queue(session_id, uid, reader, str_sess["down_q"], str_sess.get("resp_prefix", b"\x00\x00"))
    )


def downstream_gen(sess: dict):
    async def gen():
        while True:
            chunk = await sess["down_q"].get()
            if chunk is None:
                break
            sess["last_seen"] = time.time()
            yield chunk
    return gen()


_XHTTP_HEADERS = {
    "content-type": "application/grpc",
    "cache-control": "no-cache, no-store",
    "x-accel-buffering": "no",
}


@router.get("/xhttp/{auth}/{mode}/{uuid}/{session_id}")
async def xhttp_downlink(auth: str, mode: str, uuid: str, session_id: str, request: Request):
    from main import get_request_ip
    ip = get_request_ip(request)
    ensure_reaper()
    sess = await _get_or_create_session(uuid, auth, mode, session_id, ip)
    return StreamingResponse(downstream_gen(sess), headers=_XHTTP_HEADERS)
