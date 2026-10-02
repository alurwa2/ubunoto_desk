FROM python:3.10-slim

WORKDIR /app

# نصب پیش‌نیازهای سیستم‌عامل
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /lib/apt/lists/*

# کپی فایل پیش‌نیازها و نصب پکیج‌ها
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# کپی کل سورس‌کد به داخل کانتینر
COPY . .

# ایجاد دایرکتوری داده
RUN mkdir -p /data

EXPOSE 8080

CMD ["python", "main.py"]
