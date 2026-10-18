FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY app /app/app

RUN adduser --disabled-password --gecos "" appuser && chown -R appuser /app
USER appuser

ENV APP_MODULE=app.canvasser.main:app

# No access log: it would record every canvasser's IP address and route.
# Set FORWARDED_ALLOW_IPS to your reverse proxy's address so rate limits see real client IPs.
CMD ["sh", "-c", "exec uvicorn \"$APP_MODULE\" --host 0.0.0.0 --port \"${PORT:-8080}\" --no-access-log --no-server-header"]
