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

CMD ["sh", "-c", "exec uvicorn \"$APP_MODULE\" --host 0.0.0.0 --port \"${PORT:-8080}\""]
