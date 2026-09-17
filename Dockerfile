FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN python -m pip install --no-cache-dir -r requirements.txt

COPY logscan_web ./logscan_web

RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /data/scans \
    && chown -R appuser:appuser /data
USER appuser

EXPOSE 8000
VOLUME ["/data"]

CMD ["sh", "-c", "gunicorn --workers 1 --threads 1 --timeout 300 --access-logfile - --error-logfile - --log-level info --bind 0.0.0.0:${PORT:-8000} logscan_web.app:app"]
