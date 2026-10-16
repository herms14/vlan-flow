FROM python:3.12-slim

# Standard library only: no pip install needed.
WORKDIR /app
COPY server.py dashboard.html app.js style.css config.example.json ./

RUN useradd --system --uid 10001 --no-create-home vlanflow \
    && mkdir -p /data /config \
    && chown vlanflow /data

ENV VLANFLOW_CONFIG=/config/config.json \
    VLANFLOW_DB=/data/events.sqlite3 \
    VLANFLOW_HTTP_BIND=0.0.0.0 \
    VLANFLOW_PORT=8787 \
    VLANFLOW_SYSLOG_BIND=0.0.0.0 \
    VLANFLOW_SYSLOG_PORT=5514 \
    PYTHONUNBUFFERED=1

USER vlanflow
VOLUME ["/data"]
EXPOSE 8787/tcp 5514/udp

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ['VLANFLOW_PORT'], timeout=4)"

CMD ["python", "server.py"]
