FROM otel/opentelemetry-collector-contrib:0.140.1 AS otel

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       iproute2 \
       iputils-ping \
       iperf3 \
       ca-certificates \
       curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=otel /otelcol-contrib /usr/local/bin/otelcol-contrib
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY otel /etc/otel

EXPOSE 9100

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:${API_PORT:-9100}/health >/dev/null \
        && curl -fsS http://127.0.0.1:13133/ >/dev/null \
        || exit 1

CMD ["python", "-m", "app.supervisor"]
