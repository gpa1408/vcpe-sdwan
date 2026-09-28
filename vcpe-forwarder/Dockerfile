FROM python:3.13-alpine3.21

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    FORWARDER_HOST=0.0.0.0 \
    FORWARDER_PORT=9090

RUN apk add --no-cache \
    iproute2 \
    iptables \
    nftables \
    wireguard-tools \
    busybox \
    busybox-extras \
    curl \
    ca-certificates \
    dnsmasq \
    bash

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY forwarder /app/forwarder
COPY forwarder-udhcpc-script /usr/local/sbin/forwarder-udhcpc-script
RUN chmod 0755 /usr/local/sbin/forwarder-udhcpc-script \
    && mkdir -p /app/var/lib/forwarder /run/forwarder/dhcp

CMD ["uvicorn", "forwarder.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "9090"]
