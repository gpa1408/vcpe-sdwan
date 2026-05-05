FROM python:3.13-alpine3.21

# ---- System packages needed to control the Linux dataplane ---- + busybox for tbs commands
RUN apk add --no-cache \
    iproute2 \
    iptables \
    nftables \
    wireguard-tools \
    busybox-extras \
    curl \
    ca-certificates

# ---- Runtime settings ----
WORKDIR /app

# ---- Python application ----
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app /app/forwarder

# ---- Persistent state directory (mounted via volume) ----
RUN mkdir -p /state
ENV STATE_DIR=/state


# ---- Entry point ----
CMD ["uvicorn", "forwarder.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "9090"]