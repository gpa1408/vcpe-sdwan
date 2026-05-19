FROM alpine:3.21 AS builder

RUN apk add --no-cache \
    git \
    build-base \
    autoconf \
    automake \
    libtool \
    pkgconf \
    bison \
    flex \
    linux-headers \
    openssl-dev \
    json-c-dev \
    libxml2-dev \
    zlib-dev \
    readline-dev \
    ncurses-dev \
    curl-dev \
    ca-certificates \
    file \
    tar \
    gzip

WORKDIR /tmp/build

# ---- Build CLIgen ----
RUN git clone --depth 1 https://github.com/clicon/cligen.git && \
    cd cligen && \
    ./configure && \
    make -j"$(nproc)" && \
    make install

# ---- Build Clixon ----
RUN git clone --depth 1 https://github.com/clicon/clixon.git && \
    cd clixon && \
    ./configure --with-restconf=native --disable-nghttp2 && \
    make -j"$(nproc)" && \
    make install

# ---- Build Clixon callback plugins ----
COPY clixon/clixon_config_diff_callback_plugin.c /tmp/clixon_config_diff_callback_plugin.c
COPY clixon/clixon_state_callback_plugin.c /tmp/clixon_state_callback_plugin.c

RUN mkdir -p /tmp/clixon-plugins && \
    gcc -fPIC -shared \
      -o /tmp/clixon-plugins/clixon_config_diff_callback_plugin.so \
      /tmp/clixon_config_diff_callback_plugin.c \
      -I/usr/local/include \
      -L/usr/local/lib \
      -lclixon -lcligen && \
    gcc -fPIC -shared \
      -o /tmp/clixon-plugins/clixon_state_callback_plugin.so \
      /tmp/clixon_state_callback_plugin.c \
      -I/usr/local/include \
      -L/usr/local/lib \
      -lclixon -lcligen -lcurl


FROM python:3.13-alpine3.21

ENV PYTHONUNBUFFERED=1 \
    CLIXON_CONFIG=/etc/clixon/clixon-config.xml \
    LD_LIBRARY_PATH=/usr/local/lib \
    PYTHONPATH=/app \
    PATH=/usr/local/sbin:/usr/local/bin:$PATH

RUN apk add --no-cache \
    ca-certificates \
    curl \
    openssl \
    json-c \
    libxml2 \
    zlib \
    readline \
    ncurses-libs \
    libstdc++ \
    libgcc \
    libcurl \
    libffi

WORKDIR /app

# ---- Copy compiled Clixon + CLIgen from builder ----
COPY --from=builder /usr/local/ /usr/local/

# ---- Copy compiled Clixon plugins from builder ----
RUN mkdir -p /usr/local/lib/clixon/backend
COPY --from=builder /tmp/clixon-plugins/*.so /usr/local/lib/clixon/backend/

# ---- Python dependencies ----
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# ---- Application + Clixon config ----
COPY app/ /app/
COPY clixon/ /etc/clixon/
COPY entrypoint.sh /entrypoint.sh

RUN mkdir -p /etc/clixon/yang && \
    cp /usr/local/share/clixon/clixon-restconf*.yang /etc/clixon/yang/ || true

RUN chmod +x /entrypoint.sh && \
    mkdir -p \
      /var/lib/clixon \
      /run/clixon \
      /var/lib/sdwan-cpe/keys \
      /var/lib/clixon/local-public-keys \
      /var/lib/clixon/wan-link-nat-types

ENTRYPOINT ["/entrypoint.sh"]
