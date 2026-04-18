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


FROM python:3.13-alpine3.21

ENV PYTHONUNBUFFERED=1 \
    CLIXON_CONFIG=/etc/clixon/clixon-config.xml \
    LD_LIBRARY_PATH=/usr/local/lib \
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
    libcurl

WORKDIR /app

# ---- Copy compiled Clixon + CLIgen from builder ----
COPY --from=builder /usr/local/ /usr/local/

# ---- Python dependencies ----
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# ---- Application + Clixon config ----
COPY app/ /app/app/
COPY clixon/ /etc/clixon/
COPY entrypoint.sh /entrypoint.sh

RUN mkdir -p /etc/clixon/yang && \
    cp /usr/local/share/clixon/clixon-restconf*.yang /etc/clixon/yang/ || true

RUN chmod +x /entrypoint.sh && \
    mkdir -p /var/lib/clixon /run/clixon

ENTRYPOINT ["/entrypoint.sh"]