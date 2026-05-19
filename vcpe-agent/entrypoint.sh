#!/bin/sh
set -eu

CFG="${CLIXON_CONFIG:-/etc/clixon/clixon-config.xml}"
BACKEND_BIN="/usr/local/sbin/clixon_backend"
RESTCONF_BIN="/usr/local/sbin/clixon_restconf"

mkdir -p /var/lib/clixon
mkdir -p /run/clixon
mkdir -p /var/lib/sdwan-cpe/keys
mkdir -p /var/lib/clixon/local-public-keys
mkdir -p /var/lib/clixon/wan-link-nat-types

rm -f /run/clixon/clixon.sock
rm -f /run/clixon/clixon_backend.pid

if [ ! -f /var/lib/clixon/startup_db ] && [ -f /etc/clixon/startup_db ]; then
  cp /etc/clixon/startup_db /var/lib/clixon/startup_db
fi

cleanup() {
  echo "[entrypoint] stopping services..."
  kill "${AGENT_PID:-}" 2>/dev/null || true
  kill "${RESTCONF_PID:-}" 2>/dev/null || true

  if [ -f /run/clixon/clixon_backend.pid ]; then
    kill "$(cat /run/clixon/clixon_backend.pid)" 2>/dev/null || true
  fi

  wait || true
}

trap cleanup INT TERM

echo "[entrypoint] starting python agent..."
python3 -u /app/agent.py &
AGENT_PID=$!

echo "[entrypoint] waiting for python agent callback server..."
i=0
while true; do
  if python3 - <<'PY'
import socket
s = socket.socket()
s.settimeout(1)
try:
    s.connect(("127.0.0.1", 8080))
    s.close()
except Exception:
    raise SystemExit(1)
PY
  then
    break
  fi

  i=$((i+1))
  if [ "$i" -ge 30 ]; then
    echo "[entrypoint] python agent callback server failed to start"
    cleanup
    exit 1
  fi

  if ! kill -0 "$AGENT_PID" 2>/dev/null; then
    echo "[entrypoint] python agent exited before callback server became ready"
    cleanup
    exit 1
  fi

  sleep 1
done

echo "[entrypoint] starting clixon_backend..."
"$BACKEND_BIN" -s running -f "$CFG"

echo "[entrypoint] waiting for clixon backend socket..."
i=0
while [ ! -S /run/clixon/clixon.sock ] || [ ! -f /run/clixon/clixon_backend.pid ]; do
  i=$((i+1))
  if [ "$i" -ge 15 ]; then
    echo "[entrypoint] clixon_backend failed to create socket/pidfile"
    cleanup
    exit 1
  fi
  sleep 1
done

echo "[entrypoint] starting clixon_restconf..."
"$RESTCONF_BIN" -r -l e -D 1 -f "$CFG" &
RESTCONF_PID=$!

i=0
while true; do
  if kill -0 "$RESTCONF_PID" 2>/dev/null; then
    break
  fi
  i=$((i+1))
  if [ "$i" -ge 15 ]; then
    echo "[entrypoint] clixon_restconf failed"
    cleanup
    exit 1
  fi
  sleep 1
done

EXIT_CODE=0

while true; do
  if [ -f /run/clixon/clixon_backend.pid ]; then
    BACKEND_REAL_PID="$(cat /run/clixon/clixon_backend.pid)"
    if ! kill -0 "$BACKEND_REAL_PID" 2>/dev/null; then
      echo "[entrypoint] clixon_backend exited"
      EXIT_CODE=1
      break
    fi
  else
    echo "[entrypoint] clixon_backend pidfile missing"
    EXIT_CODE=1
    break
  fi

  if ! kill -0 "$RESTCONF_PID" 2>/dev/null; then
    echo "[entrypoint] clixon_restconf exited"
    EXIT_CODE=1
    break
  fi

  if ! kill -0 "$AGENT_PID" 2>/dev/null; then
    wait "$AGENT_PID" || EXIT_CODE=$?
    echo "[entrypoint] python agent exited"
    break
  fi

  sleep 2
done

cleanup
exit "$EXIT_CODE"
