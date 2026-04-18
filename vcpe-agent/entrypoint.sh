#!/bin/sh
set -eu

CFG="${CLIXON_CONFIG:-/etc/clixon/clixon-config.xml}"
BACKEND_BIN="/usr/local/sbin/clixon_backend"
RESTCONF_BIN="/usr/local/sbin/clixon_restconf"

mkdir -p /var/lib/clixon
mkdir -p /run/clixon

# Si no existe startup_db persistente, copiamos el inicial
if [ ! -f /var/lib/clixon/startup_db ] && [ -f /etc/clixon/startup_db ]; then
  cp /etc/clixon/startup_db /var/lib/clixon/startup_db
fi

cleanup() {
  echo "[entrypoint] stopping services..."
  kill "${AGENT_PID:-}" 2>/dev/null || true
  kill "${RESTCONF_PID:-}" 2>/dev/null || true
  kill "${BACKEND_PID:-}" 2>/dev/null || true
  wait || true
}

trap cleanup INT TERM

echo "[entrypoint] starting clixon_backend..."
"$BACKEND_BIN" -s running -f "$CFG" &
BACKEND_PID=$!

sleep 2
if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
  echo "[entrypoint] clixon_backend failed"
  exit 1
fi

echo "[entrypoint] starting clixon_restconf..."
"$RESTCONF_BIN" -f "$CFG" &
RESTCONF_PID=$!

sleep 2
if ! kill -0 "$RESTCONF_PID" 2>/dev/null; then
  echo "[entrypoint] clixon_restconf failed"
  cleanup
  exit 1
fi

echo "[entrypoint] starting python agent..."
python3 -m app.main &
AGENT_PID=$!

EXIT_CODE=0

while true; do
  if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
    echo "[entrypoint] clixon_backend exited"
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