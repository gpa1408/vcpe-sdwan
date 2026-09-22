#!/bin/sh
set -eu

BASE_URL="${BASE_URL:-http://127.0.0.1:9100}"
FLOW_ID="${FLOW_ID:-1001}"
WAN_LINK="${WAN_LINK:-UPL1}"
TARGET_IP="${TARGET_IP:-1.1.1.1}"
INTERVAL_SEC="${INTERVAL_SEC:-10}"

echo "== health =="
curl -fsS "$BASE_URL/health"
echo

echo "== start underlay flow job =="
curl -fsS -X POST "$BASE_URL/api/v1/monitoring/flows" \
  -H "Content-Type: application/json" \
  -d "{
    \"flow_id\":\"$FLOW_ID\",
    \"wan_link\":\"$WAN_LINK\",
    \"destination_ip\":\"$TARGET_IP\",
    \"probe_tools\":[\"ping\"],
    \"interval_sec\":$INTERVAL_SEC
  }"
echo

sleep 2

echo "== active jobs =="
curl -fsS "$BASE_URL/api/v1/monitoring/jobs"
echo

echo "== stop underlay flow job =="
curl -fsS -X DELETE "$BASE_URL/api/v1/monitoring/flows/$FLOW_ID/$WAN_LINK"
echo
