#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="/tmp/odyssey_t1_tun_mtu_guard"
TOKEN_FILE="/tmp/odyssey_t1_tun_mtu_guard.token"

mkdir -p "$WORK_DIR"
printf '0123456789abcdefA\n' >"$TOKEN_FILE"

echo "[T1.6-MTU] test 1/2: reject mtu below minimum"
set +e
"$ROOT_DIR/bin/odyssey" gateway \
  --listen-control 127.0.0.1:29971 \
  --token-file "$TOKEN_FILE" \
  --tun-name ody6guard \
  --tun-cidr 10.221.0.1/24 \
  --route-allow 10.221.0.0/24 \
  --gateway-mtu 100 \
  --tls-mode disabled >"$WORK_DIR/mtu_low.log" 2>&1
RC=$?
set -e
if [ "$RC" -eq 0 ]; then
  echo "expected mtu guard failure for low mtu" >&2
  exit 1
fi
grep -q "Invalid --gateway-mtu value" "$WORK_DIR/mtu_low.log"
echo "[T1.6-MTU] ok 1/2"

echo "[T1.6-MTU] test 2/2: reject mtu above maximum"
set +e
"$ROOT_DIR/bin/odyssey" gateway \
  --listen-control 127.0.0.1:29972 \
  --token-file "$TOKEN_FILE" \
  --tun-name ody6guard2 \
  --tun-cidr 10.222.0.1/24 \
  --route-allow 10.222.0.0/24 \
  --gateway-mtu 20000 \
  --tls-mode disabled >"$WORK_DIR/mtu_high.log" 2>&1
RC=$?
set -e
if [ "$RC" -eq 0 ]; then
  echo "expected mtu guard failure for high mtu" >&2
  exit 1
fi
grep -q "Invalid --gateway-mtu value" "$WORK_DIR/mtu_high.log"
echo "[T1.6-MTU] ok 2/2"

echo "T1_TUN_MTU_GUARD_SMOKE_OK"
