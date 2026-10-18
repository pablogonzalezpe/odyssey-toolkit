#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="/tmp/odyssey_t1_tun_create_linux"
TOKEN_FILE="/tmp/odyssey_t1_tun_create_linux.token"
PIDS=()

mkdir -p "$WORK_DIR"
printf '0123456789abcdefA\n' >"$TOKEN_FILE"

track_pid() {
  PIDS+=("$1")
}

cleanup() {
  local p
  for p in "${PIDS[@]}"; do
    kill "$p" 2>/dev/null || true
  done
}
trap cleanup EXIT

if ! command -v ip >/dev/null 2>&1; then
  echo "[T1.6] skip: ip command not available"
  exit 0
fi

echo "[T1.6] test 1/2: gateway creates and configures linux TUN"
TUN_IF="ody6$RANDOM"
"$ROOT_DIR/bin/odyssey" gateway \
  --listen-control 127.0.0.1:29970 \
  --token-file "$TOKEN_FILE" \
  --tun-name "$TUN_IF" \
  --tun-cidr 10.220.0.1/24 \
  --route-allow 10.220.0.0/24 \
  --gateway-mtu 1300 \
  --tls-mode disabled >"$WORK_DIR/gateway.log" 2>&1 &
GW_PID="$!"
track_pid "$GW_PID"
sleep 2

if ! kill -0 "$GW_PID" 2>/dev/null; then
  if grep -q "CAP_NET_ADMIN required" "$WORK_DIR/gateway.log"; then
    echo "[T1.6] skip: no CAP_NET_ADMIN in current environment"
    exit 0
  fi
  echo "gateway failed unexpectedly" >&2
  cat "$WORK_DIR/gateway.log" >&2 || true
  exit 1
fi

grep -q "tun_device=ready" "$WORK_DIR/gateway.log"
ip link show "$TUN_IF" >"$WORK_DIR/ip_link.out"
grep -q "mtu 1300" "$WORK_DIR/ip_link.out"
echo "[T1.6] ok 1/2"

echo "[T1.6] test 2/2: gateway process still running with tun device"
kill -0 "$GW_PID"
echo "[T1.6] ok 2/2"

echo "T1_TUN_CREATE_LINUX_SMOKE_OK"
