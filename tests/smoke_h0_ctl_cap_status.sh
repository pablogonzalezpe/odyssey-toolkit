#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="/tmp/odyssey_h0_ctl_cap_status"
TOKEN_FILE="/tmp/odyssey_h0_token.txt"
PIDS=()

mkdir -p "$WORK_DIR"
printf '0123456789abcdef\n' >"$TOKEN_FILE"

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

echo "[H0] test 1/1: capabilities and status through control channel"
"$ROOT_DIR/bin/odyssey" reverse-server \
  --listen-control 127.0.0.1:28501 \
  --token-file "$TOKEN_FILE" \
  --tls-mode disabled \
  --bind 127.0.0.1:28580:127.0.0.1:18080 \
  --heartbeat-ms 1000 \
  --heartbeat-timeout-ms 5000 >"$WORK_DIR/rev_srv.log" 2>&1 &
track_pid "$!"
sleep 1
"$ROOT_DIR/bin/odyssey" reverse-client \
  --connect 127.0.0.1:28501 \
  --token-file "$TOKEN_FILE" \
  --tls-mode disabled \
  --ctl-capabilities \
  --ctl-status \
  --ctl-exit-after-admin \
  --heartbeat-timeout-ms 5000 \
  --verbose >"$WORK_DIR/rev_cli.log" 2>&1

grep -q "control capabilities:" "$WORK_DIR/rev_cli.log"
grep -q "admin_actions=" "$WORK_DIR/rev_cli.log"
grep -q "control status:" "$WORK_DIR/rev_cli.log"
grep -q "stream_max=" "$WORK_DIR/rev_cli.log"
echo "[H0] ok 1/1"

echo "H0_SMOKE_OK"
