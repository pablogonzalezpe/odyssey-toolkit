#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="/tmp/odyssey_h_admin_cli"
TOKEN_FILE="/tmp/odyssey_h_admin_token.txt"
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

echo "[H-ADMIN] test 1/4: capabilities from admin command"
"$ROOT_DIR/bin/odyssey" reverse-server \
  --listen-control 127.0.0.1:28701 \
  --token-file "$TOKEN_FILE" \
  --tls-mode disabled \
  --admin-listen 127.0.0.1:28790 \
  --admin-token-file "$TOKEN_FILE" \
  --heartbeat-ms 1000 \
  --heartbeat-timeout-ms 5000 >"$WORK_DIR/rev_srv.log" 2>&1 &
track_pid "$!"
sleep 1
"$ROOT_DIR/bin/odyssey" reverse-client \
  --connect 127.0.0.1:28701 \
  --token-file "$TOKEN_FILE" \
  --tls-mode disabled \
  --heartbeat-timeout-ms 5000 >"$WORK_DIR/rev_cli.log" 2>&1 &
track_pid "$!"
sleep 2

"$ROOT_DIR/bin/odyssey" admin --connect 127.0.0.1:28790 --token-file "$TOKEN_FILE" capabilities >"$WORK_DIR/admin_caps.out"
grep -q "admin_actions=" "$WORK_DIR/admin_caps.out"
echo "[H-ADMIN] ok 1/4"

echo "[H-ADMIN] test 2/4: status from admin command"
"$ROOT_DIR/bin/odyssey" admin --connect 127.0.0.1:28790 --token-file "$TOKEN_FILE" status >"$WORK_DIR/admin_status.out"
grep -q "stream_max=" "$WORK_DIR/admin_status.out"
echo "[H-ADMIN] ok 2/4"

echo "[H-ADMIN] test 3/4: list-stream from admin command"
"$ROOT_DIR/bin/odyssey" admin --connect 127.0.0.1:28790 --token-file "$TOKEN_FILE" list-stream >"$WORK_DIR/admin_streams.out"
grep -q "stream_count=" "$WORK_DIR/admin_streams.out"
echo "[H-ADMIN] ok 3/4"

echo "[H-ADMIN] test 4/4: close-stream invalid id returns controlled error"
"$ROOT_DIR/bin/odyssey" admin --connect 127.0.0.1:28790 --token-file "$TOKEN_FILE" close-stream 999999 >"$WORK_DIR/admin_close_missing.out"
grep -q "^ERR stream not found" "$WORK_DIR/admin_close_missing.out"
echo "[H-ADMIN] ok 4/4"

echo "H_ADMIN_SMOKE_OK"
