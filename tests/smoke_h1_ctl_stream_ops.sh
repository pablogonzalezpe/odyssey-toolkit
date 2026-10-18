#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="/tmp/odyssey_h1_ctl_stream_ops"
TOKEN_FILE="/tmp/odyssey_h1_token.txt"
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

echo "[H1] test 1/2: list-stream through control channel"
"$ROOT_DIR/bin/odyssey" reverse-server \
  --listen-control 127.0.0.1:28601 \
  --token-file "$TOKEN_FILE" \
  --tls-mode disabled \
  --heartbeat-ms 1000 \
  --heartbeat-timeout-ms 5000 >"$WORK_DIR/rev_srv.log" 2>&1 &
track_pid "$!"
sleep 1

"$ROOT_DIR/bin/odyssey" reverse-client \
  --connect 127.0.0.1:28601 \
  --token-file "$TOKEN_FILE" \
  --tls-mode disabled \
  --ctl-list-stream \
  --ctl-exit-after-admin \
  --heartbeat-timeout-ms 5000 \
  --verbose >"$WORK_DIR/ctl_list.log" 2>&1

grep -q "control list-stream:" "$WORK_DIR/ctl_list.log"
grep -q "stream_count=0" "$WORK_DIR/ctl_list.log"
echo "[H1] ok 1/2"

echo "[H1] test 2/2: close-stream non-existent returns controlled error"
set +e
"$ROOT_DIR/bin/odyssey" reverse-client \
  --connect 127.0.0.1:28601 \
  --token-file "$TOKEN_FILE" \
  --tls-mode disabled \
  --ctl-close-stream 999999 \
  --ctl-exit-after-admin \
  --heartbeat-timeout-ms 5000 \
  --verbose >"$WORK_DIR/ctl_close_missing.log" 2>&1
RC=$?
set -e
if [ "$RC" -eq 0 ]; then
  echo "expected close-stream missing to fail" >&2
  exit 1
fi
grep -q "control action failed:" "$WORK_DIR/ctl_close_missing.log"
grep -q "stream not found" "$WORK_DIR/ctl_close_missing.log"
echo "[H1] ok 2/2"

echo "H1_SMOKE_OK"
