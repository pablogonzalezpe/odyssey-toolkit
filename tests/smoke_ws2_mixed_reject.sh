#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="/tmp/odyssey_ws2_smoke"
TOKEN_FILE="/tmp/odyssey_ws2_token.txt"
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

echo "[WS2] test 1/2: server=ws, client=raw -> handshake fail"

"$ROOT_DIR/bin/odyssey" reverse-server \
  --listen-control 127.0.0.1:22300 \
  --token-file "$TOKEN_FILE" \
  --tls-mode disabled \
  --transport ws \
  --heartbeat-ms 1000 \
  --heartbeat-timeout-ms 5000 >"$WORK_DIR/srv1.log" 2>&1 &
track_pid "$!"
sleep 1

"$ROOT_DIR/bin/odyssey" reverse-client \
  --connect 127.0.0.1:22300 \
  --token-file "$TOKEN_FILE" \
  --tls-mode disabled \
  --transport raw \
  --heartbeat-timeout-ms 5000 >"$WORK_DIR/cli1.log" 2>&1 &
CLI_PID=$!
track_pid "$CLI_PID"
sleep 3

# client should have failed and exited (or be retrying)
# server should log a WS handshake error
if grep -q "WS handshake failed" "$WORK_DIR/srv1.log" || \
   grep -q "expected GET request" "$WORK_DIR/srv1.log"; then
  echo "[WS2] ok 1/2: server rejected raw client"
else
  echo "expected WS handshake failure in server log" >&2
  cat "$WORK_DIR/srv1.log" >&2
  exit 1
fi

echo "[WS2] test 2/2: server=raw, client=ws -> handshake fail"

"$ROOT_DIR/bin/odyssey" reverse-server \
  --listen-control 127.0.0.1:22310 \
  --token-file "$TOKEN_FILE" \
  --tls-mode disabled \
  --transport raw \
  --heartbeat-ms 1000 \
  --heartbeat-timeout-ms 5000 >"$WORK_DIR/srv2.log" 2>&1 &
track_pid "$!"
sleep 1

"$ROOT_DIR/bin/odyssey" reverse-client \
  --connect 127.0.0.1:22310 \
  --token-file "$TOKEN_FILE" \
  --tls-mode disabled \
  --transport ws \
  --heartbeat-timeout-ms 5000 >"$WORK_DIR/cli2.log" 2>&1 &
CLI_PID2=$!
track_pid "$CLI_PID2"
sleep 3

# client should have failed the WS handshake (server sends raw protocol, not HTTP 101)
if grep -q "WS handshake failed" "$WORK_DIR/cli2.log" || \
   grep -q "expected HTTP 101" "$WORK_DIR/cli2.log"; then
  echo "[WS2] ok 2/2: client rejected raw server"
else
  echo "expected WS handshake failure in client log" >&2
  cat "$WORK_DIR/cli2.log" >&2
  exit 1
fi

echo "WS2_SMOKE_OK"
