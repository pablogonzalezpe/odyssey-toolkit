#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="/tmp/odyssey_ws1_smoke"
TOKEN_FILE="/tmp/odyssey_ws1_token.txt"
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

run_http() {
  local port="$1"
  local dir="$2"
  mkdir -p "$dir"
  echo "FLAG{odyssey_ws_works}" >"$dir/flag.txt"
  python3 -m http.server "$port" --bind 127.0.0.1 -d "$dir" >"$WORK_DIR/http_${port}.log" 2>&1 &
  track_pid "$!"
}

echo "[WS1] test 1/3: reverse tunnel over --transport ws"
run_http 18200 "$WORK_DIR/www1"

"$ROOT_DIR/bin/odyssey" reverse-server \
  --listen-control 127.0.0.1:22200 \
  --token-file "$TOKEN_FILE" \
  --tls-mode disabled \
  --transport ws \
  --bind 127.0.0.1:18201:127.0.0.1:18200 \
  --heartbeat-ms 1000 \
  --heartbeat-timeout-ms 5000 >"$WORK_DIR/srv1.log" 2>&1 &
track_pid "$!"
sleep 1

"$ROOT_DIR/bin/odyssey" reverse-client \
  --connect 127.0.0.1:22200 \
  --token-file "$TOKEN_FILE" \
  --tls-mode disabled \
  --transport ws \
  --heartbeat-timeout-ms 5000 >"$WORK_DIR/cli1.log" 2>&1 &
track_pid "$!"
sleep 2

BODY=$(curl -fsS --max-time 8 http://127.0.0.1:18201/flag.txt)
if [ "$BODY" != "FLAG{odyssey_ws_works}" ]; then
  echo "expected FLAG{odyssey_ws_works}, got: $BODY" >&2
  exit 1
fi
grep -q "WebSocket upgrade completed (server)" "$WORK_DIR/srv1.log"
grep -q "WebSocket upgrade completed (client)" "$WORK_DIR/cli1.log"
echo "[WS1] ok 1/3"

echo "[WS1] test 2/3: custom --ws-path"
run_http 18210 "$WORK_DIR/www2"

"$ROOT_DIR/bin/odyssey" reverse-server \
  --listen-control 127.0.0.1:22210 \
  --token-file "$TOKEN_FILE" \
  --tls-mode disabled \
  --transport ws \
  --ws-path /api/v2/stream \
  --bind 127.0.0.1:18211:127.0.0.1:18210 \
  --heartbeat-ms 1000 \
  --heartbeat-timeout-ms 5000 >"$WORK_DIR/srv2.log" 2>&1 &
track_pid "$!"
sleep 1

"$ROOT_DIR/bin/odyssey" reverse-client \
  --connect 127.0.0.1:22210 \
  --token-file "$TOKEN_FILE" \
  --tls-mode disabled \
  --transport ws \
  --ws-path /api/v2/stream \
  --heartbeat-timeout-ms 5000 >"$WORK_DIR/cli2.log" 2>&1 &
track_pid "$!"
sleep 2

BODY=$(curl -fsS --max-time 8 http://127.0.0.1:18211/flag.txt)
if [ "$BODY" != "FLAG{odyssey_ws_works}" ]; then
  echo "expected FLAG{odyssey_ws_works}, got: $BODY" >&2
  exit 1
fi
grep -q "WebSocket upgrade completed" "$WORK_DIR/srv2.log"
echo "[WS1] ok 2/3"

echo "[WS1] test 3/3: multiple binds over WS"
run_http 18220 "$WORK_DIR/www3a"
mkdir -p "$WORK_DIR/www3b"
echo "SECOND" >"$WORK_DIR/www3b/second.txt"
python3 -m http.server 18221 --bind 127.0.0.1 -d "$WORK_DIR/www3b" >"$WORK_DIR/http_18221.log" 2>&1 &
track_pid "$!"

"$ROOT_DIR/bin/odyssey" reverse-server \
  --listen-control 127.0.0.1:22220 \
  --token-file "$TOKEN_FILE" \
  --tls-mode disabled \
  --transport ws \
  --bind 127.0.0.1:18222:127.0.0.1:18220 \
  --bind 127.0.0.1:18223:127.0.0.1:18221 \
  --heartbeat-ms 1000 \
  --heartbeat-timeout-ms 5000 >"$WORK_DIR/srv3.log" 2>&1 &
track_pid "$!"
sleep 1

"$ROOT_DIR/bin/odyssey" reverse-client \
  --connect 127.0.0.1:22220 \
  --token-file "$TOKEN_FILE" \
  --tls-mode disabled \
  --transport ws \
  --heartbeat-timeout-ms 5000 >"$WORK_DIR/cli3.log" 2>&1 &
track_pid "$!"
sleep 2

BODY1=$(curl -fsS --max-time 8 http://127.0.0.1:18222/flag.txt)
BODY2=$(curl -fsS --max-time 8 http://127.0.0.1:18223/second.txt)
if [ "$BODY1" != "FLAG{odyssey_ws_works}" ]; then
  echo "bind1 expected FLAG, got: $BODY1" >&2
  exit 1
fi
if [ "$BODY2" != "SECOND" ]; then
  echo "bind2 expected SECOND, got: $BODY2" >&2
  exit 1
fi
echo "[WS1] ok 3/3"

echo "WS1_SMOKE_OK"
