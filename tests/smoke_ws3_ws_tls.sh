#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="/tmp/odyssey_ws3_smoke"
TOKEN_FILE="/tmp/odyssey_ws3_token.txt"
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

echo "[WS3] test 1/2: WS + TLS combined (wss://)"

openssl req -x509 -newkey rsa:2048 \
  -keyout "$WORK_DIR/server.key" -out "$WORK_DIR/server.crt" \
  -days 1 -nodes -subj "/CN=localhost" \
  -addext "subjectAltName=IP:127.0.0.1" 2>/dev/null

mkdir -p "$WORK_DIR/www1"
echo "FLAG{odyssey_ws_tls_works}" >"$WORK_DIR/www1/flag.txt"
python3 -m http.server 18400 --bind 127.0.0.1 -d "$WORK_DIR/www1" >"$WORK_DIR/http1.log" 2>&1 &
track_pid "$!"

"$ROOT_DIR/bin/odyssey" reverse-server \
  --listen-control 127.0.0.1:22400 \
  --token-file "$TOKEN_FILE" \
  --tls-mode required \
  --tls-cert "$WORK_DIR/server.crt" \
  --tls-key "$WORK_DIR/server.key" \
  --transport ws \
  --bind 127.0.0.1:18401:127.0.0.1:18400 \
  --heartbeat-ms 1000 \
  --heartbeat-timeout-ms 5000 >"$WORK_DIR/srv1.log" 2>&1 &
track_pid "$!"
sleep 1

"$ROOT_DIR/bin/odyssey" reverse-client \
  --connect 127.0.0.1:22400 \
  --token-file "$TOKEN_FILE" \
  --tls-mode required \
  --tls-ca "$WORK_DIR/server.crt" \
  --transport ws \
  --heartbeat-timeout-ms 5000 >"$WORK_DIR/cli1.log" 2>&1 &
track_pid "$!"
sleep 2

BODY=$(curl -fsS --max-time 8 http://127.0.0.1:18401/flag.txt)
if [ "$BODY" != "FLAG{odyssey_ws_tls_works}" ]; then
  echo "expected FLAG{odyssey_ws_tls_works}, got: $BODY" >&2
  exit 1
fi
grep -q "TLS handshake completed" "$WORK_DIR/srv1.log"
grep -q "WebSocket upgrade completed" "$WORK_DIR/srv1.log"
echo "[WS3] ok 1/2"

echo "[WS3] test 2/2: WS + TLS + SOCKS5"
mkdir -p "$WORK_DIR/www2"
echo "SOCKS_FLAG" >"$WORK_DIR/www2/socks.txt"
python3 -m http.server 18410 --bind 127.0.0.1 -d "$WORK_DIR/www2" >"$WORK_DIR/http2.log" 2>&1 &
track_pid "$!"

"$ROOT_DIR/bin/odyssey" reverse-server \
  --listen-control 127.0.0.1:22410 \
  --token-file "$TOKEN_FILE" \
  --tls-mode required \
  --tls-cert "$WORK_DIR/server.crt" \
  --tls-key "$WORK_DIR/server.key" \
  --transport ws \
  --socks-listen 127.0.0.1:22411 \
  --heartbeat-ms 1000 \
  --heartbeat-timeout-ms 5000 >"$WORK_DIR/srv2.log" 2>&1 &
track_pid "$!"
sleep 1

"$ROOT_DIR/bin/odyssey" reverse-client \
  --connect 127.0.0.1:22410 \
  --token-file "$TOKEN_FILE" \
  --tls-mode required \
  --tls-ca "$WORK_DIR/server.crt" \
  --transport ws \
  --allow-target localhost:18410 \
  --heartbeat-timeout-ms 5000 >"$WORK_DIR/cli2.log" 2>&1 &
track_pid "$!"
sleep 2

BODY=$(curl -fsS --max-time 8 --socks5-hostname 127.0.0.1:22411 http://localhost:18410/socks.txt)
if [ "$BODY" != "SOCKS_FLAG" ]; then
  echo "expected SOCKS_FLAG, got: $BODY" >&2
  exit 1
fi
echo "[WS3] ok 2/2"

echo "WS3_SMOKE_OK"
