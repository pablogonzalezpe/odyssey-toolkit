#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TOKEN_FILE="/tmp/odyssey_d1_token.txt"
WORK_DIR="/tmp/odyssey_d1_smoke"
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

run_fast_http() {
  local port="$1"
  python3 -m http.server "$port" --bind 127.0.0.1 >"$WORK_DIR/http_${port}.log" 2>&1 &
  track_pid "$!"
}

run_slow_http() {
  local port="$1"
  python3 - "$port" >"$WORK_DIR/http_slow_${port}.log" 2>&1 <<'PY' &
import socket
import sys
import time

port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
s.listen(16)
while True:
    c, _ = s.accept()
    _ = c.recv(2048)
    time.sleep(6)
    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
    c.close()
PY
  track_pid "$!"
}

run_stack() {
  local control_port="$1"
  local socks_port="$2"
  local server_log="$3"
  local client_log="$4"
  local server_extra="$5"
  local client_extra="$6"

  # shellcheck disable=SC2086
  "$ROOT_DIR/bin/odyssey" reverse-server \
    --listen-control "127.0.0.1:${control_port}" \
    --token-file "$TOKEN_FILE" \
    --tls-mode disabled \
    --socks-listen "127.0.0.1:${socks_port}" \
    --heartbeat-ms 1000 \
    --heartbeat-timeout-ms 5000 \
    $server_extra >"$server_log" 2>&1 &
  track_pid "$!"

  sleep 1

  # shellcheck disable=SC2086
  "$ROOT_DIR/bin/odyssey" reverse-client \
    --connect "127.0.0.1:${control_port}" \
    --token-file "$TOKEN_FILE" \
    --tls-mode disabled \
    --heartbeat-timeout-ms 5000 \
    $client_extra >"$client_log" 2>&1 &
  track_pid "$!"

  sleep 2
}

echo "[D1.4] test 1/4: socks5 CONNECT success"
run_fast_http 18010
run_stack 22101 22180 "$WORK_DIR/srv1.log" "$WORK_DIR/cli1.log" "" "--allow-target localhost:18010"
curl -fsS --max-time 8 --socks5-hostname 127.0.0.1:22180 http://localhost:18010 >"$WORK_DIR/curl1.out"
grep -q "Directory listing" "$WORK_DIR/curl1.out"
echo "[D1.4] ok 1/4"

echo "[D1.4] test 2/4: policy deny"
run_stack 22102 22181 "$WORK_DIR/srv2.log" "$WORK_DIR/cli2.log" "" "--allow-target localhost:18010"
set +e
curl -fsS --max-time 6 --socks5-hostname 127.0.0.1:22181 http://localhost:18011 >"$WORK_DIR/curl2.out" 2>"$WORK_DIR/curl2.err"
RC=$?
set -e
if [ "$RC" -eq 0 ]; then
  echo "expected deny failure in test 2" >&2
  exit 1
fi
grep -q "open failed by client reason=target not allowed" "$WORK_DIR/srv2.log"
echo "[D1.4] ok 2/4"

echo "[D1.4] test 3/4: max-streams enforcement"
run_slow_http 18013
run_stack 22103 22182 "$WORK_DIR/srv3.log" "$WORK_DIR/cli3.log" "--max-streams 1" "--allow-target localhost:18013"
curl -fsS --max-time 12 --socks5-hostname 127.0.0.1:22182 http://localhost:18013 >"$WORK_DIR/curl3a.out" 2>"$WORK_DIR/curl3a.err" &
FIRST_CURL_PID=$!
sleep 1
set +e
curl -fsS --max-time 4 --socks5-hostname 127.0.0.1:22182 http://localhost:18013 >"$WORK_DIR/curl3b.out" 2>"$WORK_DIR/curl3b.err"
RC=$?
set -e
if [ "$RC" -eq 0 ]; then
  echo "expected max-stream failure in test 3" >&2
  exit 1
fi
wait "$FIRST_CURL_PID" || true
grep -q "max streams reached" "$WORK_DIR/srv3.log"
echo "[D1.4] ok 3/4"

echo "[D1.4] test 4/4: open_fail timeout/connect-failure path"
run_stack 22104 22183 "$WORK_DIR/srv4.log" "$WORK_DIR/cli4.log" "" "--allow-target 10.255.255.1:65000 --connect-timeout-ms 1200"
set +e
curl -fsS --max-time 6 --socks5-hostname 127.0.0.1:22183 http://10.255.255.1:65000 >"$WORK_DIR/curl4.out" 2>"$WORK_DIR/curl4.err"
RC=$?
set -e
if [ "$RC" -eq 0 ]; then
  echo "expected timeout/connect failure in test 4" >&2
  exit 1
fi
grep -q "open failed by client reason=" "$WORK_DIR/srv4.log"
echo "[D1.4] ok 4/4"

echo "D1.4_SMOKE_OK"
