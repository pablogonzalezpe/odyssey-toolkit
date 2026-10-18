#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="/tmp/odyssey_g2_control_smoke"
TOKEN_FILE="/tmp/odyssey_g2_control_token.txt"
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
  python3 -m http.server "$port" --bind 127.0.0.1 >"$WORK_DIR/http_${port}.log" 2>&1 &
  track_pid "$!"
}

run_http 18300

echo "[G2] test 1/2: add-bind via control messages"
"$ROOT_DIR/bin/odyssey" reverse-server \
  --listen-control 127.0.0.1:28401 \
  --token-file "$TOKEN_FILE" \
  --tls-mode disabled \
  --bind 127.0.0.1:28480:127.0.0.1:18300 \
  --heartbeat-ms 1000 \
  --heartbeat-timeout-ms 5000 >"$WORK_DIR/rev_srv.log" 2>&1 &
track_pid "$!"
sleep 1
"$ROOT_DIR/bin/odyssey" reverse-client \
  --connect 127.0.0.1:28401 \
  --token-file "$TOKEN_FILE" \
  --tls-mode disabled \
  --ctl-list-bind \
  --ctl-add-bind 127.0.0.1:28481:127.0.0.1:18300 \
  --heartbeat-timeout-ms 5000 \
  --verbose >"$WORK_DIR/rev_cli.log" 2>&1 &
CLIENT_PID="$!"
track_pid "$CLIENT_PID"
sleep 3
curl -fsS --max-time 5 http://127.0.0.1:28481 >"$WORK_DIR/add_bind_http.out"
grep -q "Directory listing" "$WORK_DIR/add_bind_http.out"
grep -q "control add-bind id=" "$WORK_DIR/rev_srv.log"
grep -q "control list-bind:" "$WORK_DIR/rev_cli.log"
echo "[G2] ok 1/2"

kill "$CLIENT_PID" 2>/dev/null || true
sleep 1

echo "[G2] test 2/2: invalid add-bind fails through control channel"
set +e
"$ROOT_DIR/bin/odyssey" reverse-client \
  --connect 127.0.0.1:28401 \
  --token-file "$TOKEN_FILE" \
  --tls-mode disabled \
  --ctl-add-bind bad-format \
  --ctl-exit-after-admin \
  --heartbeat-timeout-ms 5000 >"$WORK_DIR/rev_cli_bad.log" 2>&1
RC=$?
set -e
if [ "$RC" -eq 0 ]; then
  echo "expected control action failure in test 2" >&2
  exit 1
fi
grep -q "control actions failed" "$WORK_DIR/rev_cli_bad.log"
echo "[G2] ok 2/2"

echo "G2_SMOKE_OK"
