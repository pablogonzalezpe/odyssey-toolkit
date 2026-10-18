#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="/tmp/odyssey_g3_control_admin_smoke"
TOKEN_FILE="/tmp/odyssey_g3_token.txt"
CTL_TOKEN_FILE="/tmp/odyssey_g3_ctl_token.txt"
PIDS=()

mkdir -p "$WORK_DIR"
printf '0123456789abcdef\n' >"$TOKEN_FILE"
printf 'admin-control-secret-001\n' >"$CTL_TOKEN_FILE"

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

run_http 18400

BASE_PORT=$((29000 + (RANDOM % 500)))
CTRL1=$((BASE_PORT + 1))
CTRL2=$((BASE_PORT + 2))
ADD1=$((BASE_PORT + 81))
ADD2=$((BASE_PORT + 82))
ADD3=$((BASE_PORT + 83))

echo "[G3] test 1/3: control-admin disabled blocks ctl actions"
"$ROOT_DIR/bin/odyssey" reverse-server \
  --listen-control "127.0.0.1:${CTRL1}" \
  --token-file "$TOKEN_FILE" \
  --tls-mode disabled \
  --control-admin disabled \
  --heartbeat-ms 1000 \
  --heartbeat-timeout-ms 5000 >"$WORK_DIR/srv_disabled.log" 2>&1 &
SRV1="$!"
track_pid "$SRV1"
sleep 1
set +e
"$ROOT_DIR/bin/odyssey" reverse-client \
  --connect "127.0.0.1:${CTRL1}" \
  --token-file "$TOKEN_FILE" \
  --tls-mode disabled \
  --ctl-add-bind "127.0.0.1:${ADD1}:127.0.0.1:18400" \
  --ctl-exit-after-admin \
  --heartbeat-timeout-ms 5000 >"$WORK_DIR/cli_disabled.log" 2>&1
RC=$?
set -e
if [ "$RC" -eq 0 ]; then
  echo "expected failure when control-admin is disabled" >&2
  exit 1
fi
grep -q "control actions failed" "$WORK_DIR/cli_disabled.log"
kill "$SRV1" 2>/dev/null || true
sleep 1
echo "[G3] ok 1/3"

echo "[G3] test 2/3: control-admin token required"
"$ROOT_DIR/bin/odyssey" reverse-server \
  --listen-control "127.0.0.1:${CTRL2}" \
  --token-file "$TOKEN_FILE" \
  --tls-mode disabled \
  --control-admin enabled \
  --control-admin-token-file "$CTL_TOKEN_FILE" \
  --heartbeat-ms 1000 \
  --heartbeat-timeout-ms 5000 >"$WORK_DIR/srv_token.log" 2>&1 &
SRV2="$!"
track_pid "$SRV2"
sleep 1
set +e
"$ROOT_DIR/bin/odyssey" reverse-client \
  --connect "127.0.0.1:${CTRL2}" \
  --token-file "$TOKEN_FILE" \
  --tls-mode disabled \
  --ctl-add-bind "127.0.0.1:${ADD2}:127.0.0.1:18400" \
  --ctl-exit-after-admin \
  --heartbeat-timeout-ms 5000 >"$WORK_DIR/cli_need_token.log" 2>&1
RC=$?
set -e
if [ "$RC" -eq 0 ]; then
  echo "expected failure without ctl token" >&2
  exit 1
fi
grep -q "control actions failed" "$WORK_DIR/cli_need_token.log"
echo "[G3] ok 2/3"

echo "[G3] test 3/3: control-admin token allows ctl add-bind"
"$ROOT_DIR/bin/odyssey" reverse-client \
  --connect "127.0.0.1:${CTRL2}" \
  --token-file "$TOKEN_FILE" \
  --tls-mode disabled \
  --ctl-token-file "$CTL_TOKEN_FILE" \
  --ctl-add-bind "127.0.0.1:${ADD3}:127.0.0.1:18400" \
  --heartbeat-timeout-ms 5000 >"$WORK_DIR/cli_with_token.log" 2>&1 &
track_pid "$!"
sleep 3
curl -fsS --max-time 5 "http://127.0.0.1:${ADD3}" >"$WORK_DIR/with_token_http.out"
grep -q "Directory listing" "$WORK_DIR/with_token_http.out"
grep -q "control add-bind id=" "$WORK_DIR/srv_token.log"
echo "[G3] ok 3/3"

echo "G3_SMOKE_OK"
