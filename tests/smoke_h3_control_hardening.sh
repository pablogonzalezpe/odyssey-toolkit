#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="/tmp/odyssey_h3_control_hardening"
TOKEN_FILE="/tmp/odyssey_h3_token.txt"
CTL_TOKEN_FILE="/tmp/odyssey_h3_ctl_token.txt"
PIDS=()

mkdir -p "$WORK_DIR"
printf '0123456789abcdef\n' >"$TOKEN_FILE"
printf 'odyssey-control-admin-001\n' >"$CTL_TOKEN_FILE"

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

BASE_PORT=$((30000 + (RANDOM % 400)))
CTRL1=$((BASE_PORT + 1))
CTRL2=$((BASE_PORT + 2))

echo "[H3] test 1/3: require-token rejects ctl action without ctl token"
"$ROOT_DIR/bin/odyssey" reverse-server \
  --listen-control "127.0.0.1:${CTRL1}" \
  --token-file "$TOKEN_FILE" \
  --tls-mode disabled \
  --control-admin enabled \
  --control-admin-require-token enabled \
  --control-admin-token-file "$CTL_TOKEN_FILE" \
  --heartbeat-ms 1000 \
  --heartbeat-timeout-ms 5000 >"$WORK_DIR/srv_require_token.log" 2>&1 &
SRV1="$!"
track_pid "$SRV1"
sleep 1
set +e
"$ROOT_DIR/bin/odyssey" reverse-client \
  --connect "127.0.0.1:${CTRL1}" \
  --token-file "$TOKEN_FILE" \
  --tls-mode disabled \
  --ctl-status \
  --ctl-exit-after-admin \
  --heartbeat-timeout-ms 5000 >"$WORK_DIR/cli_no_ctl_token.log" 2>&1
RC=$?
set -e
if [ "$RC" -eq 0 ]; then
  echo "expected ctl action failure without ctl token" >&2
  exit 1
fi
grep -q "control action failed:" "$WORK_DIR/cli_no_ctl_token.log"
grep -Eq "control admin token (required|invalid)" "$WORK_DIR/cli_no_ctl_token.log"
echo "[H3] ok 1/3"

echo "[H3] test 2/3: require-token allows ctl action with ctl token"
"$ROOT_DIR/bin/odyssey" reverse-client \
  --connect "127.0.0.1:${CTRL1}" \
  --token-file "$TOKEN_FILE" \
  --tls-mode disabled \
  --ctl-token-file "$CTL_TOKEN_FILE" \
  --ctl-status \
  --ctl-exit-after-admin \
  --heartbeat-timeout-ms 5000 >"$WORK_DIR/cli_with_ctl_token.log" 2>&1
grep -q "control status:" "$WORK_DIR/cli_with_ctl_token.log"
echo "[H3] ok 2/3"

kill "$SRV1" 2>/dev/null || true
sleep 1

echo "[H3] test 3/3: control-admin rate limit applies"
"$ROOT_DIR/bin/odyssey" reverse-server \
  --listen-control "127.0.0.1:${CTRL2}" \
  --token-file "$TOKEN_FILE" \
  --tls-mode disabled \
  --control-admin enabled \
  --control-admin-token-file "$CTL_TOKEN_FILE" \
  --control-admin-rate-limit-per-min 1 \
  --heartbeat-ms 1000 \
  --heartbeat-timeout-ms 5000 >"$WORK_DIR/srv_rate.log" 2>&1 &
track_pid "$!"
sleep 1
set +e
"$ROOT_DIR/bin/odyssey" reverse-client \
  --connect "127.0.0.1:${CTRL2}" \
  --token-file "$TOKEN_FILE" \
  --tls-mode disabled \
  --ctl-token-file "$CTL_TOKEN_FILE" \
  --ctl-status \
  --ctl-capabilities \
  --ctl-exit-after-admin \
  --heartbeat-timeout-ms 5000 >"$WORK_DIR/cli_rate.log" 2>&1
RC=$?
set -e
if [ "$RC" -eq 0 ]; then
  echo "expected rate-limit failure on second admin action" >&2
  exit 1
fi
grep -q "control action failed:" "$WORK_DIR/cli_rate.log"
grep -q "rate limit exceeded" "$WORK_DIR/cli_rate.log"
echo "[H3] ok 3/3"

echo "H3_SMOKE_OK"
