#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="/tmp/odyssey_d2_smoke"
TOKEN_FILE="${WORK_DIR}/token.txt"
SOCKS_PASS_FILE="${WORK_DIR}/socks_pass.txt"

mkdir -p "$WORK_DIR"
printf '0123456789abcdef\n' >"$TOKEN_FILE"
printf 'socksSecret123\n' >"$SOCKS_PASS_FILE"

PIDS=()
track_pid() { PIDS+=("$1"); }
cleanup() {
  local p
  for p in "${PIDS[@]}"; do
    kill "$p" 2>/dev/null || true
  done
}
trap cleanup EXIT

python3 -m http.server 18020 --bind 127.0.0.1 >"$WORK_DIR/http.log" 2>&1 &
track_pid "$!"

"$ROOT_DIR/bin/odyssey" reverse-server \
  --listen-control 127.0.0.1:23101 \
  --token-file "$TOKEN_FILE" \
  --tls-mode disabled \
  --socks-listen 127.0.0.1:23180 \
  --socks-user pivot \
  --socks-pass-file "$SOCKS_PASS_FILE" \
  >"$WORK_DIR/server.log" 2>&1 &
track_pid "$!"

sleep 1

"$ROOT_DIR/bin/odyssey" reverse-client \
  --connect 127.0.0.1:23101 \
  --token-file "$TOKEN_FILE" \
  --tls-mode disabled \
  --allow-target localhost:18020 \
  >"$WORK_DIR/client.log" 2>&1 &
track_pid "$!"

sleep 2

echo "[D2] test 1/3: credential success"
curl -fsS --max-time 8 \
  --socks5-hostname 127.0.0.1:23180 \
  --proxy-user pivot:socksSecret123 \
  http://localhost:18020 >"$WORK_DIR/ok.out"
grep -q "Directory listing" "$WORK_DIR/ok.out"

echo "[D2] test 2/3: wrong password must fail"
set +e
curl -fsS --max-time 8 \
  --socks5-hostname 127.0.0.1:23180 \
  --proxy-user pivot:wrongpass \
  http://localhost:18020 >"$WORK_DIR/badpass.out" 2>"$WORK_DIR/badpass.err"
RC_BAD=$?
set -e
if [ "$RC_BAD" -eq 0 ]; then
  echo "wrong password should fail" >&2
  exit 1
fi

echo "[D2] test 3/3: missing password must fail"
set +e
curl -fsS --max-time 8 \
  --socks5-hostname 127.0.0.1:23180 \
  http://localhost:18020 >"$WORK_DIR/noauth.out" 2>"$WORK_DIR/noauth.err"
RC_NOAUTH=$?
set -e
if [ "$RC_NOAUTH" -eq 0 ]; then
  echo "missing password should fail" >&2
  exit 1
fi

echo "D2_SMOKE_OK"
