#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="/tmp/odyssey_f_knock_smoke"
TOKEN_FILE="/tmp/odyssey_f_knock_token.txt"
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

run_http 18100

echo "[F] test 1/2: odyssey knock command unlocks relay"
"$ROOT_DIR/bin/odyssey" relay \
  --listen 127.0.0.1:28180 \
  --to 127.0.0.1:18100 \
  --allow-source 127.0.0.1 \
  --knock-seq 28111,28112 \
  --knock-timeout-ms 3000 \
  --knock-open-ms 5000 >"$WORK_DIR/relay_knock.log" 2>&1 &
track_pid "$!"
sleep 1
set +e
curl -fsS --max-time 2 http://127.0.0.1:28180 >"$WORK_DIR/pre_knock.out" 2>"$WORK_DIR/pre_knock.err"
RC=$?
set -e
if [ "$RC" -eq 0 ]; then
  echo "expected pre-knock failure in test 1" >&2
  exit 1
fi
"$ROOT_DIR/bin/odyssey" knock --host 127.0.0.1 --seq 28111,28112 --delay-ms 120 --timeout-ms 1200
curl -fsS --max-time 4 http://127.0.0.1:28180 >"$WORK_DIR/post_knock.out"
grep -q "Directory listing" "$WORK_DIR/post_knock.out"
echo "[F] ok 1/2"

echo "[F] test 2/2: reverse-client --knock-before-connect"
"$ROOT_DIR/bin/odyssey" reverse-server \
  --listen-control 127.0.0.1:28201 \
  --token-file "$TOKEN_FILE" \
  --tls-mode disabled \
  --bind 127.0.0.1:28280:127.0.0.1:18100 \
  --allow-source 127.0.0.1 \
  --knock-seq 28211,28212 \
  --knock-timeout-ms 3000 \
  --knock-open-ms 8000 \
  --heartbeat-ms 1000 \
  --heartbeat-timeout-ms 5000 >"$WORK_DIR/rev_srv.log" 2>&1 &
track_pid "$!"
sleep 1
"$ROOT_DIR/bin/odyssey" reverse-client \
  --connect 127.0.0.1:28201 \
  --token-file "$TOKEN_FILE" \
  --tls-mode disabled \
  --knock-before-connect \
  --knock-host 127.0.0.1 \
  --knock-seq 28211,28212 \
  --knock-delay-ms 120 \
  --knock-timeout-ms 1200 \
  --heartbeat-timeout-ms 5000 \
  --verbose >"$WORK_DIR/rev_cli.log" 2>&1 &
track_pid "$!"
sleep 3
curl -fsS --max-time 5 http://127.0.0.1:28280 >"$WORK_DIR/rev_bind.out"
grep -q "Directory listing" "$WORK_DIR/rev_bind.out"
grep -q "client authenticated" "$WORK_DIR/rev_srv.log"
echo "[F] ok 2/2"

echo "F_SMOKE_OK"
