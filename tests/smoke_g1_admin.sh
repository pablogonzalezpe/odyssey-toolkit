#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="/tmp/odyssey_g1_admin_smoke"
TOKEN_FILE="/tmp/odyssey_g1_admin_token.txt"
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

run_http 18200

echo "[G1] test 1/3: list-bind over admin channel"
"$ROOT_DIR/bin/odyssey" reverse-server \
  --listen-control 127.0.0.1:28301 \
  --token-file "$TOKEN_FILE" \
  --tls-mode disabled \
  --bind 127.0.0.1:28380:127.0.0.1:18200 \
  --admin-listen 127.0.0.1:28390 \
  --admin-token-file "$TOKEN_FILE" \
  --heartbeat-ms 1000 \
  --heartbeat-timeout-ms 5000 >"$WORK_DIR/rev_srv.log" 2>&1 &
track_pid "$!"
sleep 1
"$ROOT_DIR/bin/odyssey" reverse-client \
  --connect 127.0.0.1:28301 \
  --token-file "$TOKEN_FILE" \
  --tls-mode disabled \
  --heartbeat-timeout-ms 5000 >"$WORK_DIR/rev_cli.log" 2>&1 &
track_pid "$!"
sleep 2
"$ROOT_DIR/bin/odyssey" admin --connect 127.0.0.1:28390 --token-file "$TOKEN_FILE" list-bind >"$WORK_DIR/list1.out"
grep -q "OK list" "$WORK_DIR/list1.out"
BASE_ID="$(awk -F'[ =]' '/^id=/{print $2; exit}' "$WORK_DIR/list1.out")"
if [ -z "$BASE_ID" ]; then
  echo "expected base bind id in list output" >&2
  exit 1
fi
echo "[G1] ok 1/3"

echo "[G1] test 2/3: add-bind in hot mode"
"$ROOT_DIR/bin/odyssey" admin --connect 127.0.0.1:28390 --token-file "$TOKEN_FILE" \
  add-bind 127.0.0.1:28381:127.0.0.1:18200 >"$WORK_DIR/add.out"
grep -q "^OK bind_id=" "$WORK_DIR/add.out"
curl -fsS --max-time 5 http://127.0.0.1:28381 >"$WORK_DIR/add_bind_http.out"
grep -q "Directory listing" "$WORK_DIR/add_bind_http.out"
echo "[G1] ok 2/3"

echo "[G1] test 3/3: del-bind in hot mode"
"$ROOT_DIR/bin/odyssey" admin --connect 127.0.0.1:28390 --token-file "$TOKEN_FILE" \
  del-bind "$BASE_ID" >"$WORK_DIR/del.out"
grep -q "^OK bind_id=" "$WORK_DIR/del.out"
set +e
curl -fsS --max-time 3 http://127.0.0.1:28380 >"$WORK_DIR/del_http.out" 2>"$WORK_DIR/del_http.err"
RC=$?
set -e
if [ "$RC" -eq 0 ]; then
  echo "expected deleted bind to stop accepting connections" >&2
  exit 1
fi
echo "[G1] ok 3/3"

echo "G1_SMOKE_OK"
