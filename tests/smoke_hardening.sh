#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="/tmp/odyssey_hardening_smoke"
PIDS=()

mkdir -p "$WORK_DIR"

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

knock_tcp() {
  local port="$1"
  python3 - "$port" <<'PY'
import socket
import sys
port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(1.0)
try:
    s.connect(("127.0.0.1", port))
except Exception:
    pass
s.close()
PY
}

run_http 18090

echo "[HARDENING] test 1/3: allow-source deny"
"$ROOT_DIR/bin/odyssey" relay \
  --listen 127.0.0.1:28090 \
  --to 127.0.0.1:18090 \
  --allow-source 10.10.10.0/24 \
  --connect-timeout-ms 1000 >"$WORK_DIR/relay_deny.log" 2>&1 &
track_pid "$!"
sleep 1
set +e
curl -fsS --max-time 2 http://127.0.0.1:28090 >"$WORK_DIR/deny.out" 2>"$WORK_DIR/deny.err"
RC=$?
set -e
if [ "$RC" -eq 0 ]; then
  echo "expected deny failure in test 1" >&2
  exit 1
fi
grep -q "source not allowed" "$WORK_DIR/relay_deny.log"
echo "[HARDENING] ok 1/3"

echo "[HARDENING] test 2/3: rate-limit + json logs"
"$ROOT_DIR/bin/odyssey" relay \
  --listen 127.0.0.1:28091 \
  --to 127.0.0.1:18090 \
  --allow-source 127.0.0.1 \
  --rate-limit-per-min 1 \
  --log-format json >"$WORK_DIR/relay_rate.log" 2>&1 &
track_pid "$!"
sleep 1
curl -fsS --max-time 4 http://127.0.0.1:28091 >"$WORK_DIR/rate_ok.out"
set +e
curl -fsS --max-time 2 http://127.0.0.1:28091 >"$WORK_DIR/rate_fail.out" 2>"$WORK_DIR/rate_fail.err"
RC=$?
set -e
if [ "$RC" -eq 0 ]; then
  echo "expected rate limit failure in test 2" >&2
  exit 1
fi
grep -q "rate limit exceeded" "$WORK_DIR/relay_rate.log"
grep -q "\"level\"" "$WORK_DIR/relay_rate.log"
echo "[HARDENING] ok 2/3"

echo "[HARDENING] test 3/3: port-knocking open window"
"$ROOT_DIR/bin/odyssey" relay \
  --listen 127.0.0.1:28092 \
  --to 127.0.0.1:18090 \
  --allow-source 127.0.0.1 \
  --knock-seq 28101,28102 \
  --knock-timeout-ms 3000 \
  --knock-open-ms 4000 >"$WORK_DIR/relay_knock.log" 2>&1 &
track_pid "$!"
sleep 1
set +e
curl -fsS --max-time 2 http://127.0.0.1:28092 >"$WORK_DIR/knock_pre.out" 2>"$WORK_DIR/knock_pre.err"
RC=$?
set -e
if [ "$RC" -eq 0 ]; then
  echo "expected pre-knock failure in test 3" >&2
  exit 1
fi
knock_tcp 28101
sleep 0.2
knock_tcp 28102
sleep 0.5
curl -fsS --max-time 4 http://127.0.0.1:28092 >"$WORK_DIR/knock_ok.out"
sleep 5
set +e
curl -fsS --max-time 2 http://127.0.0.1:28092 >"$WORK_DIR/knock_expired.out" 2>"$WORK_DIR/knock_expired.err"
RC=$?
set -e
if [ "$RC" -eq 0 ]; then
  echo "expected post-window failure in test 3" >&2
  exit 1
fi
grep -q "port-knock unlocked source=127.0.0.1" "$WORK_DIR/relay_knock.log"
echo "[HARDENING] ok 3/3"

echo "HARDENING_SMOKE_OK"
