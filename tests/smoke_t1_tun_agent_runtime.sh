#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="/tmp/odyssey_t1_tun_agent_runtime"
TOKEN_FILE="/tmp/odyssey_t1_tun_agent_runtime.token"
HARNESS="$WORK_DIR/t1_tun_agent_harness"
PIDS=()

mkdir -p "$WORK_DIR"
printf '0123456789abcdefA\n' >"$TOKEN_FILE"

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

echo "[T1.5] test 1/4: compile tun-agent harness"
gcc -O2 -Wall -Wextra -Wpedantic -std=c11 \
  -I"$ROOT_DIR/include" \
  "$ROOT_DIR/tests/_t1_tun_agent_harness.c" \
  "$ROOT_DIR/src/od_proto.c" \
  "$ROOT_DIR/src/od_io.c" \
  "$ROOT_DIR/src/od_socket.c" \
  "$ROOT_DIR/src/od_log.c" \
  -o "$HARNESS"
echo "[T1.5] ok 1/4"

echo "[T1.5] test 2/4: start tun-agent runtime and first control exchange"
"$ROOT_DIR/bin/odyssey" reverse-client \
  --mode tun-agent \
  --connect 127.0.0.1:29960 \
  --token-file "$TOKEN_FILE" \
  --allow-cidr 10.230.0.0/24 \
  --allow-port tcp:443 \
  --allow-port udp:53 \
  --tls-mode disabled \
  --heartbeat-timeout-ms 5000 >"$WORK_DIR/tun_agent.log" 2>&1 &
track_pid "$!"
sleep 2
"$HARNESS" 29960 "$(cat "$TOKEN_FILE")" caps >"$WORK_DIR/caps_1.out"
grep -q "reason=tun-capabilities" "$WORK_DIR/caps_1.out"
grep -q "allow_cidr_count=1" "$WORK_DIR/caps_1.out"
grep -q "tun_actions=tun_caps_req,tun_status_req,tun_route_list,tun_policy_set,tun_policy_get,tun_killswitch_set,tun_pkt" "$WORK_DIR/caps_1.out"
echo "[T1.5] ok 2/4"

echo "[T1.5] test 3/4: reconnect and status/route-list exchanges"
"$HARNESS" 29960 "$(cat "$TOKEN_FILE")" status >"$WORK_DIR/status_2.out"
"$HARNESS" 29960 "$(cat "$TOKEN_FILE")" route-list >"$WORK_DIR/routes_3.out"
grep -q "reason=tun-status" "$WORK_DIR/status_2.out"
grep -q "mode=tun-agent" "$WORK_DIR/status_2.out"
grep -q "reason=tun-route-list" "$WORK_DIR/routes_3.out"
grep -q "route\\[0\\]=10.230.0.0/24" "$WORK_DIR/routes_3.out"
echo "[T1.5] ok 3/4"

echo "[T1.5] test 4/4: unsupported tun action returns typed fail"
"$HARNESS" 29960 "$(cat "$TOKEN_FILE")" route-add >"$WORK_DIR/route_add_4.out"
grep -q "ok=false" "$WORK_DIR/route_add_4.out"
grep -q "code=unsupported_capability" "$WORK_DIR/route_add_4.out"
echo "[T1.5] ok 4/4"

echo "T1_TUN_AGENT_RUNTIME_SMOKE_OK"
