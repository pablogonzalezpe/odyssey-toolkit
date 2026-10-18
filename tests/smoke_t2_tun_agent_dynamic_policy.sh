#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="/tmp/odyssey_t2_tun_agent_dynamic_policy"
TOKEN_FILE="/tmp/odyssey_t2_tun_agent_dynamic_policy.token"
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

echo "[T2.2/T2.3] test 1/5: compile tun-agent harness"
gcc -O2 -Wall -Wextra -Wpedantic -std=c11 \
  -I"$ROOT_DIR/include" \
  "$ROOT_DIR/tests/_t1_tun_agent_harness.c" \
  "$ROOT_DIR/src/od_proto.c" \
  "$ROOT_DIR/src/od_io.c" \
  "$ROOT_DIR/src/od_socket.c" \
  "$ROOT_DIR/src/od_log.c" \
  -o "$HARNESS"
echo "[T2.2/T2.3] ok 1/5"

echo "[T2.2/T2.3] test 2/5: start tun-agent runtime for dynamic policy checks"
"$ROOT_DIR/bin/odyssey" reverse-client \
  --mode tun-agent \
  --connect 127.0.0.1:29963 \
  --token-file "$TOKEN_FILE" \
  --allow-cidr 10.230.0.0/24 \
  --allow-port tcp:443 \
  --allow-port udp:53 \
  --tls-mode disabled \
  --heartbeat-timeout-ms 5000 >"$WORK_DIR/tun_agent.log" 2>&1 &
track_pid "$!"
sleep 2
"$HARNESS" 29963 "$(cat "$TOKEN_FILE")" policy-show >"$WORK_DIR/policy_show.out"
grep -q "policy_known=true" "$WORK_DIR/policy_show.out"
grep -q "allow_cidr\\[0\\]=10.230.0.0/24" "$WORK_DIR/policy_show.out"
grep -q "allow_port\\[0\\]=tcp:443" "$WORK_DIR/policy_show.out"
echo "[T2.2/T2.3] ok 2/5"

echo "[T2.2/T2.3] test 3/5: dynamic allow additions take effect immediately"
"$HARNESS" 29963 "$(cat "$TOKEN_FILE")" policy-add-port-allow >"$WORK_DIR/policy_add_port.out"
"$HARNESS" 29963 "$(cat "$TOKEN_FILE")" policy-add-cidr-allow >"$WORK_DIR/policy_add_cidr.out"
grep -q "allow_port\\[2\\]=tcp:444" "$WORK_DIR/policy_add_port.out"
grep -q "pkt-len=40" "$WORK_DIR/policy_add_port.out"
grep -q "allow_cidr\\[1\\]=10.231.0.0/24" "$WORK_DIR/policy_add_cidr.out"
grep -q "pkt-len=40" "$WORK_DIR/policy_add_cidr.out"
echo "[T2.2/T2.3] ok 3/5"

echo "[T2.2/T2.3] test 4/5: dynamic removals enforce default-deny in-session"
"$HARNESS" 29963 "$(cat "$TOKEN_FILE")" policy-del-port-deny >"$WORK_DIR/policy_del_port.out"
"$HARNESS" 29963 "$(cat "$TOKEN_FILE")" policy-del-cidr-deny >"$WORK_DIR/policy_del_cidr.out"
grep -q "ok=false" "$WORK_DIR/policy_del_port.out"
grep -q "code=policy_denied" "$WORK_DIR/policy_del_port.out"
grep -q "ok=false" "$WORK_DIR/policy_del_cidr.out"
grep -q "code=policy_denied" "$WORK_DIR/policy_del_cidr.out"
echo "[T2.2/T2.3] ok 4/5"

echo "[T2.2/T2.3] test 5/5: killswitch blocks dataplane and is reflected in status"
"$HARNESS" 29963 "$(cat "$TOKEN_FILE")" killswitch-on-status-deny >"$WORK_DIR/killswitch.out"
grep -q "killswitch_enabled=true" "$WORK_DIR/killswitch.out"
grep -q "ok=false" "$WORK_DIR/killswitch.out"
grep -q "code=killswitch_enabled" "$WORK_DIR/killswitch.out"
echo "[T2.2/T2.3] ok 5/5"

echo "T2_TUN_AGENT_DYNAMIC_POLICY_SMOKE_OK"
