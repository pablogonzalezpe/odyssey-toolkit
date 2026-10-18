#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="/tmp/odyssey_t1_tun_packet_mvp"
TOKEN_FILE="/tmp/odyssey_t1_tun_packet_mvp.token"
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

echo "[T1.7] test 1/5: compile tun-agent harness"
gcc -O2 -Wall -Wextra -Wpedantic -std=c11 \
  -I"$ROOT_DIR/include" \
  "$ROOT_DIR/tests/_t1_tun_agent_harness.c" \
  "$ROOT_DIR/src/od_proto.c" \
  "$ROOT_DIR/src/od_io.c" \
  "$ROOT_DIR/src/od_socket.c" \
  "$ROOT_DIR/src/od_log.c" \
  -o "$HARNESS"
echo "[T1.7] ok 1/5"

echo "[T1.7] test 2/5: start tun-agent runtime for packet dataplane checks"
"$ROOT_DIR/bin/odyssey" reverse-client \
  --mode tun-agent \
  --connect 127.0.0.1:29961 \
  --token-file "$TOKEN_FILE" \
  --allow-cidr 10.230.0.0/24 \
  --allow-port tcp:443 \
  --allow-port udp:53 \
  --tls-mode disabled \
  --heartbeat-timeout-ms 5000 >"$WORK_DIR/tun_agent.log" 2>&1 &
track_pid "$!"
sleep 2
echo "[T1.7] ok 2/5"

echo "[T1.7] test 3/5: allowed packet gets TUN_PKT echo"
"$HARNESS" 29961 "$(cat "$TOKEN_FILE")" pkt-allow >"$WORK_DIR/pkt_allow.out"
grep -q "pkt-len=40" "$WORK_DIR/pkt_allow.out"
echo "[T1.7] ok 3/5"

echo "[T1.7] test 4/5: denied packets return typed policy_denied"
"$HARNESS" 29961 "$(cat "$TOKEN_FILE")" pkt-deny-port >"$WORK_DIR/pkt_deny_port.out"
"$HARNESS" 29961 "$(cat "$TOKEN_FILE")" pkt-deny-cidr >"$WORK_DIR/pkt_deny_cidr.out"
grep -q "ok=false" "$WORK_DIR/pkt_deny_port.out"
grep -q "code=policy_denied" "$WORK_DIR/pkt_deny_port.out"
grep -q "ok=false" "$WORK_DIR/pkt_deny_cidr.out"
grep -q "code=policy_denied" "$WORK_DIR/pkt_deny_cidr.out"
echo "[T1.7] ok 4/5"

echo "[T1.7] test 5/5: status exports packet counters in-session"
"$HARNESS" 29961 "$(cat "$TOKEN_FILE")" pkt-allow-status >"$WORK_DIR/pkt_allow_status.out"
grep -q "pkt-len=40" "$WORK_DIR/pkt_allow_status.out"
grep -q "pkts_in=1" "$WORK_DIR/pkt_allow_status.out"
grep -q "pkts_out=1" "$WORK_DIR/pkt_allow_status.out"
grep -q "drops_policy=0" "$WORK_DIR/pkt_allow_status.out"
echo "[T1.7] ok 5/5"

echo "T1_TUN_PACKET_MVP_SMOKE_OK"
