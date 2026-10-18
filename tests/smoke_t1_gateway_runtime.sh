#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="/tmp/odyssey_t1_gateway_runtime"
TOKEN_FILE="/tmp/odyssey_t1_gateway_runtime.token"
PROBE="$WORK_DIR/t1_gateway_probe"
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

echo "[T1.4] test 1/4: compile gateway probe"
gcc -O2 -Wall -Wextra -Wpedantic -std=c11 \
  -I"$ROOT_DIR/include" \
  "$ROOT_DIR/tests/_t1_gateway_probe.c" \
  "$ROOT_DIR/src/od_proto.c" \
  "$ROOT_DIR/src/od_io.c" \
  "$ROOT_DIR/src/od_socket.c" \
  "$ROOT_DIR/src/od_log.c" \
  -o "$PROBE"
echo "[T1.4] ok 1/4"

echo "[T1.4] test 2/4: gateway runtime starts and accepts control channel"
"$ROOT_DIR/bin/odyssey" gateway \
  --listen-control 127.0.0.1:29940 \
  --token-file "$TOKEN_FILE" \
  --tun-name ody4 \
  --tun-cidr 10.240.0.1/24 \
  --route-allow 10.240.0.0/24 \
  --tls-mode disabled >"$WORK_DIR/gateway.log" 2>&1 &
GW_PID="$!"
track_pid "$GW_PID"
sleep 2
if ! kill -0 "$GW_PID" 2>/dev/null; then
  if grep -q "CAP_NET_ADMIN required" "$WORK_DIR/gateway.log"; then
    echo "[T1.4] skip: no CAP_NET_ADMIN in current environment"
    exit 0
  fi
  echo "gateway failed to start unexpectedly" >&2
  cat "$WORK_DIR/gateway.log" >&2 || true
  exit 1
fi
grep -q "gateway runtime listening on 127.0.0.1:29940" "$WORK_DIR/gateway.log"
echo "[T1.4] ok 2/4"

echo "[T1.4] test 3/4: TUN_CAPS_REQ and TUN_STATUS_REQ work"
"$PROBE" 127.0.0.1 29940 "$(cat "$TOKEN_FILE")" caps >"$WORK_DIR/caps.out"
"$PROBE" 127.0.0.1 29940 "$(cat "$TOKEN_FILE")" status >"$WORK_DIR/status.out"
grep -q "reason=tun-capabilities" "$WORK_DIR/caps.out"
grep -q "tun_scaffold=true" "$WORK_DIR/caps.out"
grep -q "tun_actions=tun_caps_req,tun_status_req,tun_route_add,tun_route_del,tun_route_list,tun_policy_set,tun_policy_get,tun_killswitch_set,tun_pkt,snapshot" "$WORK_DIR/caps.out"
grep -q "reason=tun-status" "$WORK_DIR/status.out"
grep -q "tun_mode=scaffold" "$WORK_DIR/status.out"
grep -q "route_allow_count=1" "$WORK_DIR/status.out"
echo "[T1.4] ok 3/4"

echo "[T1.4] test 4/4: dynamic route add/list works in gateway runtime"
"$PROBE" 127.0.0.1 29940 "$(cat "$TOKEN_FILE")" route-add >"$WORK_DIR/route_add.out"
grep -q "route added 10.10.10.0/24" "$WORK_DIR/route_add.out"
"$PROBE" 127.0.0.1 29940 "$(cat "$TOKEN_FILE")" route-list >"$WORK_DIR/route_list.out"
grep -q "route\\[1\\]=10.10.10.0/24" "$WORK_DIR/route_list.out"
echo "[T1.4] ok 4/4"

echo "T1_GATEWAY_RUNTIME_SMOKE_OK"
