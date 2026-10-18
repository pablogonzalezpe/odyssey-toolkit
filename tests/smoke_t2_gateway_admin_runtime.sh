#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="/tmp/odyssey_t2_gateway_admin_runtime"
TOKEN_FILE="/tmp/odyssey_t2_gateway_admin_runtime.token"
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

echo "[T2.1/T2.2/T2.3] test 1/3: start gateway with admin listener"
"$ROOT_DIR/bin/odyssey" gateway \
  --listen-control 127.0.0.1:29970 \
  --token-file "$TOKEN_FILE" \
  --admin-listen 127.0.0.1:29971 \
  --admin-token-file "$TOKEN_FILE" \
  --tun-name ody_t2a \
  --tun-cidr 10.240.0.1/24 \
  --route-allow 10.240.0.0/24 \
  --tls-mode disabled >"$WORK_DIR/gateway.log" 2>&1 &
GW_PID="$!"
track_pid "$GW_PID"
sleep 2
if ! kill -0 "$GW_PID" 2>/dev/null; then
  if grep -q "CAP_NET_ADMIN required" "$WORK_DIR/gateway.log"; then
    echo "[T2.1/T2.2/T2.3] skip: no CAP_NET_ADMIN in current environment"
    exit 0
  fi
  echo "gateway failed to start unexpectedly" >&2
  cat "$WORK_DIR/gateway.log" >&2 || true
  exit 1
fi
"$ROOT_DIR/bin/odyssey" reverse-client \
  --mode tun-agent \
  --connect 127.0.0.1:29970 \
  --token-file "$TOKEN_FILE" \
  --allow-cidr 10.240.0.0/24 \
  --allow-port tcp:443 \
  --tls-mode disabled \
  --heartbeat-timeout-ms 5000 >"$WORK_DIR/tun_agent.log" 2>&1 &
track_pid "$!"
sleep 3
echo "[T2.1/T2.2/T2.3] ok 1/3"

echo "[T2.1/T2.2/T2.3] test 2/3: admin route and policy mutations are hot"
"$ROOT_DIR/bin/odyssey" admin --connect 127.0.0.1:29971 --token-file "$TOKEN_FILE" route-list >"$WORK_DIR/route_list_1.out"
"$ROOT_DIR/bin/odyssey" admin --connect 127.0.0.1:29971 --token-file "$TOKEN_FILE" route-add 10.241.0.0/24 >"$WORK_DIR/route_add.out"
"$ROOT_DIR/bin/odyssey" admin --connect 127.0.0.1:29971 --token-file "$TOKEN_FILE" route-list >"$WORK_DIR/route_list_2.out"
"$ROOT_DIR/bin/odyssey" admin --connect 127.0.0.1:29971 --token-file "$TOKEN_FILE" route-del 10.241.0.0/24 >"$WORK_DIR/route_del.out"
"$ROOT_DIR/bin/odyssey" admin --connect 127.0.0.1:29971 --token-file "$TOKEN_FILE" route-list >"$WORK_DIR/route_list_3.out"
"$ROOT_DIR/bin/odyssey" admin --connect 127.0.0.1:29971 --token-file "$TOKEN_FILE" policy-show >"$WORK_DIR/policy_1.out"
"$ROOT_DIR/bin/odyssey" admin --connect 127.0.0.1:29971 --token-file "$TOKEN_FILE" policy-allow-cidr-add 10.242.0.0/24 >"$WORK_DIR/policy_add_cidr.out"
"$ROOT_DIR/bin/odyssey" admin --connect 127.0.0.1:29971 --token-file "$TOKEN_FILE" policy-allow-port-add tcp:8443 >"$WORK_DIR/policy_add_port.out"
"$ROOT_DIR/bin/odyssey" admin --connect 127.0.0.1:29971 --token-file "$TOKEN_FILE" policy-show >"$WORK_DIR/policy_2.out"
"$ROOT_DIR/bin/odyssey" admin --connect 127.0.0.1:29971 --token-file "$TOKEN_FILE" policy-allow-cidr-del 10.242.0.0/24 >"$WORK_DIR/policy_del_cidr.out"
"$ROOT_DIR/bin/odyssey" admin --connect 127.0.0.1:29971 --token-file "$TOKEN_FILE" policy-allow-port-del tcp:8443 >"$WORK_DIR/policy_del_port.out"
"$ROOT_DIR/bin/odyssey" admin --connect 127.0.0.1:29971 --token-file "$TOKEN_FILE" policy-show >"$WORK_DIR/policy_3.out"
grep -q "route\\[0\\]=10.240.0.0/24" "$WORK_DIR/route_list_1.out"
grep -q "^OK route added 10.241.0.0/24" "$WORK_DIR/route_add.out"
grep -q "route\\[1\\]=10.241.0.0/24" "$WORK_DIR/route_list_2.out"
grep -q "^OK route deleted 10.241.0.0/24" "$WORK_DIR/route_del.out"
if grep -q "10.241.0.0/24" "$WORK_DIR/route_list_3.out"; then
  echo "expected deleted route to disappear from admin route-list" >&2
  exit 1
fi
grep -q "policy_known=true" "$WORK_DIR/policy_1.out"
grep -q "allow_cidr\\[0\\]=10.240.0.0/24" "$WORK_DIR/policy_1.out"
grep -q "allow_port\\[0\\]=tcp:443" "$WORK_DIR/policy_1.out"
grep -q "allow_cidr\\[1\\]=10.242.0.0/24" "$WORK_DIR/policy_2.out"
grep -q "allow_port\\[1\\]=tcp:8443" "$WORK_DIR/policy_2.out"
if grep -q "10.242.0.0/24" "$WORK_DIR/policy_3.out"; then
  echo "expected deleted policy CIDR to disappear from policy-show" >&2
  exit 1
fi
if grep -q "tcp:8443" "$WORK_DIR/policy_3.out"; then
  echo "expected deleted policy port to disappear from policy-show" >&2
  exit 1
fi
echo "[T2.1/T2.2/T2.3] ok 2/3"

echo "[T2.1/T2.2/T2.3] test 3/3: killswitch and snapshot export runtime state"
"$ROOT_DIR/bin/odyssey" admin --connect 127.0.0.1:29971 --token-file "$TOKEN_FILE" killswitch on >"$WORK_DIR/killswitch_on.out"
"$ROOT_DIR/bin/odyssey" admin --connect 127.0.0.1:29971 --token-file "$TOKEN_FILE" snapshot >"$WORK_DIR/snapshot_on.out"
"$ROOT_DIR/bin/odyssey" admin --connect 127.0.0.1:29971 --token-file "$TOKEN_FILE" killswitch off >"$WORK_DIR/killswitch_off.out"
"$ROOT_DIR/bin/odyssey" admin --connect 127.0.0.1:29971 --token-file "$TOKEN_FILE" snapshot >"$WORK_DIR/snapshot_off.out"
grep -q "^OK killswitch updated" "$WORK_DIR/killswitch_on.out"
grep -q "reason=snapshot" "$WORK_DIR/snapshot_on.out"
grep -q "killswitch_manual=true" "$WORK_DIR/snapshot_on.out"
grep -q "killswitch_blocking=true" "$WORK_DIR/snapshot_on.out"
grep -q "^OK killswitch updated" "$WORK_DIR/killswitch_off.out"
grep -q "killswitch_manual=false" "$WORK_DIR/snapshot_off.out"
grep -q "control_connected=true" "$WORK_DIR/snapshot_off.out"
echo "[T2.1/T2.2/T2.3] ok 3/3"

echo "T2_GATEWAY_ADMIN_RUNTIME_SMOKE_OK"
