#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="/tmp/odyssey_t2_gateway_ctl_dynamic"
TOKEN_FILE="/tmp/odyssey_t2_gateway_ctl_dynamic.token"
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

echo "[T2.1/T2.2/T2.3] test 1/1: control channel exposes dynamic route/policy/killswitch/snapshot"
"$ROOT_DIR/bin/odyssey" gateway \
  --listen-control 127.0.0.1:29972 \
  --token-file "$TOKEN_FILE" \
  --tun-name ody_t2c \
  --tun-cidr 10.250.0.1/24 \
  --route-allow 10.250.0.0/24 \
  --control-admin enabled \
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
  --connect 127.0.0.1:29972 \
  --token-file "$TOKEN_FILE" \
  --tls-mode disabled \
  --ctl-route-list \
  --ctl-route-add 10.250.9.0/24 \
  --ctl-route-list \
  --ctl-route-del 10.250.9.0/24 \
  --ctl-route-list \
  --ctl-policy-show \
  --ctl-policy-allow-cidr-add 10.250.8.0/24 \
  --ctl-policy-allow-port-add tcp:8443 \
  --ctl-policy-show \
  --ctl-killswitch on \
  --ctl-snapshot \
  --ctl-exit-after-admin \
  --heartbeat-timeout-ms 5000 \
  --verbose >"$WORK_DIR/ctl.log" 2>&1

grep -q "control route-list:" "$WORK_DIR/ctl.log"
grep -q "route\\[0\\]=10.250.0.0/24" "$WORK_DIR/ctl.log"
grep -q "control action ok: route added 10.250.9.0/24" "$WORK_DIR/ctl.log"
grep -q "route\\[1\\]=10.250.9.0/24" "$WORK_DIR/ctl.log"
grep -q "control action ok: route deleted 10.250.9.0/24" "$WORK_DIR/ctl.log"
grep -q "control policy-show:" "$WORK_DIR/ctl.log"
grep -q "policy_known=false" "$WORK_DIR/ctl.log"
grep -q "allow_cidr\\[0\\]=10.250.8.0/24" "$WORK_DIR/ctl.log"
grep -q "allow_port\\[0\\]=tcp:8443" "$WORK_DIR/ctl.log"
grep -q "control action ok: on" "$WORK_DIR/ctl.log"
grep -q "control snapshot:" "$WORK_DIR/ctl.log"
grep -q "killswitch_manual=true" "$WORK_DIR/ctl.log"
grep -q "killswitch_blocking=true" "$WORK_DIR/ctl.log"
echo "[T2.1/T2.2/T2.3] ok 1/1"

echo "T2_GATEWAY_CTL_DYNAMIC_SMOKE_OK"
