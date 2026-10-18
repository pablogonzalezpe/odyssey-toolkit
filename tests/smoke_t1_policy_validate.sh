#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="/tmp/odyssey_t1_policy_validate"
TOKEN_FILE="/tmp/odyssey_t1_policy_validate.token"

mkdir -p "$WORK_DIR"
printf '0123456789abcdefA\n' >"$TOKEN_FILE"

echo "[T1.2] test 1/4: gateway rejects default route"
set +e
"$ROOT_DIR/bin/odyssey" gateway \
  --listen-control 127.0.0.1:29910 \
  --token-file "$TOKEN_FILE" \
  --tun-name ody0 \
  --tun-cidr 10.99.0.1/24 \
  --route-allow 0.0.0.0/0 \
  --tls-mode disabled >"$WORK_DIR/gateway_default_route.log" 2>&1
RC=$?
set -e
if [ "$RC" -eq 0 ]; then
  echo "expected gateway default-route rejection" >&2
  exit 1
fi
grep -q "TUN policy error: default route 0.0.0.0/0 not allowed in T1" "$WORK_DIR/gateway_default_route.log"
echo "[T1.2] ok 1/4"

echo "[T1.2] test 2/4: tun-agent rejects invalid allow-port spec"
set +e
"$ROOT_DIR/bin/odyssey" reverse-client \
  --mode tun-agent \
  --connect 127.0.0.1:29911 \
  --token-file "$TOKEN_FILE" \
  --allow-cidr 10.99.0.0/24 \
  --allow-port icmp:8 \
  --tls-mode disabled >"$WORK_DIR/tun_agent_bad_port.log" 2>&1
RC=$?
set -e
if [ "$RC" -eq 0 ]; then
  echo "expected tun-agent allow-port rejection" >&2
  exit 1
fi
grep -q "TUN policy error: invalid allow-port spec" "$WORK_DIR/tun_agent_bad_port.log"
echo "[T1.2] ok 2/4"

echo "[T1.2] test 3/4: gateway accepts strict route allowlist"
PIDS=()
cleanup() {
  local p
  for p in "${PIDS[@]:-}"; do
    kill "$p" 2>/dev/null || true
  done
}
trap cleanup EXIT

"$ROOT_DIR/bin/odyssey" gateway \
  --listen-control 127.0.0.1:29912 \
  --token-file "$TOKEN_FILE" \
  --tun-name ody1 \
  --tun-cidr 10.88.0.1/24 \
  --route-allow 10.88.0.0/24 \
  --tls-mode disabled >"$WORK_DIR/gateway_ok.log" 2>&1 &
GW_PID="$!"
PIDS+=("$GW_PID")
sleep 2
if ! kill -0 "$GW_PID" 2>/dev/null; then
  if grep -q "CAP_NET_ADMIN required" "$WORK_DIR/gateway_ok.log"; then
    echo "[T1.2] skip 3/4 (no CAP_NET_ADMIN)"
  else
    echo "gateway unexpectedly exited in test 3" >&2
    cat "$WORK_DIR/gateway_ok.log" >&2 || true
    exit 1
  fi
else
  grep -q "gateway runtime listening on 127.0.0.1:29912" "$WORK_DIR/gateway_ok.log"
fi
echo "[T1.2] ok 3/4"

echo "[T1.2] test 4/4: tun-agent accepts strict allowlists"
set +e
timeout 4 "$ROOT_DIR/bin/odyssey" reverse-client \
  --mode tun-agent \
  --connect 127.0.0.1:29913 \
  --token-file "$TOKEN_FILE" \
  --allow-cidr 10.88.0.0/24 \
  --allow-port tcp:443 \
  --allow-port udp:53 \
  --tls-mode disabled >"$WORK_DIR/tun_agent_ok.log" 2>&1
RC=$?
set -e
if [ "$RC" -ne 124 ]; then
  echo "expected timeout run for tun-agent runtime in test 4" >&2
  exit 1
fi
grep -q "reverse-client tun-agent runtime connect=127.0.0.1:29913" "$WORK_DIR/tun_agent_ok.log"
grep -q "default-deny=true" "$WORK_DIR/tun_agent_ok.log"
echo "[T1.2] ok 4/4"

echo "T1_POLICY_VALIDATE_SMOKE_OK"
