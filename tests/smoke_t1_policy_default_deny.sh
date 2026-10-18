#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="/tmp/odyssey_t1_policy_default_deny"
TOKEN_FILE="/tmp/odyssey_t1_policy_default_deny.token"

mkdir -p "$WORK_DIR"
printf '0123456789abcdefA\n' >"$TOKEN_FILE"

echo "[T1.2-DD] test 1/4: tun-agent denies empty allow-cidr list"
set +e
"$ROOT_DIR/bin/odyssey" reverse-client \
  --mode tun-agent \
  --connect 127.0.0.1:29920 \
  --token-file "$TOKEN_FILE" \
  --allow-port tcp:22 \
  --tls-mode disabled >"$WORK_DIR/no_allow_cidr.log" 2>&1
RC=$?
set -e
if [ "$RC" -eq 0 ]; then
  echo "expected allow-cidr required failure" >&2
  exit 1
fi
grep -q "TUN policy error: allow-cidr list is required" "$WORK_DIR/no_allow_cidr.log"
echo "[T1.2-DD] ok 1/4"

echo "[T1.2-DD] test 2/4: tun-agent denies empty allow-port list"
set +e
"$ROOT_DIR/bin/odyssey" reverse-client \
  --mode tun-agent \
  --connect 127.0.0.1:29921 \
  --token-file "$TOKEN_FILE" \
  --allow-cidr 10.77.0.0/24 \
  --tls-mode disabled >"$WORK_DIR/no_allow_port.log" 2>&1
RC=$?
set -e
if [ "$RC" -eq 0 ]; then
  echo "expected allow-port required failure" >&2
  exit 1
fi
grep -q "TUN policy error: allow-port list is required" "$WORK_DIR/no_allow_port.log"
echo "[T1.2-DD] ok 2/4"

echo "[T1.2-DD] test 3/4: gateway denies empty route-allow list"
set +e
"$ROOT_DIR/bin/odyssey" gateway \
  --listen-control 127.0.0.1:29922 \
  --token-file "$TOKEN_FILE" \
  --tun-name ody2 \
  --tun-cidr 10.77.0.1/24 \
  --tls-mode disabled >"$WORK_DIR/no_route_allow.log" 2>&1
RC=$?
set -e
if [ "$RC" -eq 0 ]; then
  echo "expected route-allow required failure" >&2
  exit 1
fi
grep -q "TUN policy error: route-allow list is required" "$WORK_DIR/no_route_allow.log"
echo "[T1.2-DD] ok 3/4"

echo "[T1.2-DD] test 4/4: tun-agent denies default route allow-cidr"
set +e
"$ROOT_DIR/bin/odyssey" reverse-client \
  --mode tun-agent \
  --connect 127.0.0.1:29923 \
  --token-file "$TOKEN_FILE" \
  --allow-cidr 0.0.0.0/0 \
  --allow-port tcp:443 \
  --tls-mode disabled >"$WORK_DIR/default_route.log" 2>&1
RC=$?
set -e
if [ "$RC" -eq 0 ]; then
  echo "expected default-route allow-cidr rejection" >&2
  exit 1
fi
grep -q "TUN policy error: default route 0.0.0.0/0 not allowed in T1" "$WORK_DIR/default_route.log"
echo "[T1.2-DD] ok 4/4"

echo "T1_POLICY_DEFAULT_DENY_SMOKE_OK"
