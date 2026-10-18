#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="/tmp/odyssey_t1_proto_names"
PROBE="$WORK_DIR/t1_proto_probe"

mkdir -p "$WORK_DIR"

echo "[T1.3] test 1/2: compile proto probe"
gcc -O2 -Wall -Wextra -Wpedantic -std=c11 \
  -I"$ROOT_DIR/include" \
  "$ROOT_DIR/tests/_t1_proto_probe.c" \
  "$ROOT_DIR/src/od_proto.c" \
  "$ROOT_DIR/src/od_io.c" \
  "$ROOT_DIR/src/od_socket.c" \
  "$ROOT_DIR/src/od_log.c" \
  -o "$PROBE"
echo "[T1.3] ok 1/2"

echo "[T1.3] test 2/2: verify TUN msg names mapping"
"$PROBE" names >"$WORK_DIR/names.out"
grep -q "28=TUN_CAPS_REQ" "$WORK_DIR/names.out"
grep -q "29=TUN_CAPS_RESP" "$WORK_DIR/names.out"
grep -q "30=TUN_STATUS_REQ" "$WORK_DIR/names.out"
grep -q "31=TUN_STATUS_RESP" "$WORK_DIR/names.out"
grep -q "32=TUN_ROUTE_ADD" "$WORK_DIR/names.out"
grep -q "33=TUN_ROUTE_DEL" "$WORK_DIR/names.out"
grep -q "34=TUN_ROUTE_LIST" "$WORK_DIR/names.out"
grep -q "35=TUN_ROUTE_LIST_RESP" "$WORK_DIR/names.out"
grep -q "36=TUN_POLICY_SET" "$WORK_DIR/names.out"
grep -q "37=TUN_POLICY_GET" "$WORK_DIR/names.out"
grep -q "38=TUN_POLICY_RESP" "$WORK_DIR/names.out"
grep -q "39=TUN_SESSION_LIST" "$WORK_DIR/names.out"
grep -q "40=TUN_SESSION_LIST_RESP" "$WORK_DIR/names.out"
grep -q "41=TUN_SESSION_CLOSE" "$WORK_DIR/names.out"
grep -q "42=TUN_KILLSWITCH_SET" "$WORK_DIR/names.out"
grep -q "43=TUN_MTU_SET" "$WORK_DIR/names.out"
grep -q "44=TUN_PKT" "$WORK_DIR/names.out"
grep -q "45=TUN_OK" "$WORK_DIR/names.out"
grep -q "46=TUN_FAIL" "$WORK_DIR/names.out"
grep -q "47=SNAPSHOT_REQ" "$WORK_DIR/names.out"
grep -q "48=SNAPSHOT_RESP" "$WORK_DIR/names.out"
echo "[T1.3] ok 2/2"

echo "T1_PROTO_MSG_NAMES_SMOKE_OK"
