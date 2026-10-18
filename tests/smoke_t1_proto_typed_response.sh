#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="/tmp/odyssey_t1_proto_typed"
PROBE="$WORK_DIR/t1_proto_probe"

mkdir -p "$WORK_DIR"

echo "[T1.3-RESP] test 1/2: compile proto probe"
gcc -O2 -Wall -Wextra -Wpedantic -std=c11 \
  -I"$ROOT_DIR/include" \
  "$ROOT_DIR/tests/_t1_proto_probe.c" \
  "$ROOT_DIR/src/od_proto.c" \
  "$ROOT_DIR/src/od_io.c" \
  "$ROOT_DIR/src/od_socket.c" \
  "$ROOT_DIR/src/od_log.c" \
  -o "$PROBE"
echo "[T1.3-RESP] ok 1/2"

echo "[T1.3-RESP] test 2/2: verify typed response envelope helper"
"$PROBE" typed >"$WORK_DIR/typed.out"
grep -q "^ok=true$" "$WORK_DIR/typed.out"
grep -q "^code=OK$" "$WORK_DIR/typed.out"
grep -q "^reason=probe$" "$WORK_DIR/typed.out"
grep -q "^correlation_id=corr-42$" "$WORK_DIR/typed.out"
grep -q "^ts_ms=123456789$" "$WORK_DIR/typed.out"
grep -q "^data:$" "$WORK_DIR/typed.out"
grep -q "^k1=v1$" "$WORK_DIR/typed.out"
grep -q "^k2=v2$" "$WORK_DIR/typed.out"
echo "[T1.3-RESP] ok 2/2"

echo "T1_PROTO_TYPED_RESPONSE_SMOKE_OK"
