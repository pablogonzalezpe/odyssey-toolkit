#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ODYSSEY="$ROOT_DIR/bin/odyssey"
WORK_DIR="/tmp/odyssey_u1_udp_relay"
PIDS=()

mkdir -p "$WORK_DIR"

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

echo "[U1] test 1/3: basic UDP relay (single datagram echo)"

python3 -c "
import socket, threading
def serve():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('127.0.0.1', 19001))
    s.settimeout(5)
    data, addr = s.recvfrom(4096)
    s.sendto(b'ECHO:' + data, addr)
    s.close()
t = threading.Thread(target=serve, daemon=True)
t.start()
t.join(6)
" &
track_pid "$!"
sleep 0.5

"$ODYSSEY" relay --listen 127.0.0.1:19000 --to 127.0.0.1:19001 --udp --verbose \
  >"$WORK_DIR/relay1.log" 2>&1 &
track_pid "$!"
sleep 0.5

REPLY=$(python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.sendto(b'HELLO_UDP', ('127.0.0.1', 19000))
data, _ = s.recvfrom(4096)
print(data.decode())
s.close()
")

if [ "$REPLY" != "ECHO:HELLO_UDP" ]; then
  echo "expected 'ECHO:HELLO_UDP', got '$REPLY'" >&2
  exit 1
fi
echo "[U1] ok 1/3"

echo "[U1] test 2/3: multiple clients"

python3 -c "
import socket, threading
def serve():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('127.0.0.1', 19011))
    s.settimeout(5)
    for _ in range(3):
        data, addr = s.recvfrom(4096)
        s.sendto(b'RE:' + data, addr)
    s.close()
t = threading.Thread(target=serve, daemon=True)
t.start()
t.join(6)
" &
track_pid "$!"
sleep 0.5

"$ODYSSEY" relay --listen 127.0.0.1:19010 --to 127.0.0.1:19011 --udp --verbose \
  >"$WORK_DIR/relay2.log" 2>&1 &
track_pid "$!"
sleep 0.5

REPLIES=$(python3 -c "
import socket
results = []
for i in range(3):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    msg = f'MSG{i}'.encode()
    s.sendto(msg, ('127.0.0.1', 19010))
    data, _ = s.recvfrom(4096)
    results.append(data.decode())
    s.close()
print(' '.join(sorted(results)))
")

if [ "$REPLIES" != "RE:MSG0 RE:MSG1 RE:MSG2" ]; then
  echo "expected 'RE:MSG0 RE:MSG1 RE:MSG2', got '$REPLIES'" >&2
  exit 1
fi
echo "[U1] ok 2/3"

echo "[U1] test 3/3: allow-source filtering"

"$ODYSSEY" relay --listen 127.0.0.1:19020 --to 127.0.0.1:19021 --udp \
  --allow-source 10.99.99.99 --verbose \
  >"$WORK_DIR/relay3.log" 2>&1 &
track_pid "$!"
sleep 0.5

python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
s.sendto(b'BLOCKED', ('127.0.0.1', 19020))
try:
    s.recvfrom(4096)
    print('FAIL')
except socket.timeout:
    print('OK')
s.close()
" >"$WORK_DIR/filter_result.txt"

FILTER_RESULT=$(cat "$WORK_DIR/filter_result.txt")
if [ "$FILTER_RESULT" != "OK" ]; then
  echo "expected source filter to block, got: $FILTER_RESULT" >&2
  exit 1
fi
grep -q "rejected" "$WORK_DIR/relay3.log"
echo "[U1] ok 3/3"

echo "U1_SMOKE_OK"
