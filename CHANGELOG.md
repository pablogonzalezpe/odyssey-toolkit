# Changelog

All notable changes to Odyssey are documented in this file.

## [0.2.0] - 2026-10-25

### New feature
- **UDP relay mode.** Userspace NAT table that maps each client address:port to a connected DGRAM socket, with poll-based forwarding and configurable session timeout. Flags: `--udp`, `--udp-timeout-ms` (default 30 000 ms). Hardening options (`--allow-source`, `--rate-limit-per-min`) apply per datagram. Incompatible with `--knock-seq` (port-knocking is TCP only)

### Docker labs
- UDP relay lab (`docker/lab-udp-relay`) forwarding DNS queries through a jumpbox to an internal dnsmasq server

### Tests
- 3 new smoke tests for UDP relay: basic echo, multiple clients, and source filtering (`tests/smoke_u1_udp_relay.sh`)

## [0.1.0] - 2026-10-18

First public release. Single-binary C pivoting toolkit with six operating modes.

### Core tunneling
- Local TCP relay with multi-client support (fork on Linux, threads on Windows)
- Reverse tunnel with token authentication, heartbeat, and exponential-backoff reconnection
- Stream multiplexing over a single control channel with multiple concurrent data streams
- Multiple bind rules per tunnel (`--bind LOCAL:REMOTE`)
- SOCKS5 reverse proxy via `--socks-listen` (CONNECT, IPv4/domain, optional userpass auth)

### Security and transport
- TLS / mTLS via OpenSSL (`--tls-mode required|disabled`, `--require-mtls`)
- Token policy with minimum 16 characters and weak/demo value rejection
- Source filtering with `--allow-source` (exact IP or CIDR notation)
- Rate limiting with `--rate-limit-per-min`
- Port-knocking with `--knock-seq` on relay/server, standalone `odyssey knock`, and auto pre-connect knocking on `reverse-client`
- JSON structured logging with `--log-format json`

### Dynamic control plane
- Hot bind management to add, remove, and list binds at runtime
- Admin CLI (`odyssey admin`) for out-of-band management of binds, streams, routes, policies, killswitch, and snapshots
- Capabilities and status queries
- Stream control to list and close individual streams on demand
- Admin hardening with optional token and rate limiting

### Defensive TUN gateway (Linux)
- L3 tunnel mode where `odyssey gateway` creates a TUN interface (`ody0`) and bridges real IP packets to a remote `tun-agent` over the control channel
- Agent-side TUN (`ody_agent0`) with `--agent-tun-cidr` for full L3 forwarding
- Return-path validation on agent (source IP/port check on return traffic)
- Deny-by-default with explicit `--route-allow` and `--allow-cidr` / `--allow-port` allowlists
- Dynamic route and policy management at runtime
- Killswitch to instantly stop all data-plane forwarding
- Runtime snapshot to export full node state for diagnostics

### Build and platform
- Linux with GCC + Make and auto-detected OpenSSL via pkg-config
- Windows via MinGW cross-compile
- CI with GitHub Actions build and non-TUN smoke tests
- 23 smoke tests covering relay, SOCKS5, TLS, knock, admin, control, TUN, and gateway modes (3 more added in v0.2.0)

### Docker labs
- Docker Compose relay lab (`docker/lab-relay`) with three Alpine containers and two isolated networks
- Docker Compose reverse tunnel lab (`docker/lab-reverse`) demonstrating outbound control channel from jumpbox to pentester

## Next

- Docker Compose lab for SOCKS5 mode
- Docker Compose lab for reverse tunnel with TLS
