# Lab: WebSocket Transport

Demonstrates Odyssey reverse tunnel with the control channel over WebSocket (--transport ws).

## Network layout

```
pentester (10.10.10.3)       jumpbox (10.10.10.2 / 10.10.20.3)       destiny (10.10.20.2)
        |                              |                                     |
        +--- pentest-net 10.10.10.0/24 +--- internal-net 10.10.20.0/24 -----+
```

- **pentester** runs `odyssey reverse-server --transport ws` and waits for the agent
- **jumpbox** runs `odyssey reverse-client --transport ws` and connects back over WebSocket
- **destiny** serves a file on port 8080 (only reachable from internal-net)

The bind rule on the server maps `127.0.0.1:8080` to `10.10.20.2:8080` through the tunnel.

## Usage

```bash
docker compose up -d --build
docker exec -it pentester-ws sh
```

Inside the pentester container:

```bash
cat /root/instructions.txt
curl http://127.0.0.1:8080/flag.txt
```

Expected output: `FLAG{odyssey_ws_transport_works}`

## What is different

The control channel uses WebSocket binary frames (RFC 6455) instead of raw TCP.
Both sides perform an HTTP Upgrade handshake before the Odyssey protocol starts.
The tunnel multiplexing, binds, SOCKS5 and data streams are unchanged.

## Cleanup

```bash
docker compose down
```
