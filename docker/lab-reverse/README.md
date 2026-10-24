# Lab: Reverse Tunnel

Demonstrates Odyssey reverse tunnel mode where the jumpbox initiates the control channel back to the pentester.

## Network layout

```
pentester (10.10.10.3)       jumpbox (10.10.10.2 / 10.10.20.3)       destiny (10.10.20.2)
        |                              |                                     |
        +--- pentest-net 10.10.10.0/24 +--- internal-net 10.10.20.0/24 -----+
```

- **pentester** runs `odyssey reverse-server` and waits for the agent
- **jumpbox** runs `odyssey reverse-client` and connects back to pentester on port 9001
- **destiny** serves a file on port 8080 (only reachable from internal-net)

The bind rule on the server maps `127.0.0.1:8080` to `10.10.20.2:8080` through the tunnel.

## Usage

```bash
docker compose up -d --build
docker exec -it pentester-rev sh
```

Inside the pentester container:

```bash
cat /root/instructions.txt
curl http://127.0.0.1:8080/flag.txt
```

Expected output: `FLAG{odyssey_reverse_works}`

## Difference from the relay lab

In the relay lab, the pentester connects to jumpbox:8080 and the relay forwards to destiny. Here, the jumpbox calls back to the pentester. The pentester accesses the tunneled service on its own localhost (127.0.0.1:8080). No inbound port is needed on the jumpbox for data.

## Cleanup

```bash
docker compose down
```
