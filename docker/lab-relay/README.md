# Lab: Relay

Demonstrates Odyssey relay mode forwarding traffic through a jumpbox to reach an isolated network.

## Network layout

```
pentester (10.10.10.3)       jumpbox (10.10.10.2 / 10.10.20.3)       destiny (10.10.20.2)
        |                              |                                     |
        +--- pentest-net 10.10.10.0/24 +--- internal-net 10.10.20.0/24 -----+
```

- **pentester** can only reach jumpbox (pentest-net)
- **destiny** can only reach jumpbox (internal-net)
- **jumpbox** bridges both networks with `odyssey relay`

## Usage

```bash
docker compose up -d --build
docker exec -it pentester sh
```

Inside the pentester container:

```bash
cat /root/instructions.txt
curl http://10.10.10.2:8080/flag.txt
```

Expected output: `FLAG{odyssey_relay_works}`

## Cleanup

```bash
docker compose down
```
