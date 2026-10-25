# Lab: UDP Relay (DNS forwarding)

Demonstrates Odyssey UDP relay mode forwarding DNS queries through a jumpbox to an internal DNS server.

## Network layout

```
pentester (10.10.10.3)       jumpbox (10.10.10.2 / 10.10.20.3)       destiny (10.10.20.2)
        |                              |                                     |
        +--- pentest-net 10.10.10.0/24 +--- internal-net 10.10.20.0/24 -----+
```

- **pentester** sends DNS queries with `dig`
- **jumpbox** runs `odyssey relay --udp` forwarding port 53 to destiny
- **destiny** runs dnsmasq with a custom zone (`secret.internal` resolves to `10.10.20.99`)

## Usage

```bash
docker compose up -d --build
docker exec -it pentester-udp sh
```

Inside the pentester container:

```bash
cat /root/instructions.txt
dig @10.10.10.2 secret.internal
```

Expected answer: `secret.internal. 0 IN A 10.10.20.99`

## Difference from the TCP relay lab

DNS traffic is UDP. The relay creates a NAT session per client and forwards datagrams without establishing a TCP connection. This is the same mechanism used for forwarding SNMP, syslog, or any other UDP service through a jumpbox.

## Cleanup

```bash
docker compose down
```
