#!/usr/bin/env bash
set -euo pipefail

echo "[1/3] Launch test backend (terminal A): nc -lvnp 7000"
echo "[2/3] Launch relay (terminal B): ./bin/odyssey relay --listen 0.0.0.0:6000 --to 127.0.0.1:7000"
echo "[3/3] Connect client (terminal C): nc 127.0.0.1 6000"
