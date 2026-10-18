#!/usr/bin/env bash
set -euo pipefail

echo "[1/4] Terminal A (target interno de prueba):"
echo "      python3 -m http.server 18010 --bind 127.0.0.1"
echo
echo "[2/4] Terminal B (reverse-server con SOCKS5 local):"
echo "      ./bin/odyssey reverse-server \\"
echo "        --listen-control 127.0.0.1:20101 \\"
echo "        --token-file ./tests/tmp/token.txt \\"
echo "        --tls-mode disabled \\"
echo "        --socks-listen 127.0.0.1:21080"
echo
echo "[3/4] Terminal C (reverse-client):"
echo "      ./bin/odyssey reverse-client \\"
echo "        --connect 127.0.0.1:20101 \\"
echo "        --token-file ./tests/tmp/token.txt \\"
echo "        --tls-mode disabled \\"
echo "        --allow-target localhost:18010"
echo
echo "[4/4] Terminal D (uso SOCKS5 con curl):"
echo "      curl --socks5-hostname 127.0.0.1:21080 http://localhost:18010"
echo
echo "Tip proxychains:"
echo "  socks5 127.0.0.1 21080"
