#!/bin/sh
echo "Waiting for TLS certificate..."
while [ ! -f /certs/server.crt ]; do sleep 1; done
echo "Certificate found, connecting..."
exec odyssey reverse-client \
  --connect 10.10.10.3:9001 \
  --token-file /root/token.txt \
  --tls-mode required \
  --tls-ca /certs/server.crt
