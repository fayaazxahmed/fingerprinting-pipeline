#!/bin/bash

docker stop spoofer 2>/dev/null && docker rm spoofer 2>/dev/null

docker run -d \
  --name spoofer \
  --network iot-sim-net \
  --ip 192.168.10.41 \
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  --privileged \
  -v "$(pwd)/extractor/spoofer.py:/app/spoofer.py" \
  python:3.11-slim \
  bash -c "apt-get update && apt-get install -y iproute2 tcpdump && pip install scapy -q && python3 /app/spoofer.py"