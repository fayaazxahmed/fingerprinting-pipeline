#!/bin/bash

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PROJECT_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)

docker stop ip-conflict 2>/dev/null && docker rm ip-conflict 2>/dev/null

docker run -d \
  --name ip-conflict \
  --network iot-sim-net \
  --ip 192.168.10.45 \
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  --privileged \
  -v "$PROJECT_ROOT/extractor/ip_conflict_device.py:/app/ip_conflict_device.py" \
  python:3.11-slim \
  bash -c "pip install scapy -q && python3 /app/ip_conflict_device.py"