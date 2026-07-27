#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

BRIDGE_ID=$(docker network inspect iot-sim-net --format '{{.Id}}' | cut -c1-12)
BRIDGE_IFACE="br-${BRIDGE_ID}"

echo "Bridge interface: $BRIDGE_IFACE"

docker rm -f observer 2>/dev/null || true

docker run -d \
  --name observer \
  --network host \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  -v "$PROJECT_ROOT/captures:/captures" \
  -v "$PROJECT_ROOT/extractor/extractor.py:/app/extractor.py" \
  -v "$PROJECT_ROOT/log_util.py:/app/log_util.py" \
  nicolaka/netshoot \
  bash -c "
    ip link set $BRIDGE_IFACE promisc on &&
    apk add python3 py3-pip -q &&
    pip install scapy --break-system-packages -q &&
    python3 /app/extractor.py $BRIDGE_IFACE
  "
