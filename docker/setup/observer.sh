#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Get the bridge interface name from the network ID
BRIDGE_ID=$(docker network inspect iot-sim-net --format '{{.Id}}' | cut -c1-12)
BRIDGE_IFACE="br-${BRIDGE_ID}"

echo "Bridge interface: $BRIDGE_IFACE"

docker rm -f observer 2>/dev/null || true

docker run -d \
  --name observer \
  --net=host \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  -e BRIDGE_IFACE="$BRIDGE_IFACE" \
  -v "$PROJECT_ROOT/captures:/captures" \
  -v "$PROJECT_ROOT/extractor/extractor.py:/app/extractor.py" \
  nicolaka/netshoot \
  bash -c "
    ip link set $BRIDGE_IFACE promisc on &&
    apk add python3 py3-pip -q &&
    pip install scapy --break-system-packages -q &&
    python3 /app/extractor.py $BRIDGE_IFACE
  "