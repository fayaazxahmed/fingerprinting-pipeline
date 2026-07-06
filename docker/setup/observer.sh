#!/bin/bash
docker run -d \
  --name observer \
  --network iot-sim-net \
  --ip 192.168.10.100 \
  --cap-add NET_ADMIN \
  -v $(pwd)/captures:/captures \
  -v $(pwd)/extractor/extractor.py:/app/extractor.py \
  python:3.11-slim \
  bash -c "pip install scapy -q && python /app/extractor.py"