#!/bin/bash
docker run -d \
  --name shared-service \
  --network iot-sim-net \
  --ip 192.168.10.50 \
  -p 1883:1883 \
  -p 9001:9001 \
  eclipse-mosquitto