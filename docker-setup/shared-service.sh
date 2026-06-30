#!/bin/bash
docker run -d \
  --name shared-service \
  --network iot-sim-net \
  --ip 192.168.10.50 \
  eclipse-mosquitto