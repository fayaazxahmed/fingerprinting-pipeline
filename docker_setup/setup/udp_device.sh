#!/bin/bash
docker run -d \
  --name benign-udp \
  --network iot-sim-net \
  --ip 192.168.10.12 \
  python:3.11-slim \
  python -c "
import socket, time
while True:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b'sensor-reading:22.4C', ('192.168.10.50', 5005))
        s.close()
    except Exception as e:
        print(f'UDP error: {e}')
    time.sleep(3)
"