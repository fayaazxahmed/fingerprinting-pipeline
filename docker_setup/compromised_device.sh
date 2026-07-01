#!/bin/bash
docker run -d \
  --name hostile-beacon \
  --network iot-sim-net \
  --ip 192.168.10.22 \
  python:3.11-slim \
  python -c "
import socket, time
while True:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(('192.168.10.99', 4444))
        s.send(b'beacon:checkin')
        s.close()
    except:
        pass
    time.sleep(8)
"