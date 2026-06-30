#!/bin/bash
docker run -d \
  --name benign-tcp \
  --network iot-sim-net \
  --ip 192.168.10.11 \
  python:3.11-slim \
  python -c "
import socket, time
while True:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('192.168.10.50', 1883))
    s.send(b'tcp-heartbeat')
    s.close()
    time.sleep(5)
"