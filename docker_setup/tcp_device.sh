#!/bin/bash
docker run -d \
  --name benign-tcp \
  --network iot-sim-net \
  --ip 192.168.10.11 \
  python:3.11-slim \
  python -c "
import socket, time
while True:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('192.168.10.50', 1883))
        s.send(b'meter-reading:00423kWh')
        s.close()
    except Exception as e:
        print(f'TCP error: {e}')
    time.sleep(5)
"