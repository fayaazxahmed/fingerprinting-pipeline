#!/bin/bash
docker run -d \
  --name hostile-scanner \
  --network iot-sim-net \
  --ip 192.168.10.20 \
  python:3.11-slim \
  python -c "
import socket, time
targets = ['192.168.10.11', '192.168.10.12', '192.168.10.13', '192.168.10.50']
ports = [22, 80, 443, 1883, 5005, 5006, 8080, 8443]
while True:
    for ip in targets:
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                s.connect((ip, port))
                s.close()
            except:
                pass
    time.sleep(10)
"