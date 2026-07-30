docker run -d \
  --name similar-hostile \
  --network iot-sim-net \
  --ip 192.168.10.31 \
  python:3.11-slim \
  python -c "
import socket, time, random
targets = ['192.168.10.11', '192.168.10.12', '192.168.10.13', '192.168.10.50']
ports = [5005, 5006, 1883, 8080, 4444, 22]
idx = 0
while True:
    try:
        # mimic sensor: send one UDP packet to broker
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = f'temp:{round(random.uniform(20.0, 25.0), 2)}'.encode()
        s.sendto(payload, ('192.168.10.50', 5005))
        s.close()

        # hostile: also probe one target/port per cycle, slowly
        t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        t.settimeout(0.5)
        t.connect((targets[idx % len(targets)], ports[idx % len(ports)]))
        t.close()
    except:
        pass
    idx += 1
    time.sleep(random.uniform(4.5, 5.5))
"