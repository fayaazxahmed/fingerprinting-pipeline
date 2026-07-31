docker run -d \
  --name similar-benign \
  --network iot-sim-net \
  --ip 192.168.10.30 \
  python:3.11-slim \
  python -c "
import socket, time, random
while True:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = f'temp:{round(random.uniform(20.0, 25.0), 2)}'.encode()
        s.sendto(payload, ('192.168.10.50', 5005))
        s.close()
        print(f'sent: {payload}', flush=True)
    except Exception as e:
        print(f'error: {e}', flush=True)
    time.sleep(random.uniform(4.5, 5.5))
"