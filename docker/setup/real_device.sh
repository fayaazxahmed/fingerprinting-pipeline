docker run -d \
  --name real-device \
  --network iot-sim-net \
  --ip 192.168.10.40 \
  python:3.11-slim \
  python -c "
import socket, time, random
while True:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = b'sensor:real:temp:22.4'
        s.sendto(payload, ('192.168.10.50', 5005))
        s.close()
        print('real device sent', flush=True)
    except Exception as e:
        print(f'error: {e}', flush=True)
    time.sleep(5)
"