from scapy.all import sniff, IP, TCP, UDP, Ether
import csv, time, os

OUTPUT = "/captures/features.csv"
FIELDS = [
    "timestamp", "src_ip", "dst_ip", "protocol",
    "src_port", "dst_port", "payload_size",
    "tcp_flags", "inter_arrival_time"
]

last_seen = {}

def extract(pkt):
    if not pkt.haslayer(IP):
        return

    now = time.time()
    src = pkt[IP].src
    iat = round(now - last_seen.get(src, now), 6)
    last_seen[src] = now

    proto = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "OTHER"
    src_port = pkt[TCP].sport if pkt.haslayer(TCP) else \
               pkt[UDP].sport if pkt.haslayer(UDP) else None
    dst_port = pkt[TCP].dport if pkt.haslayer(TCP) else \
               pkt[UDP].dport if pkt.haslayer(UDP) else None
    flags = str(pkt[TCP].flags) if pkt.haslayer(TCP) else None
    size = len(pkt[IP].payload)

    row = [
        round(now, 6), src, pkt[IP].dst, proto,
        src_port, dst_port, size, flags, iat
    ]

    write_header = not os.path.exists(OUTPUT)
    with open(OUTPUT, "a", newline="") as f:
        writer = csv.writer(f)
        if write_header:
            writer.writerow(FIELDS)
        writer.writerow(row)
print(f"Extractor running — writing to {OUTPUT} every %s", flush=True)
sniff(iface="eth0", prn=extract, store=False)