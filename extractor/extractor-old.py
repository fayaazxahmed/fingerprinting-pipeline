from scapy.all import sniff, IP, TCP, UDP, Ether
import csv, time, os, math, sys
from collections import defaultdict

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_APP = os.path.dirname(os.path.abspath(__file__))
for path in (_ROOT, _APP):
    if path not in sys.path:
        sys.path.insert(0, path)

from log_util import log

OUTPUT = "/captures/features.csv"
WINDOW = 10

FIELDS = [
    "window_start", "src_ip",
    "network_packets_all_count",
    "network_tcp_flags_std_deviation",
    "network_mss_max",
    "network_packet_size_min",
    "network_ips_dst_count",
    "network_macs_dst_count",
    "network_packets_dst_count",
    "network_tcp_flags_fin_count",
    "network_window_size_max",
    "network_ip_length_min",
    "network_ttl_min",
    "network_ports_all_count",
    "network_tcp_flags_syn_count",
    "network_macs_src_count",
    "network_window_size_std_deviation",
    "network_mss_avg",
    "network_ip_flags_avg",
    "network_ips_all_count",
    "network_ports_dst_count",
]

# Initialize CSV with header columns for each feature
def initialize_csv():
    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    with open(OUTPUT, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(FIELDS)

# Per-device state buffers
buffers = defaultdict(lambda: {
    "packets_all":      [],
    "tcp_flags_vals":   [],
    "mss_vals":         [],
    "packet_sizes":     [],
    "dst_ips":          set(),
    "dst_macs":         set(),
    "src_macs":         set(),
    "dst_packet_count": defaultdict(int),
    "fin_count":        0,
    "syn_count":        0,
    "window_sizes":     [],
    "ip_lengths":       [],
    "ttls":             [],
    "src_ports":        set(),
    "dst_ports":        set(),
    "ip_flags_vals":    [],
    "all_ips":          set(),
})

window_start = time.time()

# Helpers
def std_dev(values):
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return round(math.sqrt(variance), 6)

def safe_min(values):
    return min(values) if values else None

def safe_max(values):
    return max(values) if values else None

def safe_avg(values):
    return round(sum(values) / len(values), 6) if values else None

def get_mss(pkt):
    if not pkt.haslayer(TCP):
        return None
    for opt_name, opt_val in pkt[TCP].options:
        if opt_name == "MSS":
            return opt_val
    return None

# Flush window to CSV
def flush(ts):
    if not buffers:
        log("No data to flush for this window")
        return

    write_header = not os.path.exists(OUTPUT) or os.path.getsize(OUTPUT) == 0

    with open(OUTPUT, "a", newline="") as f:
        writer = csv.writer(f)

        rows_written = 0
        for src_ip, b in buffers.items():
            if not b["packets_all"]:
                continue

            all_dst_packet_count = sum(b["dst_packet_count"].values())
            row = [
                round(ts, 3),
                src_ip,
                len(b["packets_all"]),
                std_dev(b["tcp_flags_vals"]),
                safe_max(b["mss_vals"]),
                safe_min(b["packet_sizes"]),
                len(b["dst_ips"]),
                len(b["dst_macs"]),
                all_dst_packet_count,
                b["fin_count"],
                safe_max(b["window_sizes"]),
                safe_min(b["ip_lengths"]),
                safe_min(b["ttls"]),
                len(b["src_ports"]) + len(b["dst_ports"]),
                b["syn_count"],
                len(b["src_macs"]),
                std_dev(b["window_sizes"]),
                safe_avg(b["mss_vals"]),
                safe_avg(b["ip_flags_vals"]),
                len(b["all_ips"]),
                len(b["dst_ports"]),
            ]
            writer.writerow(row)
            rows_written += 1

        f.flush()
        os.fsync(f.fileno())

    log(f"Flushed {rows_written} device rows to {OUTPUT}")
    buffers.clear()

# Packet handler
def handle_packet(pkt):
    global window_start

    now = time.time()
    if now - window_start >= WINDOW:
        log(f"Window closed — flushing at {time.strftime('%H:%M:%S')}")
        flush(window_start)
        window_start = now

    if not pkt.haslayer(IP):
        return

    src = pkt[IP].src
    b = buffers[src]

    b["packets_all"].append((now, len(pkt)))
    b["packet_sizes"].append(len(pkt))
    b["ip_lengths"].append(pkt[IP].len)
    b["ttls"].append(pkt[IP].ttl)
    b["ip_flags_vals"].append(int(pkt[IP].flags))
    b["all_ips"].add(pkt[IP].src)
    b["all_ips"].add(pkt[IP].dst)
    b["dst_ips"].add(pkt[IP].dst)

    if pkt.haslayer(Ether):
        b["dst_macs"].add(pkt[Ether].dst)
        b["src_macs"].add(pkt[Ether].src)

    if pkt.haslayer(TCP):
        flags = int(pkt[TCP].flags)
        b["tcp_flags_vals"].append(flags)
        b["window_sizes"].append(pkt[TCP].window)
        b["dst_ports"].add(pkt[TCP].dport)
        b["src_ports"].add(pkt[TCP].sport)
        b["dst_packet_count"][pkt[IP].dst] += 1

        if flags & 0x01:
            b["fin_count"] += 1
        if flags & 0x02:
            b["syn_count"] += 1

        mss = get_mss(pkt)
        if mss:
            b["mss_vals"].append(mss)

    elif pkt.haslayer(UDP):
        b["dst_ports"].add(pkt[UDP].dport)
        b["src_ports"].add(pkt[UDP].sport)
        b["dst_packet_count"][pkt[IP].dst] += 1

# Main
if __name__ == "__main__":
    os.makedirs("/captures", exist_ok=True)
    initialize_csv()

    sys.stdout = os.fdopen(sys.stdout.fileno(), "w", buffering=1)

    # Accept bridge interface as argument, fall back to eth0
    iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"

    log(f"Extractor starting — interface: {iface}, output: {OUTPUT}, window: {WINDOW}s")
    log(f"Enabling promiscuous mode on {iface}")

    # Enable promiscuous mode via OS before sniff starts
    os.system(f"ip link set {iface} promisc on")

    log("Waiting for packets...")

    try:
        sniff(iface=iface, prn=handle_packet, store=False, promisc=True)
    except KeyboardInterrupt:
        log("Interrupted — flushing final window")
        flush(window_start)
        log("Extractor stopped")
    except Exception as e:
        log(f"Fatal error: {e}")
        sys.exit(1)