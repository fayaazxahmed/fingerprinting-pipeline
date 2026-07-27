from scapy.all import sniff, IP, TCP, UDP, Ether
import csv, time, os, math, sys
from collections import defaultdict
import time

def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)
    sys.stdout.flush()

OUTPUT = "/captures/features.csv"
WINDOW = 10

FIELDS = [
    # ── Metadata ──────────────────────────────────────────────────────────────
    "window_start",
    "src_ip",

    # ── Packet counts ─────────────────────────────────────────────────────────
    "network_packets_all_count",
    "network_packets_dst_count",
    "network_packets_src_count",

    # ── IP address counts ─────────────────────────────────────────────────────
    "network_ips_all_count",
    "network_ips_dst_count",
    "network_ips_src_count",

    # ── MAC address counts ────────────────────────────────────────────────────
    "network_macs_all_count",
    "network_macs_dst_count",
    "network_macs_src_count",

    # ── Port counts ───────────────────────────────────────────────────────────
    "network_ports_all_count",
    "network_ports_dst_count",
    "network_ports_src_count",

    # ── Protocol counts ───────────────────────────────────────────────────────
    "network_protocols_all_count",
    "network_protocols_dst_count",
    "network_protocols_src_count",

    # ── Packet size stats ─────────────────────────────────────────────────────
    "network_packet-size_avg",
    "network_packet-size_max",
    "network_packet-size_min",
    "network_packet-size_std_deviation",

    # ── Payload length stats ──────────────────────────────────────────────────
    "network_payload-length_avg",
    "network_payload-length_max",
    "network_payload-length_min",
    "network_payload-length_std_deviation",

    # ── IP length stats ───────────────────────────────────────────────────────
    "network_ip-length_avg",
    "network_ip-length_max",
    "network_ip-length_min",
    "network_ip-length_std_deviation",

    # ── Header length stats ───────────────────────────────────────────────────
    "network_header-length_avg",
    "network_header-length_max",
    "network_header-length_min",
    "network_header-length_std_deviation",

    # ── TTL stats ─────────────────────────────────────────────────────────────
    "network_ttl_avg",
    "network_ttl_max",
    "network_ttl_min",
    "network_ttl_std_deviation",

    # ── IP flags stats ────────────────────────────────────────────────────────
    "network_ip-flags_avg",
    "network_ip-flags_max",
    "network_ip-flags_min",
    "network_ip-flags_std_deviation",

    # ── TCP flag counts ───────────────────────────────────────────────────────
    "network_tcp-flags-ack_count",
    "network_tcp-flags-fin_count",
    "network_tcp-flags-psh_count",
    "network_tcp-flags-rst_count",
    "network_tcp-flags-syn_count",
    "network_tcp-flags-urg_count",

    # ── TCP flag value stats ──────────────────────────────────────────────────
    "network_tcp-flags_avg",
    "network_tcp-flags_max",
    "network_tcp-flags_min",
    "network_tcp-flags_std_deviation",

    # ── TCP window size stats ─────────────────────────────────────────────────
    "network_window-size_avg",
    "network_window-size_max",
    "network_window-size_min",
    "network_window-size_std_deviation",

    # ── MSS stats ─────────────────────────────────────────────────────────────
    "network_mss_avg",
    "network_mss_max",
    "network_mss_min",
    "network_mss_std_deviation",

    # ── Inter-packet timing ───────────────────────────────────────────────────
    "network_time-delta_avg",
    "network_time-delta_max",
    "network_time-delta_min",
    "network_time-delta_std_deviation",
    "network_interval-packets",

    # ── Fragmentation ─────────────────────────────────────────────────────────
    "network_fragmentation-score",
    "network_fragmented-packets",

    # ── Log / message fields ──────────────────────────────────────────────────
    "log_data-ranges_avg",
    "log_data-ranges_max",
    "log_data-ranges_min",
    "log_data-ranges_std_deviation",
    "log_data-types_count",
    "log_interval-messages",
    "log_messages_count",
]


# ── CSV initialisation ────────────────────────────────────────────────────────

def initialize_csv():
    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    with open(OUTPUT, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(FIELDS)
        f.flush()


# ── Per-device state buffers ──────────────────────────────────────────────────

buffers = defaultdict(lambda: {
    # Packet tracking
    "packets_all":          [],       # (timestamp, size) tuples for all packets
    "packet_sizes":         [],
    "dst_packet_count":     defaultdict(int),
    "src_packet_count":     0,

    # IP addresses
    "src_ips":              set(),
    "dst_ips":              set(),
    "all_ips":              set(),

    # MAC addresses
    "src_macs":             set(),
    "dst_macs":             set(),
    "all_macs":             set(),

    # Ports
    "src_ports":            set(),
    "dst_ports":            set(),

    # Protocols
    "dst_protocols":        set(),
    "src_protocols":        set(),
    "all_protocols":        set(),

    # IP layer stats
    "ip_lengths":           [],
    "header_lengths":       [],
    "ttls":                 [],
    "ip_flags_vals":        [],

    # Payload
    "payload_lengths":      [],

    # TCP
    "tcp_flags_vals":       [],
    "window_sizes":         [],
    "mss_vals":             [],
    "ack_count":            0,
    "fin_count":            0,
    "psh_count":            0,
    "rst_count":            0,
    "syn_count":            0,
    "urg_count":            0,

    # Timing
    "packet_times":         [],       # raw timestamps for delta computation

    # Fragmentation
    "fragmented_count":     0,

    # Log / message (approximated from payload size ranges)
    "payload_ranges":       [],       # max-min payload size per burst
    "payload_type_set":     set(),    # unique payload size buckets as type proxy
    "message_count":        0,
    "last_message_time":    None,
    "message_intervals":    [],
})

window_start = time.time()


# ── Math helpers ──────────────────────────────────────────────────────────────

def std_dev(values):
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return round(math.sqrt(variance), 6)

def safe_min(values):
    return round(min(values), 6) if values else 0

def safe_max(values):
    return round(max(values), 6) if values else 0

def safe_avg(values):
    return round(sum(values) / len(values), 6) if values else 0

def compute_deltas(times):
    """Returns list of inter-packet time deltas in milliseconds."""
    if len(times) < 2:
        return []
    return [round((times[i] - times[i - 1]) * 1000, 6)
            for i in range(1, len(times))]

def get_mss(pkt):
    if not pkt.haslayer(TCP):
        return None
    for opt_name, opt_val in pkt[TCP].options:
        if opt_name == "MSS":
            return opt_val
    return None

def get_protocol_name(pkt):
    """Returns a simple protocol string for the packet."""
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    return "OTHER"


# ── Flush window to CSV ───────────────────────────────────────────────────────

def flush(ts):
    if not buffers:
        log("No data to flush for this window")
        return

    with open(OUTPUT, "a", newline="") as f:
        writer = csv.writer(f)

        rows_written = 0
        for src_ip, b in buffers.items():
            if not b["packets_all"]:
                continue

            # ── Counts ────────────────────────────────────────────────────────
            packets_all_count  = len(b["packets_all"])
            packets_dst_count  = sum(b["dst_packet_count"].values())
            packets_src_count  = b["src_packet_count"]

            # ── Timing deltas ─────────────────────────────────────────────────
            deltas             = compute_deltas(b["packet_times"])
            interval_packets   = len(deltas)

            # ── Fragmentation score ───────────────────────────────────────────
            frag_score = (
                round(b["fragmented_count"] / packets_all_count, 6)
                if packets_all_count > 0 else 0
            )

            # ── Log / message approximations ──────────────────────────────────
            # payload_ranges approximates data-ranges (spread of payload sizes)
            # payload_type_set approximates distinct data types seen
            # message_count tracks packets with non-zero payload as messages
            log_ranges = b["payload_ranges"] if b["payload_ranges"] else [0]
            msg_intervals = b["message_intervals"] if b["message_intervals"] else [0]

            row = [
                # Metadata
                round(ts, 3),
                src_ip,

                # Packet counts
                packets_all_count,
                packets_dst_count,
                packets_src_count,

                # IP address counts
                len(b["all_ips"]),
                len(b["dst_ips"]),
                len(b["src_ips"]),

                # MAC address counts
                len(b["all_macs"]),
                len(b["dst_macs"]),
                len(b["src_macs"]),

                # Port counts
                len(b["src_ports"]) + len(b["dst_ports"]),
                len(b["dst_ports"]),
                len(b["src_ports"]),

                # Protocol counts
                len(b["all_protocols"]),
                len(b["dst_protocols"]),
                len(b["src_protocols"]),

                # Packet size stats
                safe_avg(b["packet_sizes"]),
                safe_max(b["packet_sizes"]),
                safe_min(b["packet_sizes"]),
                std_dev(b["packet_sizes"]),

                # Payload length stats
                safe_avg(b["payload_lengths"]),
                safe_max(b["payload_lengths"]),
                safe_min(b["payload_lengths"]),
                std_dev(b["payload_lengths"]),

                # IP length stats
                safe_avg(b["ip_lengths"]),
                safe_max(b["ip_lengths"]),
                safe_min(b["ip_lengths"]),
                std_dev(b["ip_lengths"]),

                # Header length stats
                safe_avg(b["header_lengths"]),
                safe_max(b["header_lengths"]),
                safe_min(b["header_lengths"]),
                std_dev(b["header_lengths"]),

                # TTL stats
                safe_avg(b["ttls"]),
                safe_max(b["ttls"]),
                safe_min(b["ttls"]),
                std_dev(b["ttls"]),

                # IP flags stats
                safe_avg(b["ip_flags_vals"]),
                safe_max(b["ip_flags_vals"]),
                safe_min(b["ip_flags_vals"]),
                std_dev(b["ip_flags_vals"]),

                # TCP flag counts
                b["ack_count"],
                b["fin_count"],
                b["psh_count"],
                b["rst_count"],
                b["syn_count"],
                b["urg_count"],

                # TCP flag value stats
                safe_avg(b["tcp_flags_vals"]),
                safe_max(b["tcp_flags_vals"]),
                safe_min(b["tcp_flags_vals"]),
                std_dev(b["tcp_flags_vals"]),

                # Window size stats
                safe_avg(b["window_sizes"]),
                safe_max(b["window_sizes"]),
                safe_min(b["window_sizes"]),
                std_dev(b["window_sizes"]),

                # MSS stats
                safe_avg(b["mss_vals"]),
                safe_max(b["mss_vals"]),
                safe_min(b["mss_vals"]),
                std_dev(b["mss_vals"]),

                # Time delta stats
                safe_avg(deltas),
                safe_max(deltas),
                safe_min(deltas),
                std_dev(deltas),
                interval_packets,

                # Fragmentation
                frag_score,
                b["fragmented_count"],

                # Log / message approximations
                safe_avg(log_ranges),
                safe_max(log_ranges),
                safe_min(log_ranges),
                std_dev(log_ranges),
                len(b["payload_type_set"]),
                safe_avg(msg_intervals),
                b["message_count"],
            ]

            writer.writerow(row)
            rows_written += 1

        f.flush()
        os.fsync(f.fileno())

    log(f"Flushed {rows_written} device rows to {OUTPUT}")
    buffers.clear()


# ── Packet handler ────────────────────────────────────────────────────────────

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
    b   = buffers[src]

    # ── Packet-level ──────────────────────────────────────────────────────────
    pkt_size = len(pkt)
    b["packets_all"].append((now, pkt_size))
    b["packet_sizes"].append(pkt_size)
    b["packet_times"].append(now)
    b["src_packet_count"] += 1

    # ── IP layer ──────────────────────────────────────────────────────────────
    ip_len        = pkt[IP].len
    header_len    = pkt[IP].ihl * 4          # IHL is in 32-bit words
    payload_len   = max(ip_len - header_len, 0)
    ip_flag_val   = int(pkt[IP].flags)
    is_fragmented = (ip_flag_val & 0x1) or (pkt[IP].frag > 0)  # MF flag or offset

    b["ip_lengths"].append(ip_len)
    b["header_lengths"].append(header_len)
    b["payload_lengths"].append(payload_len)
    b["ttls"].append(pkt[IP].ttl)
    b["ip_flags_vals"].append(ip_flag_val)

    b["src_ips"].add(pkt[IP].src)
    b["dst_ips"].add(pkt[IP].dst)
    b["all_ips"].add(pkt[IP].src)
    b["all_ips"].add(pkt[IP].dst)

    b["dst_packet_count"][pkt[IP].dst] += 1

    if is_fragmented:
        b["fragmented_count"] += 1

    # ── MAC layer ─────────────────────────────────────────────────────────────
    if pkt.haslayer(Ether):
        src_mac = pkt[Ether].src
        dst_mac = pkt[Ether].dst
        b["src_macs"].add(src_mac)
        b["dst_macs"].add(dst_mac)
        b["all_macs"].add(src_mac)
        b["all_macs"].add(dst_mac)

    # ── Protocol tracking ─────────────────────────────────────────────────────
    proto = get_protocol_name(pkt)
    b["src_protocols"].add(proto)
    b["dst_protocols"].add(proto)
    b["all_protocols"].add(proto)

    # ── TCP layer ─────────────────────────────────────────────────────────────
    if pkt.haslayer(TCP):
        flags = int(pkt[TCP].flags)
        b["tcp_flags_vals"].append(flags)
        b["window_sizes"].append(pkt[TCP].window)
        b["dst_ports"].add(pkt[TCP].dport)
        b["src_ports"].add(pkt[TCP].sport)

        if flags & 0x10: b["ack_count"] += 1
        if flags & 0x01: b["fin_count"] += 1
        if flags & 0x08: b["psh_count"] += 1
        if flags & 0x04: b["rst_count"] += 1
        if flags & 0x02: b["syn_count"] += 1
        if flags & 0x20: b["urg_count"] += 1

        mss = get_mss(pkt)
        if mss:
            b["mss_vals"].append(mss)

    # ── UDP layer ─────────────────────────────────────────────────────────────
    elif pkt.haslayer(UDP):
        b["dst_ports"].add(pkt[UDP].dport)
        b["src_ports"].add(pkt[UDP].sport)

    # ── Log / message approximation ───────────────────────────────────────────
    # Treat any packet with payload as a message and track payload size
    # ranges and type diversity as proxies for log_data-ranges and log_data-types
    if payload_len > 0:
        b["message_count"] += 1

        # Track inter-message intervals
        if b["last_message_time"] is not None:
            interval = round((now - b["last_message_time"]) * 1000, 6)
            b["message_intervals"].append(interval)
        b["last_message_time"] = now

        # Payload range: spread within a rolling buffer of last 10 payloads
        recent = b["payload_lengths"][-10:]
        if len(recent) > 1:
            b["payload_ranges"].append(max(recent) - min(recent))

        # Payload type bucket: group into size bands as a type proxy
        if payload_len < 64:
            b["payload_type_set"].add("tiny")
        elif payload_len < 256:
            b["payload_type_set"].add("small")
        elif payload_len < 1024:
            b["payload_type_set"].add("medium")
        else:
            b["payload_type_set"].add("large")


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    os.makedirs("/captures", exist_ok=True)
    initialize_csv()

    sys.stdout = os.fdopen(sys.stdout.fileno(), "w", buffering=1)

    iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"

    log(f"Extractor starting — interface: {iface}, output: {OUTPUT}, window: {WINDOW}s")
    log(f"Enabling promiscuous mode on {iface}")

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