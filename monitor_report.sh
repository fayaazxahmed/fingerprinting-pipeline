#!/bin/bash

# ─────────────────────────────────────────
# IoT Simulation Network Monitor
# ─────────────────────────────────────────

NETWORK="iot-sim-net"
CAPTURE_DIR="./captures"
CONTAINERS=(
    "shared-service:192.168.10.50"
    "benign-tcp:192.168.10.11"
    "benign-udp:192.168.10.12"
    "hostile-scanner:192.168.10.20"
    "hostile-flooder:192.168.10.21"
    "hostile-beacon:192.168.10.22"
    "observer:192.168.10.100"
)

# ─────────────────────────────────────────
# 1. NETWORK HEALTH
# ─────────────────────────────────────────
echo "=============================="
echo " NETWORK STATUS"
echo "=============================="
docker network inspect $NETWORK --format '
Network:    {{.Name}}
Driver:     {{.Driver}}
Subnet:     {{range .IPAM.Config}}{{.Subnet}}{{end}}
Gateway:    {{range .IPAM.Config}}{{.Gateway}}{{end}}
Containers: {{len .Containers}} connected
'

# ─────────────────────────────────────────
# 2. CONTAINER STATUS + IP VERIFICATION
# ─────────────────────────────────────────
echo "=============================="
echo " CONTAINER STATUS"
echo "=============================="
printf "%-20s %-18s %-12s %-10s\n" "NAME" "IP" "STATUS" "UPTIME"
echo "──────────────────────────────────────────────────────────"
for entry in "${CONTAINERS[@]}"; do
    NAME="${entry%%:*}"
    EXPECTED_IP="${entry##*:}"
    STATUS=$(docker inspect --format '{{.State.Status}}' $NAME 2>/dev/null || echo "not found")
    UPTIME=$(docker inspect --format '{{.State.StartedAt}}' $NAME 2>/dev/null || echo "N/A")
    ACTUAL_IP=$(docker inspect --format \
        '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
        $NAME 2>/dev/null || echo "N/A")
    IP_CHECK=""
    [ "$ACTUAL_IP" != "$EXPECTED_IP" ] && IP_CHECK=" ⚠ IP MISMATCH"
    printf "%-20s %-18s %-12s %-10s%s\n" \
        "$NAME" "$ACTUAL_IP" "$STATUS" "${UPTIME:0:19}" "$IP_CHECK"
done

# ─────────────────────────────────────────
# 3. PER-CONTAINER NETWORK STATS
# ─────────────────────────────────────────
echo ""
echo "=============================="
echo " NETWORK I/O PER CONTAINER"
echo "=============================="
printf "%-20s %-15s %-15s %-12s %-12s\n" \
    "NAME" "RX BYTES" "TX BYTES" "RX PACKETS" "TX PACKETS"
echo "──────────────────────────────────────────────────────────────────────"
for entry in "${CONTAINERS[@]}"; do
    NAME="${entry%%:*}"
    STATS=$(docker stats $NAME --no-stream --format \
        '{{.NetIO}}' 2>/dev/null || echo "N/A")
    RX=$(echo $STATS | awk '{print $1}')
    TX=$(echo $STATS | awk '{print $3}')
    RX_PKTS=$(docker exec $NAME cat /sys/class/net/eth0/statistics/rx_packets \
        2>/dev/null || echo "N/A")
    TX_PKTS=$(docker exec $NAME cat /sys/class/net/eth0/statistics/tx_packets \
        2>/dev/null || echo "N/A")
    printf "%-20s %-15s %-15s %-12s %-12s\n" \
        "$NAME" "$RX" "$TX" "$RX_PKTS" "$TX_PKTS"
done

# ─────────────────────────────────────────
# 4. LIVE TRAFFIC SNAPSHOT PER CONTAINER
# ─────────────────────────────────────────
echo ""
echo "=============================="
echo " LIVE TRAFFIC SNAPSHOT (5s)"
echo "=============================="
for entry in "${CONTAINERS[@]}"; do
    NAME="${entry%%:*}"
    IP="${entry##*:}"
    echo ""
    echo "── $NAME ($IP) ──"
    docker exec observer tcpdump -i eth0 -n \
        "host $IP" -c 10 --timeout 5 \
        2>/dev/null | head -12 || echo "  No traffic captured"
done

# ─────────────────────────────────────────
# 5. PROTOCOL BREAKDOWN PER CONTAINER
# ─────────────────────────────────────────
echo ""
echo "=============================="
echo " PROTOCOL BREAKDOWN"
echo "=============================="
for entry in "${CONTAINERS[@]}"; do
    NAME="${entry%%:*}"
    IP="${entry##*:}"
    echo ""
    echo "── $NAME ($IP) ──"
    echo "  TCP packets:"
    docker exec observer tcpdump -i eth0 -n \
        "tcp and host $IP" -c 20 --timeout 5 2>/dev/null \
        | grep -c "^[0-9]" || echo "  0"
    echo "  UDP packets:"
    docker exec observer tcpdump -i eth0 -n \
        "udp and host $IP" -c 20 --timeout 5 2>/dev/null \
        | grep -c "^[0-9]" || echo "  0"
done

# ─────────────────────────────────────────
# 6. SUSPICIOUS BEHAVIOUR FLAGS
# ─────────────────────────────────────────
echo ""
echo "=============================="
echo " SUSPICIOUS BEHAVIOUR FLAGS"
echo "=============================="

echo ""
echo "── Port scan detection (high unique dest ports from single IP) ──"
docker exec observer tcpdump -i eth0 -n "tcp[tcpflags] & tcp-syn != 0" \
    -c 100 --timeout 10 2>/dev/null \
    | awk '{print $3}' \
    | sed 's/\.[^.]*$//' \
    | sort | uniq -c | sort -rn \
    | awk '$1 > 5 {print "  ⚠ SCAN CANDIDATE: " $2 " (" $1 " SYN packets)"}'

echo ""
echo "── High-rate UDP sources (potential flood) ──"
docker exec observer tcpdump -i eth0 -n "udp" \
    -c 200 --timeout 10 2>/dev/null \
    | awk '{print $3}' \
    | sed 's/\.[^.]*$//' \
    | sort | uniq -c | sort -rn \
    | awk '$1 > 50 {print "  ⚠ FLOOD CANDIDATE: " $2 " (" $1 " UDP packets)"}'

echo ""
echo "── Unexpected destinations (traffic not destined for broker .50) ──"
docker exec observer tcpdump -i eth0 -n \
    "not dst 192.168.10.50 and not dst 192.168.10.100 and not dst 255.255.255.255" \
    -c 50 --timeout 10 2>/dev/null \
    | awk '{print $5}' \
    | sort | uniq -c | sort -rn \
    | awk '$1 > 0 {print "  ⚠ UNEXPECTED DEST: " $2 " (" $1 " packets)"}'

# ─────────────────────────────────────────
# 7. PCAP EXPORT FOR MODEL INGESTION
# ─────────────────────────────────────────
echo ""
echo "=============================="
echo " PCAP EXPORT"
echo "=============================="
mkdir -p $CAPTURE_DIR
for entry in "${CONTAINERS[@]}"; do
    NAME="${entry%%:*}"
    IP="${entry##*:}"
    OUTPUT="$CAPTURE_DIR/${NAME}_$(date +%Y%m%d_%H%M%S).pcap"
    echo "Capturing 30s of traffic from $NAME → $OUTPUT"
    docker exec observer tcpdump -i eth0 -n \
        "host $IP" -G 30 -W 1 -w "/captures/${NAME}.pcap" \
        2>/dev/null &
done
wait
echo "All captures written to $CAPTURE_DIR"
echo ""
echo "End of report"