#!/bin/bash
# pktgen.sh — 48-thread line-rate packet generator
# Usage: ./pktgen.sh <dst_ip> <dst_mac> <pkt_size> <duration_sec>

DST_IP="${1:-192.168.100.1}"
DST_MAC="${2:-98:03:9b:7f:72:00}"
PKT_SIZE="${3:-64}"
DURATION="${4:-10}"
NUM_THREADS="${5:-48}"
IFACE="enp175s0f0np0"

pgset() {
    local dev="$1"
    local val="$2"
    echo "$val" > "$dev"
}

echo "=== pktgen multi-queue ==="
echo "  dst_ip=$DST_IP  dst_mac=$DST_MAC"
echo "  pkt_size=${PKT_SIZE}B  threads=$NUM_THREADS  duration=${DURATION}s"
echo ""

# Stop any running instance
echo "stop" > /proc/net/pktgen/pgctrl 2>/dev/null
sleep 0.5

# Configure each thread
for i in $(seq 0 $((NUM_THREADS - 1))); do
    THREAD="/proc/net/pktgen/kpktgend_${i}"
    DEV="/proc/net/pktgen/${IFACE}@${i}"

    pgset "$THREAD" "rem_device_all"
    pgset "$THREAD" "add_device ${IFACE}@${i}"

    pgset "$DEV" "count 0"
    pgset "$DEV" "pkt_size ${PKT_SIZE}"
    pgset "$DEV" "dst_mac ${DST_MAC}"
    pgset "$DEV" "dst ${DST_IP}"
    pgset "$DEV" "src_min 192.168.100.2"
    pgset "$DEV" "src_max 192.168.100.2"
    pgset "$DEV" "udp_src_min $((1024 + i * 256))"
    pgset "$DEV" "udp_src_max $((1024 + i * 256 + 255))"
    pgset "$DEV" "udp_dst_min 5001"
    pgset "$DEV" "udp_dst_max 5001"
    pgset "$DEV" "flag UDPSRC_RND"
    pgset "$DEV" "delay 0"
    #pgset "$DEV" "clone_skb 1000000"
    pgset "$DEV" "clone_skb 0"
    pgset "$DEV" "burst 64"
done

echo "All $NUM_THREADS threads configured. Starting..."
echo "start" > /proc/net/pktgen/pgctrl &

# Sample every second, compute delta (instantaneous pps)
sleep 1
prev=0
for s in $(seq 1 $((DURATION - 1))); do
    total=0
    for i in $(seq 0 $((NUM_THREADS - 1))); do
        pkts=$(grep "pkts-sofar" /proc/net/pktgen/${IFACE}@${i} 2>/dev/null \
               | awk '{print $2}' | tr -d '[:space:]')
        [[ "$pkts" =~ ^[0-9]+$ ]] && total=$((total + pkts))
    done
    delta=$((total - prev))
    mpps_inst=$(python3 -c "print(f'{$delta/1e6:.3f}')")
    echo "  [${s}s] $total pkts-sofar  |  ${mpps_inst} Mpps instant"
    prev=$total
    sleep 1
done

# Read final stats BEFORE stopping
echo ""
echo "Reading final stats..."
total_pkts=0
total_errors=0
for i in $(seq 0 $((NUM_THREADS - 1))); do
    DEV="/proc/net/pktgen/${IFACE}@${i}"
    pkts=$(grep "pkts-sofar" "$DEV" 2>/dev/null | awk '{print $2}' | tr -d '[:space:]')
    # errors: line looks like "errors: 0" — match exactly
    errs=$(grep "^  errors:" "$DEV" 2>/dev/null | awk '{print $2}' | tr -d '[:space:]')
    [[ "$pkts"  =~ ^[0-9]+$ ]] && total_pkts=$((total_pkts + pkts))
    [[ "$errs"  =~ ^[0-9]+$ ]] && total_errors=$((total_errors + errs))
done

# Now stop
echo "stop" > /proc/net/pktgen/pgctrl
sleep 0.5

elapsed=$((DURATION - 1))  # exclude ramp-up second
echo ""
echo "=== Summary ==="
echo "  Total packets TX : $total_pkts"
echo "  Total errors     : $total_errors"
python3 -c "
pkts=$total_pkts
sz=$PKT_SIZE
dur=$elapsed
if dur > 0:
    mpps = pkts / dur / 1e6
    gbps = pkts * sz * 8 / dur / 1e9
    print(f'  Throughput       : {mpps:.3f} Mpps  /  {gbps:.2f} Gbps')
else:
    print('  Throughput       : N/A')
"
