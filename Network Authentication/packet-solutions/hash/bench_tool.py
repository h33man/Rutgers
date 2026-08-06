#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
bench_tool.py — Hash kfunc benchmark orchestration tool

Usage:
    python3 bench_tool.py instrcount
    python3 bench_tool.py latency    --iface <iface> --gen-host <host> --gen-iface <iface> --dst-ip <ip> --dst-mac <mac>
    python3 bench_tool.py throughput --iface <iface> --gen-host <host> --gen-iface <iface> --dst-ip <ip> --dst-mac <mac>
    python3 bench_tool.py all        --iface <iface> --gen-host <host> --gen-iface <iface> --dst-ip <ip> --dst-mac <mac>

Single-queue saturation (exposes hash cost per variant):
    python3 bench_tool.py throughput ... --num-threads 48 --num-rx-queues 1
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Variant definitions
# ---------------------------------------------------------------------------

VARIANTS = [
    "blank",
    "parse_only",
    "sha256",
    "sha512",
    "hmac_sha256",
    "hmac_sha512",
    "blake3",
    "chacha20",
    "kfunc_sha256",
    "pure_ebpf",
    "packet_resize",
]

KFUNC_VARIANTS = {"sha256", "sha512", "hmac_sha256", "hmac_sha512", "blake3", "chacha20", "kfunc_sha256"}

KFUNC_MODULES = {
    "sha256":      "sha256_crypto",
    "sha512":      "sha512_crypto",
    "hmac_sha256": "hmac_crypto",
    "hmac_sha512": "hmac_crypto",
    "blake3":      "blake3_kfunc",
    "chacha20":    "chacha20_kfunc",
    "kfunc_sha256": "sha256_kfunc",
}

BPF_PIN_ROOT  = "/sys/fs/bpf"
BPF_PIN_PATH  = f"{BPF_PIN_ROOT}/xdp_bench_prog"
BPF_MAP_DIR   = f"{BPF_PIN_ROOT}/xdp_bench_maps"
LAT_HIST_NAME = "lat_hist"
LAT_BUCKETS   = 64
NUM_THREADS   = 48

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(cmd, check=True, capture=True):
    result = subprocess.run(
        cmd, shell=True, check=check,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        text=True
    )
    return result

def ssh(host, cmd, check=True):
    full = f"ssh -o StrictHostKeyChecking=no -o BatchMode=yes {host} '{cmd}'"
    return run(full, check=check)

def log(msg):
    print(f"[bench] {msg}", flush=True)

# ---------------------------------------------------------------------------
# BPF program load / unload
# ---------------------------------------------------------------------------

def _pin_map_by_name(prog_pin, map_name, dest_pin):
    info = run(f"bpftool prog show pinned {prog_pin} -j", check=False).stdout
    try:
        prog_info = json.loads(info)
        for map_id in prog_info.get("map_ids", []):
            map_info = run(f"bpftool map show id {map_id} -j", check=False).stdout
            m = json.loads(map_info)
            if m.get("name") == map_name:
                run(f"bpftool map pin id {map_id} {dest_pin}", check=False)
                return True
    except (json.JSONDecodeError, KeyError):
        pass
    log(f"WARNING: could not pin {map_name}")
    return False

def load_variant(variant):
    obj = f"xdp_{variant}.o"
    if not Path(obj).exists():
        log(f"ERROR: {obj} not found — run 'make xdp' first")
        return False

    run(f"rm -f {BPF_PIN_PATH}", check=False)

    if variant == "blank":
        cmd = f"bpftool prog load {obj} {BPF_PIN_PATH} 2>bpftool_err.txt"
    elif variant == "pure_ebpf":
        run(f"rm -rf {BPF_MAP_DIR} && mkdir -p {BPF_MAP_DIR}", check=False)
        run("rm -f /sys/fs/bpf/xdp_stats_map", check=False)
        cmd = f"bpftool prog load {obj} {BPF_PIN_PATH} 2>bpftool_err.txt"
    else:
        run(f"rm -rf {BPF_MAP_DIR} && mkdir -p {BPF_MAP_DIR}", check=False)
        cmd = f"bpftool prog load {obj} {BPF_PIN_PATH} pinmaps {BPF_MAP_DIR} 2>bpftool_err.txt"

    result = run(cmd, check=False)
    if result.returncode != 0:
        err = Path("bpftool_err.txt").read_text().strip() if Path("bpftool_err.txt").exists() else ""
        log(f"FAILED to load {obj}:\n{err}")
        return False

    # Pin lat_hist map for any variant that uses it (all except blank)
    #if variant not in {"blank"}:
    if variant == "pure_ebpf":
        _pin_map_by_name(BPF_PIN_PATH, "lat_hist", f"{BPF_MAP_DIR}/lat_hist")

    return True

def attach_variant(iface):
    result = run(
        f"bpftool net attach xdp pinned {BPF_PIN_PATH} dev {iface} 2>bpftool_err.txt",
        check=False
    )
    if result.returncode != 0:
        err = Path("bpftool_err.txt").read_text().strip() if Path("bpftool_err.txt").exists() else ""
        log(f"FAILED to attach to {iface}:\n{err}")
        return False
    return True

def detach_unload(iface):
    run(f"bpftool net detach xdp dev {iface}", check=False)
    run(f"rm -f {BPF_PIN_PATH}", check=False)
    run(f"rm -rf {BPF_MAP_DIR}", check=False)
    run("rm -f /sys/fs/bpf/xdp_stats_map", check=False)

# ---------------------------------------------------------------------------
# Instruction count
# ---------------------------------------------------------------------------

def get_instrcount(variant):
    obj = f"xdp_{variant}.o"
    if not Path(obj).exists():
        return None, None

    run(f"rm -f {BPF_PIN_PATH}", check=False)

    if variant == "blank":
        cmd = f"bpftool -d prog load {obj} {BPF_PIN_PATH} 2>bpftool_err.txt"
    elif variant == "pure_ebpf":
        # pure_ebpf hardcodes /sys/fs/bpf/xdp_stats_map — clear stale pin
        # first, then load without pinmaps to avoid libbpf conflict
        run(f"rm -rf {BPF_MAP_DIR} && mkdir -p {BPF_MAP_DIR}", check=False)
        run("rm -f /sys/fs/bpf/xdp_stats_map", check=False)
        cmd = f"bpftool -d prog load {obj} {BPF_PIN_PATH} 2>bpftool_err.txt"
    else:
        run(f"rm -rf {BPF_MAP_DIR} && mkdir -p {BPF_MAP_DIR}", check=False)
        cmd = f"bpftool -d prog load {obj} {BPF_PIN_PATH} pinmaps {BPF_MAP_DIR} 2>bpftool_err.txt"

    run(cmd, check=False)
    err_text = Path("bpftool_err.txt").read_text() if Path("bpftool_err.txt").exists() else ""

    if not Path(BPF_PIN_PATH).exists():
        msg = err_text.strip().splitlines()[-1] if err_text.strip() else "unknown error"
        log(f"  {variant}: FAILED — {msg}")
        run(f"rm -rf {BPF_MAP_DIR}", check=False)
        return None, None

    xlated = run(f"bpftool prog dump xlated pinned {BPF_PIN_PATH}", check=False)
    insn_lines = [l for l in xlated.stdout.splitlines() if re.match(r'\s*\d+:', l)]
    bpf_insns = len(insn_lines)

    vsteps_match = re.search(r'processed (\d+) insns', err_text)
    vsteps = int(vsteps_match.group(1)) if vsteps_match else None

    run(f"rm -f {BPF_PIN_PATH}", check=False)
    run(f"rm -rf {BPF_MAP_DIR}", check=False)
    run("rm -f /sys/fs/bpf/xdp_stats_map", check=False)

    return bpf_insns, vsteps

# ---------------------------------------------------------------------------
# Latency histogram
# ---------------------------------------------------------------------------

def read_lat_hist():
    pin = f"{BPF_MAP_DIR}/{LAT_HIST_NAME}"
    if not Path(pin).exists():
        log(f"WARNING: lat_hist map not found at {pin}")
        return [0] * LAT_BUCKETS

    counts = [0] * LAT_BUCKETS
    dump = run(f"bpftool map dump pinned {pin} -j", check=False).stdout
    try:
        entries = json.loads(dump)
        for entry in entries:
            raw_key = entry["key"]
            if isinstance(raw_key, list):
                key = int.from_bytes(bytes(int(b, 16) for b in raw_key), byteorder='little')
            elif isinstance(raw_key, str):
                key = int(raw_key, 16)
            else:
                key = int(raw_key)

            if not (0 <= key < LAT_BUCKETS):
                continue

            for cpu_entry in entry.get("values", []):
                raw_val = cpu_entry["value"]
                if isinstance(raw_val, list):
                    val = int.from_bytes(bytes(int(b, 16) for b in raw_val), byteorder='little')
                elif isinstance(raw_val, str):
                    val = int(raw_val, 16)
                else:
                    val = int(raw_val)
                counts[key] += val

    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
        log(f"WARNING: failed to parse lat_hist: {e}")

    return counts

def hist_percentiles(counts):
    total = sum(counts)
    if total == 0:
        return {"p50": 0, "p99": 0, "p999": 0, "total_packets": 0}

    def percentile(p):
        target = total * p / 100.0
        cumul = 0
        for i, c in enumerate(counts):
            cumul += c
            if cumul >= target:
                return int(2 ** (i - 0.5)) if i > 0 else 0
        return 2 ** (LAT_BUCKETS - 1)

    return {
        "p50":           percentile(50),
        "p99":           percentile(99),
        "p999":          percentile(99.9),
        "total_packets": total,
    }

def clear_lat_hist():
    pin = f"{BPF_MAP_DIR}/{LAT_HIST_NAME}"
    if not Path(pin).exists():
        return
    ncpus = os.cpu_count() or 1
    zero_val = " ".join(["0x00"] * 8)
    per_cpu_zeros = " ".join([zero_val] * ncpus)
    for i in range(LAT_BUCKETS):
        key_bytes = i.to_bytes(4, byteorder='little')
        key_str = " ".join(f"0x{b:02x}" for b in key_bytes)
        run(f"bpftool map update pinned {pin} key {key_str} value {per_cpu_zeros}",
            check=False)

# ---------------------------------------------------------------------------
# NIC queue control
# ---------------------------------------------------------------------------

def set_rx_queues2(iface, n):
    """Restrict RSS to n queues using weight vector. n=0 restores all 48."""
    if n == 0:
        n = 48
    weights = " ".join(["1"] + ["0"] * (48 - 1)) if n == 1 else \
              " ".join(["1"] * n + ["0"] * (48 - n))
    result = run(f"ethtool -X {iface} weight {weights}", check=False)
    if result.returncode != 0:
        log(f"WARNING: failed to set {iface} RSS to {n} queues")
    else:
        log(f"  RX queues: {iface} RSS restricted to {n} queues")

def set_rx_queues(iface, n):
    """Pin RX queue count on DUT NIC. n=0 restores to hardware maximum."""
    if n == 0:
        result = run(f"ethtool -l {iface} 2>/dev/null", check=False)
        in_current = False
        for line in result.stdout.splitlines():
            if "Current hardware settings" in line:
                in_current = True
            if in_current and "Combined:" in line:
                m = re.search(r"Combined:\s*(\d+)", line)
                if m:
                    n = int(m.group(1))
                    break
        if n == 0:
            n = NUM_THREADS  # fallback
    result = run(f"ethtool -X {iface} equal {n}", check=False)
    if result.returncode != 0:
        log(f"WARNING: failed to set {iface} to {n} RX queues")
    else:
        log(f"  RX queues: {iface} set to {n}")

def get_rx_stats2(iface, queue=None):
    """Read RX packet count on mlx5.
    queue=None  -> global rx_packets (all queues)
    queue=N     -> per-queue rx{N}_packets (single-queue mode)
    """
    result = run(f"ethtool -S {iface} 2>/dev/null", check=False)
    if queue is not None:
        pattern = re.compile(rf'\s*rx{queue}_packets\s*:')
    else:
        pattern = re.compile(r'\s*rx_packets\s*:')
    for line in result.stdout.splitlines():
        if pattern.match(line):
            m = re.search(r':\s*(\d+)', line)
            if m:
                return int(m.group(1))
    try:
        return int(Path(f"/sys/class/net/{iface}/statistics/rx_packets").read_text().strip())
    except (ValueError, OSError):
        return 0

def get_rx_stats(iface, queue=None, num_queues=1):
    result = run(f"ethtool -S {iface} 2>/dev/null", check=False)
    lines  = result.stdout.splitlines()
    if queue is None:
        pattern = re.compile(r'\s*rx_packets\s*:')
        for line in lines:
            if pattern.match(line):
                m = re.search(r':\s*(\d+)', line)
                if m:
                    return int(m.group(1))
    else:
        total = 0
        for q in range(num_queues):
            pattern = re.compile(rf'\s*rx{q}_packets\s*:')
            for line in lines:
                if pattern.match(line):
                    m = re.search(r':\s*(\d+)', line)
                    if m:
                        total += int(m.group(1))
                        break
        return total
    try:
        return int(Path(f"/sys/class/net/{iface}/statistics/rx_packets").read_text().strip())
    except (ValueError, OSError):
        return 0

def get_rx_drop_stats(iface):
    result = run(f"ethtool -S {iface} 2>/dev/null", check=False)
    for line in result.stdout.splitlines():
        if 'rx_out_of_buffer' in line:
            m = re.search(r':\s*(\d+)', line)
            if m:
                return int(m.group(1))
    return 0

# ---------------------------------------------------------------------------
# pktgen control
# ---------------------------------------------------------------------------

PKTGEN_SCRIPT = "/tmp/pktgen_multiqueue.sh"

def gen_start(gen_host, gen_iface, dst_ip, dst_mac, pkt_size, duration,
              num_threads=NUM_THREADS):
    """Start pktgen on generator; returns immediately.
    duration=0 means run indefinitely (passes a very large value so the
    pktgen script never self-terminates — caller must call gen_stop()).
    num_threads passed as $5 to the script."""
    ssh(gen_host,
        "echo stop > /proc/net/pktgen/pgctrl 2>/dev/null; sleep 0.3; true",
        check=False)
    if num_threads < 4:
        log(f"WARNING: {num_threads} pktgen thread(s) sends only ~{num_threads*20}K pps "
            f"— too low to distinguish from background traffic. Use >=4 threads.")
    actual_duration = 999999 if duration == 0 else duration
    cmd = (f"nohup setsid bash {PKTGEN_SCRIPT} "
           f"{dst_ip} {dst_mac} {pkt_size} {actual_duration} {num_threads} "
           f"> /tmp/pktgen_mq.log 2>&1 &")
    ssh(gen_host, cmd, check=False)
    dur_str = "infinite" if duration == 0 else f"{duration}s"
    log(f"  pktgen started on {gen_host}:{gen_iface} -> {dst_ip} "
        f"pkt_size={pkt_size} duration={dur_str} ({num_threads} threads)")

def gen_wait(gen_host, duration, timeout=120):
    """Wait for pktgen to finish.
    The script uses nohup setsid so bash exits immediately after launching
    kernel threads — we cannot poll a userspace process. Simply sleep for
    the script duration plus startup margin.
    """
    time.sleep(duration + 1)
    return True

def gen_stop(gen_host):
    """Stop pktgen kernel threads."""
    ssh(gen_host,
        "echo stop > /proc/net/pktgen/pgctrl 2>/dev/null; "
        "pkill -f pktgen_mq_run.sh 2>/dev/null; "
        "pkill -f pktgen_multiqueue.sh 2>/dev/null; true",
        check=False)
    time.sleep(1)

def gen_get_tx_stats(gen_host, gen_iface, num_threads=NUM_THREADS):
    """Read total TX packets from pktgen log summary."""
    r = ssh(gen_host, "grep 'Total packets TX' /tmp/pktgen_mq.log 2>/dev/null",
            check=False)
    m = re.search(r'Total packets TX\s*:\s*(\d+)', r.stdout)
    if m:
        return int(m.group(1))
    # fallback: sum proc files
    r2 = ssh(gen_host,
             f"grep -h 'pkts-sofar' /proc/net/pktgen/{gen_iface}@* 2>/dev/null",
             check=False)
    total = sum(int(x) for x in re.findall(r'pkts-sofar:\s*(\d+)', r2.stdout))
    return total if total > 0 else None

# ---------------------------------------------------------------------------
# Module check
# ---------------------------------------------------------------------------

def check_modules(variant):
    mod = KFUNC_MODULES.get(variant)
    if mod is None:
        return True
    result = run(f"lsmod | grep -q '^{mod}'", check=False)
    if result.returncode != 0:
        log(f"WARNING: {mod} not loaded — {variant} kfunc will not resolve")
        return False
    return True

# ---------------------------------------------------------------------------
# Measurement phases
# ---------------------------------------------------------------------------

def phase_instrcount(args):
    log("=" * 60)
    log("PHASE: Instruction Count")
    log("=" * 60)

    results = {}
    header = f"{'Variant':<24}  {'BPF insns':>10}  {'Verifier steps':>15}"
    log(header)
    log("-" * len(header))

    for variant in VARIANTS:
        if variant in KFUNC_VARIANTS:
            check_modules(variant)
        insns, vsteps = get_instrcount(variant)
        vsteps_str = str(vsteps) if vsteps is not None else "-"
        insns_str  = str(insns)  if insns  is not None else "FAILED"
        log(f"  {variant:<22}  {insns_str:>10}  {vsteps_str:>15}")
        results[variant] = {"bpf_insns": insns, "verifier_steps": vsteps}

    return results

def phase_latency(args, variant):
    """Measure latency histogram for one variant.
    Assumes pktgen is already running at line rate — does NOT start/stop it.
    """
    log(f"  Latency run: {variant}")

    if not load_variant(variant):
        return None
    if not attach_variant(args.iface):
        detach_unload(args.iface)
        return None

    num_rx_q = getattr(args, 'num_rx_queues', 0)
    if num_rx_q > 0:
        set_rx_queues(args.iface, num_rx_q)
        time.sleep(0.3)

    clear_lat_hist()
    time.sleep(args.duration)

    if variant == "blank":
        result = {"p50": 0, "p99": 0, "p999": 0, "total_packets": None,
                  "note": "no histogram — blank variant has zero instrumentation"}
    else:
        counts = read_lat_hist()
        result = hist_percentiles(counts)
        result["histogram"] = counts

    if num_rx_q > 0:
        set_rx_queues(args.iface, 0)
    detach_unload(args.iface)

    log(f"    p50={result.get('p50')}ns  p99={result.get('p99')}ns  "
        f"p99.9={result.get('p999')}ns  pkts={result.get('total_packets')}")
    return result

def phase_latency2(args, variant):
    log(f"  Latency run: {variant}")

    if not load_variant(variant):
        return None
    if not attach_variant(args.iface):
        detach_unload(args.iface)
        return None

    time.sleep(0.5)

    num_threads = getattr(args, 'num_threads', NUM_THREADS)
    num_rx_q    = getattr(args, 'num_rx_queues', 0)
    if num_rx_q > 0:
        set_rx_queues(args.iface, num_rx_q)
        time.sleep(0.5)

    if variant != "blank":
        clear_lat_hist()

    gen_start(args.gen_host, args.gen_iface,
              args.dst_ip, args.dst_mac,
              pkt_size=args.pkt_size, duration=args.duration,
              num_threads=num_threads)

    log(f"    Waiting {args.duration}s...")
    gen_wait(args.gen_host, args.duration, timeout=args.duration + 60)
    time.sleep(0.5)

    #if variant == "blank":
    #    result = {"p50": None, "p99": None, "p999": None, "total_packets": None,
    #              "note": "no histogram — blank variant has zero instrumentation"}
    #else:
    counts = read_lat_hist()
    result = hist_percentiles(counts)
    result["histogram"] = counts

    tx_pkts = gen_get_tx_stats(args.gen_host, args.gen_iface,
                               num_threads=num_threads)
    result["tx_packets"] = tx_pkts

    if num_rx_q > 0:
        set_rx_queues(args.iface, 0)
    detach_unload(args.iface)

    log(f"    p50={result.get('p50')}ns  p99={result.get('p99')}ns  "
        f"p99.9={result.get('p999')}ns  pkts={result.get('total_packets')}")
    return result



def get_rx_packets_global(iface):
    """Read the global rx_packets counter from ethtool -S.
    Equivalent to: ethtool -S <iface> | awk '/^[[:space:]]*rx_packets:/ {print $2}'
    Falls back to /sys/class/net if ethtool doesn't have it.
    """
    result = run(f"ethtool -S {iface} 2>/dev/null", check=False)
    for line in result.stdout.splitlines():
        if re.match(r'\s*rx_packets\s*:', line):
            m = re.search(r':\s*(\d+)', line)
            if m:
                return int(m.group(1))
    try:
        return int(Path(f"/sys/class/net/{iface}/statistics/rx_packets").read_text().strip())
    except (ValueError, OSError):
        return 0


def wait_for_line_rate(iface, poll_interval=0.5, stable_window=3, tolerance=0.05, timeout=30):
    """Poll rx_packets until the instantaneous rate has been stable for
    `stable_window` consecutive samples within `tolerance` (5%) of each other.
    Returns the rx_packets value at the moment stability is confirmed, and the
    wall-clock time of that snapshot — ready to use as the measurement baseline.

    This replaces a fixed ramp-up sleep: instead of guessing how long pktgen
    takes to reach line rate, we detect it directly from the counter.
    """
    log(f"    Waiting for line rate (stable={stable_window}x{poll_interval}s "
        f"within {tolerance*100:.0f}%, timeout={timeout}s)...")

    prev      = get_rx_packets_global(iface)
    prev_time = time.time()
    stable_count = 0
    ref_rate     = None
    deadline     = prev_time + timeout

    while time.time() < deadline:
        time.sleep(poll_interval)
        now      = get_rx_packets_global(iface)
        now_time = time.time()
        dt       = now_time - prev_time
        rate     = (now - prev) / dt / 1e6   # Mpps

        if ref_rate is None or abs(rate - ref_rate) / max(ref_rate, 1e-9) > tolerance:
            # Rate changed more than tolerance — reset stability counter
            ref_rate     = rate
            stable_count = 1
        else:
            stable_count += 1

        log(f"      {rate:.3f} Mpps  (stable {stable_count}/{stable_window})")

        if stable_count >= stable_window:
            log(f"    Line rate confirmed at {rate:.3f} Mpps after "
                f"{now_time - (deadline - timeout):.1f}s")
            return now, now_time

        prev      = now
        prev_time = now_time

    log(f"    WARNING: line rate did not stabilize within {timeout}s — "
        f"using last sample as baseline anyway")
    now = get_rx_packets_global(iface)
    return now, time.time()


def phase_throughput(args, variant):
    """Measure throughput for one variant.
    Assumes pktgen is already running at line rate on the generator.
    Does NOT start or stop pktgen — caller owns that lifecycle.
    """
    log(f"  Throughput run: {variant}")

    if not load_variant(variant):
        return None
    if not attach_variant(args.iface):
        detach_unload(args.iface)
        return None

    num_rx_q = getattr(args, 'num_rx_queues', 0)
    if num_rx_q > 0:
        set_rx_queues(args.iface, num_rx_q)
        time.sleep(0.5)   # let RSS indirection table settle

    # Snapshot before: per-queue SW counters for active queues only
    drop_before = get_rx_drop_stats(args.iface)
    #sw_before   = get_rx_packets_global(args.iface)
    sw_before   = get_rx_stats(args.iface, queue=0, num_queues=num_rx_q)
    t_before    = time.time()

    time.sleep(args.duration)

    # Snapshot after
    #sw_after   = get_rx_packets_global(args.iface)
    sw_after   = get_rx_stats(args.iface, queue=0, num_queues=num_rx_q)
    drop_after = get_rx_drop_stats(args.iface)
    t_after    = time.time()

    rx_pkts  = sw_after  - sw_before   # SW packets that passed through XDP
    hw_drops = drop_after - drop_before # ring-exhaustion drops (pre-XDP)
    elapsed  = t_after - t_before
    mpps     = rx_pkts / elapsed / 1e6
    gbps     = rx_pkts * args.pkt_size * 8 / elapsed / 1e9

    # drop_rate = fraction of NIC-received packets lost to ring exhaustion
    # denominator = SW passed + HW dropped = total arriving at active queues
    total = rx_pkts + hw_drops
    drop_rate = hw_drops / total if total > 0 else 0.0

    if hw_drops > 0:
        log(f"    Dropped {hw_drops} packets (ring exhaustion)")

    result = {
        "mpps":      round(mpps, 3),
        "gbps":      round(gbps, 3),
        "rx_pkts":   rx_pkts,
        "hw_drops":  hw_drops,
        "elapsed_s": round(elapsed, 3),
        "drop_rate": round(drop_rate, 4),
    }

    detach_unload(args.iface)

    log(f"    {mpps:.3f} Mpps  {gbps:.2f} Gbps   drop={drop_rate:.2%}")
    return result

PKTGEN_RAMP_S = 11   # seconds to wait after gen_start before traffic is stable

def phase_all(args):
    results = {
        "meta": {
            "dut_iface":    args.iface,
            "gen_host":     args.gen_host,
            "gen_iface":    args.gen_iface,
            "dst_ip":       args.dst_ip,
            "dst_mac":      args.dst_mac,
            "duration_s":   args.duration,
            "pkt_size":     args.pkt_size,
            "num_threads":  getattr(args, 'num_threads', NUM_THREADS),
            "num_rx_queues":getattr(args, 'num_rx_queues', 0),
            "timestamp":    time.strftime("%Y-%m-%dT%H:%M:%S"),
        },
        "instrcount": {},
        "latency":    {},
        "throughput": {},
    }

    results["instrcount"] = phase_instrcount(args)

    log("")
    log("=" * 60)
    log("PHASE: Latency + Throughput (per variant)")
    log("=" * 60)

    # Start pktgen once for the entire throughput sweep.
    # duration=0 means run indefinitely; we call gen_stop() when done.
    num_threads = getattr(args, 'num_threads', NUM_THREADS)
    gen_start(args.gen_host, args.gen_iface,
              args.dst_ip, args.dst_mac,
              pkt_size=args.pkt_size, duration=0,
              num_threads=num_threads)
    log(f"  Waiting {PKTGEN_RAMP_S}s for pktgen to reach line rate...")
    time.sleep(PKTGEN_RAMP_S)
    log("  Traffic is up. Starting variant sweep.")

    try:
        for variant in VARIANTS:
            log(f"\n--- {variant} ---")
            if variant in KFUNC_VARIANTS:
                check_modules(variant)

            lat = phase_latency(args, variant)
            if lat:
                results["latency"][variant] = lat

            tput = phase_throughput(args, variant)
            if tput:
                results["throughput"][variant] = tput

            save_results(results, args.output)
            log(f"  Results saved to {args.output}")
    finally:
        log("  Stopping pktgen...")
        gen_stop(args.gen_host)

    return results

def save_results(results, path):
    with open(path, "w") as f:
        json.dump(results, f, indent=2)

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Hash kfunc benchmark tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("command",
        choices=["instrcount", "latency", "throughput", "all"])
    parser.add_argument("--iface",
        help="XDP interface on DUT (this machine)")
    parser.add_argument("--gen-host",
        default="root@srv6.sb9.orbit-lab.org",
        help="SSH host for traffic generator")
    parser.add_argument("--gen-iface",
        help="Interface on generator machine")
    parser.add_argument("--dst-ip",
        help="Destination IP on DUT")
    parser.add_argument("--dst-mac",
        help="Destination MAC on DUT")
    parser.add_argument("--pkt-size", type=int, default=64,
        dest="pkt_size",
        help="Packet size in bytes (default: 64)")
    parser.add_argument("--duration", type=int, default=10,
        help="Traffic duration per run in seconds (default: 10)")
    parser.add_argument("--num-threads", type=int, default=NUM_THREADS,
        dest="num_threads",
        help=f"pktgen threads on generator (default: {NUM_THREADS})")
    parser.add_argument("--num-rx-queues", type=int, default=0,
        dest="num_rx_queues",
        help="Pin DUT NIC to N RX queues (0=all, 1=single-queue saturation)")
    parser.add_argument("--output", default="bench_results.json",
        help="Output JSON file (default: bench_results.json)")
    parser.add_argument("--variant",
        help="Run a single variant only")

    args = parser.parse_args()

    if args.command in ("latency", "throughput", "all"):
        for req in ("iface", "gen_iface", "dst_ip", "dst_mac"):
            if not getattr(args, req):
                parser.error(f"--{req.replace('_','-')} required for {args.command}")

    results = {}

    if args.command == "instrcount":
        results["instrcount"] = phase_instrcount(args)
        save_results(results, args.output)
        log(f"\nResults written to {args.output}")

    elif args.command == "latency":
        variants = [args.variant] if args.variant else VARIANTS
        results["latency"] = {}
        num_threads = getattr(args, 'num_threads', NUM_THREADS)
        gen_start(args.gen_host, args.gen_iface,
                  args.dst_ip, args.dst_mac,
                  pkt_size=args.pkt_size, duration=0,
                  num_threads=num_threads)
        log(f"  Waiting {PKTGEN_RAMP_S}s for pktgen to reach line rate...")
        time.sleep(PKTGEN_RAMP_S)
        log("  Traffic is up. Starting variant sweep.")
        try:
            for v in variants:
                r = phase_latency(args, v)
                if r:
                    results["latency"][v] = r
        finally:
            log("  Stopping pktgen...")
            gen_stop(args.gen_host)
        save_results(results, args.output)
        log(f"\nResults written to {args.output}")

    elif args.command == "throughput":
        variants = [args.variant] if args.variant else VARIANTS
        results["throughput"] = {}
        num_threads = getattr(args, 'num_threads', NUM_THREADS)
        gen_start(args.gen_host, args.gen_iface,
                  args.dst_ip, args.dst_mac,
                  pkt_size=args.pkt_size, duration=0,
                  num_threads=num_threads)
        log(f"  Waiting {PKTGEN_RAMP_S}s for pktgen to reach line rate...")
        time.sleep(PKTGEN_RAMP_S)
        log("  Traffic is up. Starting variant sweep.")
        try:
            for v in variants:
                r = phase_throughput(args, v)
                if r:
                    results["throughput"][v] = r
        finally:
            log("  Stopping pktgen...")
            gen_stop(args.gen_host)
        save_results(results, args.output)
        log(f"\nResults written to {args.output}")

    elif args.command == "all":
        results = phase_all(args)
        save_results(results, args.output)
        log(f"\nAll results written to {args.output}")

if __name__ == "__main__":
    main()
