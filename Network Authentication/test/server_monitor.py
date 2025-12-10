#!/usr/bin/env python3
import json
import argparse
import re
import os
import subprocess
from datetime import datetime
import socket


def parse_tcpdump_log(log_file):
    with open(log_file, "r") as f:
        text = f.read()

    def find(pattern):
        m = re.search(pattern, text)
        return int(m.group(1)) if m else None

    return {
        "packets_captured": find(r"(\d+)\s+packets captured"),
        "packets_received_by_filter": find(r"(\d+)\s+packets received by filter"),
        "packets_dropped_kernel": find(r"(\d+)\s+packets dropped by kernel"),
        "packets_dropped_interface": find(r"(\d+)\s+packets dropped by interface"),
    }


def start_tcpdump(interface, port, pcap, log):
    cmd = ["tcpdump", "-i", interface, "udp", "port", str(port), "-w", pcap]
    out = open(log, "w")
    proc = subprocess.Popen(cmd, stdout=out, stderr=subprocess.STDOUT)
    return proc.pid, out


def stop_tcpdump(pid, outfile):
    os.kill(pid, 2)  # SIGINT
    os.waitpid(pid, 0)
    outfile.flush()
    outfile.close()


def main():
    parser = argparse.ArgumentParser(description="Server UDP throughput logger with sync messaging.")
    parser.add_argument("-i", "--interface", required=True)
    parser.add_argument("-p", "--port", type=int, default=11111)
    parser.add_argument("-m", "--packet-size", type=int, required=True)
    parser.add_argument("--control-port", type=int, default=54321)
    parser.add_argument("-o", "--output", default="server_results.json")
    parser.add_argument("--prefix", default="server_capture")
    parser.add_argument("-n", "--iterations", type=int, required=True)
    parser.add_argument("-t", "--duration", type=int, required=True)
    args = parser.parse_args()

    # ---- Control socket ----
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", args.control_port))
    print(f"Listening for sync messages on UDP port {args.control_port}")

    # ---- NEW: Final data structure ----
    results = {
        "test_info": {
            "packet_size": args.packet_size,
            "duration": args.duration,
            "timestamp": datetime.now().isoformat()
        },
        "server_throughput": []
    }

    # ---- Per iteration ----
    for iteration in range(1, args.iterations + 1):

        pcap = "/dev/null" #os.path.join("/tmp", f"{args.prefix}_pkt{args.packet_size}_iter{iteration}.pcap")
        log = os.path.join("/tmp", f"{args.prefix}_pkt{args.packet_size}_iter{iteration}.log")

        print(f"\n=== ITERATION {iteration} START ===")

        if os.path.exists(log):
            os.remove(log)

        # Start tcpdump
        pid, out = start_tcpdump(args.interface, args.port, pcap, log)
        print(f"tcpdump started PID={pid} → {pcap}")

        print("Waiting for client sync message...")

        # Wait for sync
        while True:
            msg, addr = sock.recvfrom(1024)
            msg = msg.decode(errors="ignore").strip()
            if msg == "ITER_DONE":
                print(f"Received sync from {addr}")
                break

        # Stop tcpdump
        print("Stopping tcpdump...")
        stop_tcpdump(pid, out)

        # Parse stats
        stats = parse_tcpdump_log(log)
        packets = stats["packets_received_by_filter"]

        if packets is None:
            raise RuntimeError(f"Missing tcpdump summary in {log}")

        throughput_mbps = (packets * args.packet_size * 8) / args.duration / 1024 / 1024

        # Build iteration entry
        iter_entry = {
            "iteration": iteration,
            **stats,
            "throughput_mbps": round(throughput_mbps, 3),
            "throughput_gbps": round(throughput_mbps / 1024, 3)
        }

        results["server_throughput"].append(iter_entry)

        print(f"Iteration {iteration} throughput = {throughput_mbps:.3f} Mbps")
        print("=== ITERATION COMPLETE ===")

    # ---- Write final JSON ----
    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)

    print("\nAll iterations complete.")
    print(f"Saved results → {args.output}")


if __name__ == "__main__":
    main()

