#!/usr/bin/env python3
"""
DDoS Throughput Monitor
Runs iperf3 tests at a specified attack traffic rate and records throughput.
Results are appended to a shared JSON file, keyed by attack rate, so the
plotting script can sweep across all recorded rates in one figure.

Usage:
  # Record throughput under 10 Gbps attack traffic
  python3 ddos_monitor.py -s 192.168.100.1 -a 10 -n 20 -t 5 -o ddos_results.json

  # Sweep 10..100 Gbps in a shell loop
  for rate in $(seq 10 10 100); do
      python3 ddos_monitor.py -s 192.168.100.1 -a $rate -n 20 -t 5 -o ddos_results.json
  done
"""

import subprocess
import json
import argparse
import time
import os
from datetime import datetime
from typing import Optional, Dict, List


# ---------------------------------------------------------------------------
# Helper: run one iperf3 UDP test and return structured result
# ---------------------------------------------------------------------------

class Iperf3Monitor:
    def __init__(self, server_ip: str, port: int, msg_size: int, iterations: int,
                 duration: int, sender_bandwidth: str, attack_rate_gbps: float,
                 output_file: str):
        self.server_ip       = server_ip
        self.port            = port
        self.msg_size        = msg_size
        self.iterations      = iterations
        self.duration        = duration
        self.sender_bandwidth = sender_bandwidth   # "0" = max, "N" = N Gbps
        self.attack_rate_gbps = attack_rate_gbps
        self.output_file     = output_file
        self.bandwidth_samples: List[Dict] = []

    # ------------------------------------------------------------------
    def run_single_test(self, iteration: int) -> Optional[Dict]:
        """Run one iperf3 UDP test and parse the JSON output."""

        bw_arg = "0" if self.sender_bandwidth == "0" else f"{self.sender_bandwidth}G"

        cmd = [
            'iperf3',
            '-c', self.server_ip,
            '-p', str(self.port),
            '-u',
            '-b', bw_arg,
            '-l', str(self.msg_size),
            '-t', str(self.duration),
            '-J',
        ]

        print(f"  [{iteration:>3}/{self.iterations}] Running iperf3 ...", end=' ', flush=True)

        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=self.duration + 30,
            )

            if result.returncode != 0:
                print(f"FAILED (exit {result.returncode}): {result.stderr.strip()}")
                return None

            data = json.loads(result.stdout)
            end_stats = data.get('end', {})

            sum_sent     = end_stats.get('sum', {})
            sum_received = end_stats.get('sum_received', {})

            sender_bw_mbps   = sum_sent.get('bits_per_second', 0) / 1_000_000
            receiver_bw_mbps = sum_received.get('bits_per_second', 0) / 1_000_000

            packets_sent     = sum_sent.get('packets', 0)
            packets_received = sum_received.get('packets', 0)
            packets_lost     = sum_received.get('lost_packets', 0)
            loss_percent     = sum_received.get('lost_percent', 0)
            jitter_ms        = sum_received.get('jitter_ms', 0)

            print(f"Sender: {sender_bw_mbps:>9.2f} Mbps  "
                  f"Receiver: {receiver_bw_mbps:>9.2f} Mbps  "
                  f"Loss: {loss_percent:.1f}%")

            return {
                'sample':                  iteration,
                'timestamp':               time.time(),
                'sender_bandwidth_mbps':   round(sender_bw_mbps,   2),
                'sender_bandwidth_gbps':   round(sender_bw_mbps / 1000, 4),
                'receiver_bandwidth_mbps': round(receiver_bw_mbps,  2),
                'receiver_bandwidth_gbps': round(receiver_bw_mbps / 1000, 4),
                'packets_sent':            packets_sent,
                'packets_received':        packets_received,
                'packets_lost':            packets_lost,
                'loss_percent':            round(loss_percent, 2),
                'jitter_ms':               round(jitter_ms,    3),
            }

        except subprocess.TimeoutExpired:
            print("TIMEOUT")
            return None
        except json.JSONDecodeError as e:
            print(f"JSON parse error: {e}")
            return None
        except Exception as e:
            print(f"Error: {e}")
            return None

    # ------------------------------------------------------------------
    def run_tests(self) -> bool:
        """Run all iterations and collect samples."""

        print("=" * 70)
        print("DDoS Throughput Monitor")
        print("=" * 70)
        print(f"  Server         : {self.server_ip}:{self.port}")
        print(f"  Packet size    : {self.msg_size} bytes")
        print(f"  Duration/iter  : {self.duration} s")
        print(f"  Iterations     : {self.iterations}")
        print(f"  Sender BW limit: {'Max' if self.sender_bandwidth == '0' else self.sender_bandwidth + ' Gbps'}")
        print(f"  Attack rate    : {self.attack_rate_gbps} Gbps")
        print("-" * 70)

        t0 = time.time()

        for i in range(1, self.iterations + 1):
            sample = self.run_single_test(i)
            if sample:
                self.bandwidth_samples.append(sample)
            else:
                print(f"  Warning: iteration {i} failed, skipping")
            if i < self.iterations:
                time.sleep(0.5)

        elapsed = time.time() - t0
        print("-" * 70)
        print(f"Completed {len(self.bandwidth_samples)}/{self.iterations} "
              f"iterations in {elapsed:.1f} s")

        return len(self.bandwidth_samples) > 0

    # ------------------------------------------------------------------
    def _statistics(self) -> Dict:
        if not self.bandwidth_samples:
            return {}

        def stats(values):
            avg = sum(values) / len(values)
            std = (sum((x - avg) ** 2 for x in values) / len(values)) ** 0.5
            return {
                'avg_mbps': round(avg,      2),
                'max_mbps': round(max(values), 2),
                'min_mbps': round(min(values), 2),
                'std_dev':  round(std,      2),
            }

        sender_bw   = [s['sender_bandwidth_mbps']   for s in self.bandwidth_samples]
        receiver_bw = [s['receiver_bandwidth_mbps']  for s in self.bandwidth_samples]
        loss_pcts   = [s['loss_percent']             for s in self.bandwidth_samples]

        return {
            'sender':   stats(sender_bw),
            'receiver': stats(receiver_bw),
            'packets': {
                'total_sent':     sum(s['packets_sent']     for s in self.bandwidth_samples),
                'total_received': sum(s['packets_received'] for s in self.bandwidth_samples),
                'total_lost':     sum(s['packets_lost']     for s in self.bandwidth_samples),
                'avg_loss_percent': round(sum(loss_pcts) / len(loss_pcts), 2),
            },
            'sample_count': len(self.bandwidth_samples),
        }

    # ------------------------------------------------------------------
    def save_results(self):
        """Append this run's results to the shared JSON file."""

        if not self.bandwidth_samples:
            print("No data to save.")
            return

        stats = self._statistics()

        new_entry = {
            'test_info': {
                'server_ip':        self.server_ip,
                'port':             self.port,
                'msg_size':         self.msg_size,
                'duration':         self.duration,
                'iterations':       self.iterations,
                'sender_bandwidth': (f"{self.sender_bandwidth}G"
                                     if self.sender_bandwidth != "0" else "maximum"),
                'attack_rate_gbps': self.attack_rate_gbps,
                'timestamp':        datetime.now().isoformat(),
                'test_type':        'ddos_throughput',
            },
            'bandwidth_samples': self.bandwidth_samples,
            'statistics':        stats,
        }

        # Load existing entries
        existing: List[Dict] = []
        if os.path.exists(self.output_file):
            try:
                with open(self.output_file, 'r') as f:
                    content = f.read().strip()
                if content:
                    parsed = json.loads(content)
                    existing = parsed if isinstance(parsed, list) else [parsed]
            except Exception as e:
                print(f"Warning: could not read existing file ({e}); starting fresh.")

        existing.append(new_entry)

        with open(self.output_file, 'w') as f:
            json.dump(existing, f, indent=2)

        print("\n" + "=" * 70)
        print(f"Results saved → {self.output_file}  ({len(existing)} total entries)")
        print(f"\nStatistics for attack rate {self.attack_rate_gbps} Gbps:")
        print(f"  Sender   avg: {stats['sender']['avg_mbps']:.2f} Mbps  "
              f"[{stats['sender']['min_mbps']:.2f} – {stats['sender']['max_mbps']:.2f}]")
        print(f"  Receiver avg: {stats['receiver']['avg_mbps']:.2f} Mbps  "
              f"[{stats['receiver']['min_mbps']:.2f} – {stats['receiver']['max_mbps']:.2f}]")
        print(f"  Packet loss : {stats['packets']['avg_loss_percent']:.2f}%")
        print("=" * 70)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='DDoS throughput monitor — records iperf3 UDP throughput under a given attack rate',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single attack rate
  python3 ddos_monitor.py -s 192.168.100.1 -a 10 -n 20 -t 5 -o ddos_results.json

  # Sweep 10 to 100 Gbps (shell loop)
  for rate in $(seq 10 10 100); do
      python3 ddos_monitor.py -s 192.168.100.1 -a $rate -n 20 -t 5 -o ddos_results.json
  done

  # Then plot
  python3 plot_ddos.py ddos_results.json -o ddos_plot.png
        """
    )

    parser.add_argument('-s', '--server',     required=True,
                        help='iperf3 server IP')
    parser.add_argument('-p', '--port',       type=int, default=5201,
                        help='Server port (default: 5201)')
    parser.add_argument('-m', '--msg-size',   type=int, default=8192,
                        help='UDP payload size in bytes (default: 8192)')
    parser.add_argument('-n', '--iterations', type=int, default=20,
                        help='Number of iperf3 runs (default: 20)')
    parser.add_argument('-t', '--time',       type=int, default=5,
                        help='Duration of each run in seconds (default: 5)')
    parser.add_argument('-b', '--bandwidth',  default="0",
                        help='Legitimate sender bandwidth limit in Gbps; 0 = max (default: 0)')
    parser.add_argument('-a', '--attack-rate', type=float, required=True,
                        help='Attack traffic rate in Gbps (e.g. 10, 50, 100)')
    parser.add_argument('-o', '--output',     default='ddos_results.json',
                        help='Output JSON file (results are appended, default: ddos_results.json)')

    args = parser.parse_args()

    try:
        bw_val = float(args.bandwidth)
        if bw_val < 0:
            parser.error("--bandwidth must be >= 0")
    except ValueError:
        parser.error("--bandwidth must be a number")

    if args.attack_rate < 0:
        parser.error("--attack-rate must be >= 0")

    monitor = Iperf3Monitor(
        server_ip=args.server,
        port=args.port,
        msg_size=args.msg_size,
        iterations=args.iterations,
        duration=args.time,
        sender_bandwidth=args.bandwidth,
        attack_rate_gbps=args.attack_rate,
        output_file=args.output,
    )

    if monitor.run_tests():
        monitor.save_results()
    else:
        print("\nAll iterations failed. Check:")
        print(f"  1. iperf3 server is running:  iperf3 -s -p {args.port}")
        print(f"  2. {args.server} is reachable")
        print("  3. Firewall allows traffic on the port")


if __name__ == '__main__':
    main()
