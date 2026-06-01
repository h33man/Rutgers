#!/usr/bin/env python3
"""
iperf3/Sockperf-based UDP Benchmark Tool

Uses iperf3 for bandwidth (throughput) measurements and sockperf for RTT.
Compatible with the same JSON output format as the C version.

Requirements:
  - iperf3 installed: sudo apt-get install iperf3
  - sockperf installed: sudo apt-get install sockperf
  - iperf3 server running: iperf3 -s
  - sockperf server running: sockperf server -p 11111

Usage:
    python3 auth_benchmark.py -d 192.168.100.1 -p 8192 -a no_auth
    python3 auth_benchmark.py -d 192.168.100.1 -p 1024 -m rtt -a ebpf_auth
    python3 auth_benchmark.py -d 192.168.100.1 -p 8192 -a art_delay 100
"""

import subprocess
import json
import time
import argparse
import re
import sys
import os
import statistics
from datetime import datetime

class HybridBenchmark:
    def __init__(self, dst_ip, packet_size, duration=10, interface="eth0"):
        self.dst_ip = dst_ip
        self.packet_size = packet_size
        self.duration = duration
        self.interface = interface
        self.iperf_port = 5201
        self.sockperf_port = 11111
        
        # Check if required tools are available
        if not self.check_iperf3():
            print("Error: iperf3 not found. Install with: sudo apt-get install iperf3")
            sys.exit(1)
        if not self.check_sockperf():
            print("Error: sockperf not found. Install with: sudo apt-get install sockperf")
            sys.exit(1)
    
    def check_iperf3(self):
        """Check if iperf3 is installed"""
        try:
            subprocess.run(["iperf3", "--version"], 
                          capture_output=True, timeout=5)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def check_sockperf(self):
        """Check if sockperf is installed"""
        try:
            subprocess.run(["sockperf", "--version"], 
                          capture_output=True, timeout=15)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def run_bandwidth_test(self):
        """
        Run bandwidth test using iperf3 with multiple runs for std dev
        Measures both sender and receiver bandwidth
        
        Returns:
            dict: {bandwidth_mbps, bandwidth_std, receiver_bandwidth_mbps, 
                   receiver_bandwidth_std, packets_sent, packets_received, 
                   packet_loss_percent, duration}
        """
        print(f"\nRunning bandwidth test (iperf3)...")
        print(f"  Duration: {self.duration} seconds per run")
        print(f"  Packet size: {self.packet_size} bytes")
        print(f"  Running 32 iterations for std dev...")
        
        sender_bandwidths = []
        receiver_bandwidths = []
        total_packets_sent = 0
        total_packets_received = 0
        loss_percentages = []
        
        # Run 3 iterations for standard deviation
        for run in range(32):
            cmd = [
                "iperf3", "-c", self.dst_ip,
                "-p", str(self.iperf_port),
                "-u",  # UDP mode
                "-t", str(self.duration),
                "-l", str(self.packet_size),
                "-b", "0",  # unlimited bandwidth
                "-J"  # JSON output
            ]
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True,
                                       timeout=self.duration + 10)
                
                if result.returncode == 0:
                    data = json.loads(result.stdout)
                    
                    # Extract sender and receiver statistics
                    end_stats = data.get('end', {})
                    sum_sent = end_stats.get('sum', {})
                    sum_received = end_stats.get('sum_received', {})
                    
                    # Sender bandwidth
                    sender_bw_bps = sum_sent.get('bits_per_second', 0)
                    sender_bw_mbps = sender_bw_bps / 1_000_000
                    sender_bandwidths.append(sender_bw_mbps)
                    
                    # Receiver bandwidth
                    receiver_bw_bps = sum_received.get('bits_per_second', 0)
                    receiver_bw_mbps = receiver_bw_bps / 1_000_000
                    receiver_bandwidths.append(receiver_bw_mbps)
                    
                    # Packet statistics
                    packets_sent = sum_sent.get('packets', 0)
                    packets_received = sum_received.get('packets', 0)
                    loss_percent = sum_received.get('lost_percent', 0)
                    
                    total_packets_sent += packets_sent
                    total_packets_received += packets_received
                    loss_percentages.append(loss_percent)
                    
                    print(f"    Run {run+1}: Sender {sender_bw_mbps:.2f} Mbps, " +
                          f"Receiver {receiver_bw_mbps:.2f} Mbps, Loss {loss_percent:.2f}%")
                
                time.sleep(1)  # Brief pause between runs
                
            except subprocess.TimeoutExpired:
                print(f"  ✗ Run {run+1} timed out")
            except json.JSONDecodeError:
                print(f"  ✗ Run {run+1} failed to parse JSON")
            except Exception as e:
                print(f"  ✗ Run {run+1} error: {e}")
        
        if sender_bandwidths and receiver_bandwidths:
            avg_sender_bw = statistics.mean(sender_bandwidths)
            std_sender_bw = statistics.stdev(sender_bandwidths) if len(sender_bandwidths) > 1 else 0.0
            
            avg_receiver_bw = statistics.mean(receiver_bandwidths)
            std_receiver_bw = statistics.stdev(receiver_bandwidths) if len(receiver_bandwidths) > 1 else 0.0
            
            avg_loss = statistics.mean(loss_percentages) if loss_percentages else 0.0
            
            print(f"  ✓ Sender BW: {avg_sender_bw:.2f} ± {std_sender_bw:.2f} Mbps")
            print(f"  ✓ Receiver BW: {avg_receiver_bw:.2f} ± {std_receiver_bw:.2f} Mbps")
            print(f"  ✓ Packets: {total_packets_sent} sent, {total_packets_received} received")
            print(f"  ✓ Avg Loss: {avg_loss:.2f}%")
            
            return {
                'bandwidth_mbps': avg_sender_bw,
                'bandwidth_std': std_sender_bw,
                'receiver_bandwidth_mbps': avg_receiver_bw,
                'receiver_bandwidth_std': std_receiver_bw,
                'packets_sent': total_packets_sent,
                'packets_received': total_packets_received,
                'packet_loss_percent': avg_loss,
                'duration': self.duration * 3  # Total duration across 3 runs
            }
        else:
            print(f"  ✗ Failed to measure bandwidth")
            return {
                'bandwidth_mbps': 0.0,
                'bandwidth_std': 0.0,
                'receiver_bandwidth_mbps': 0.0,
                'receiver_bandwidth_std': 0.0,
                'packets_sent': 0,
                'packets_received': 0,
                'packet_loss_percent': 0.0,
                'duration': 0.0
            }
    
    def run_rtt_test(self, num_samples=100):
        """
        Run RTT test using sockperf ping-pong mode
        
        Returns:
            dict: {avg_rtt, std_rtt, min_rtt, max_rtt, successful, total}
        """
        print(f"\nRunning RTT test (sockperf)...")
        print(f"  Samples: {num_samples}")
        print(f"  Packet size: {self.packet_size} bytes")
        
        # sockperf uses message size (payload without headers)
        msg_size = max(self.packet_size - 28, 14)
        
        # Run sockperf in ping-pong mode
        cmd = [
            "sockperf", "ping-pong",
            "-i", self.dst_ip,
            "-p", str(self.sockperf_port),
            "-t", str(int(num_samples / 10)),  # Duration in seconds (approx)
            "--msg-size", str(msg_size),
            "--pps", "10",  # 10 packets per second for RTT measurement
            "--full-rtt"  # Enable full RTT statistics
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                   timeout=60)
            
            # Parse output
            rtt_stats = self._parse_rtt_output(result.stdout)
            
            if rtt_stats['avg_rtt'] > 0:
                print(f"  ✓ RTT: {rtt_stats['avg_rtt']:.3f} ± {rtt_stats['std_rtt']:.3f} µs")
                print(f"  ✓ Range: {rtt_stats['min_rtt']:.3f} - {rtt_stats['max_rtt']:.3f} µs")
                print(f"  ✓ Success: {rtt_stats['successful']}/{rtt_stats['total']}")
            else:
                print(f"  ✗ Failed to measure RTT")
            
            return rtt_stats
            
        except subprocess.TimeoutExpired:
            print(f"  ✗ Test timed out")
            return {
                'avg_rtt': 0.0,
                'std_rtt': 0.0,
                'min_rtt': 0.0,
                'max_rtt': 0.0,
                'successful': 0,
                'total': 0
            }
        except Exception as e:
            print(f"  ✗ Error: {e}")
            return {
                'avg_rtt': 0.0,
                'std_rtt': 0.0,
                'min_rtt': 0.0,
                'max_rtt': 0.0,
                'successful': 0,
                'total': 0
            }
    
    def _parse_rtt_output(self, output):
        """Parse sockperf ping-pong output for RTT statistics"""
        avg_rtt = 0.0
        std_rtt = 0.0
        min_rtt = 0.0
        max_rtt = 0.0
        successful = 0
        
        for line in output.split('\n'):
            # Example: "====> avg-rtt=84.624 (std-dev=5.430)"
            # Values are in microseconds
            if 'avg-rtt' in line:
                avg_match = re.search(r'avg-rtt=([\d.]+)\s+\(std-dev=([\d.]+)\)', line)
                if avg_match:
                    avg_rtt = float(avg_match.group(1))  # Keep in microseconds
                    std_rtt = float(avg_match.group(2))
            
            # Example: "---> <MIN> observation =  79.027"
            if '<MIN>' in line:
                min_match = re.search(r'observation\s*=\s*([\d.]+)', line)
                if min_match:
                    min_rtt = float(min_match.group(1))
            
            # Example: "---> <MAX> observation =  136.619"
            if '<MAX>' in line:
                max_match = re.search(r'observation\s*=\s*([\d.]+)', line)
                if max_match:
                    max_rtt = float(max_match.group(1))
            
            # Count successful messages
            # Example: "sockperf: [Valid Duration] RunTime=0.371 sec; SentMessages=4374; ReceivedMessages=4374"
            if 'ReceivedMessages' in line:
                received_match = re.search(r'ReceivedMessages=(\d+)', line)
                if received_match:
                    successful = int(received_match.group(1))
        
        return {
            'avg_rtt': avg_rtt,
            'std_rtt': std_rtt,
            'min_rtt': min_rtt,
            'max_rtt': max_rtt,
            'successful': successful,
            'total': successful
        }

def write_json_results(filename, dst_ip, packet_size, duration, 
                      bw_stats, rtt_stats, phase, loop_count=-1):
    """Write results to JSON file"""
    
    # Check if file exists
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            data = json.load(f)
    else:
        # Create new structure
        data = {
            "metadata": {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "description": "UDP performance benchmark using iperf3 and sockperf",
                "dest_ip": dst_ip,
                "duration": duration
            },
            "results": {
                "no_auth": {
                    "bandwidth": {}, "bandwidth_std": {}, 
                    "receiver_bandwidth": {}, "receiver_bandwidth_std": {},
                    "rtt": {}, "rtt_std": {}, "rtt_min": {}, "rtt_max": {}, 
                    "packets_sent": {}, "packets_received": {}, "packet_loss_percent": {}
                },
                "ebpf_auth": {
                    "bandwidth": {}, "bandwidth_std": {}, 
                    "receiver_bandwidth": {}, "receiver_bandwidth_std": {},
                    "rtt": {}, "rtt_std": {}, "rtt_min": {}, "rtt_max": {}, 
                    "packets_sent": {}, "packets_received": {}, "packet_loss_percent": {}
                },
                "kernel_auth": {
                    "bandwidth": {}, "bandwidth_std": {}, 
                    "receiver_bandwidth": {}, "receiver_bandwidth_std": {},
                    "rtt": {}, "rtt_std": {}, "rtt_min": {}, "rtt_max": {}, 
                    "packets_sent": {}, "packets_received": {}, "packet_loss_percent": {}
                },
                "crypto_auth": {
                    "bandwidth": {}, "bandwidth_std": {}, 
                    "receiver_bandwidth": {}, "receiver_bandwidth_std": {},
                    "rtt": {}, "rtt_std": {}, "rtt_min": {}, "rtt_max": {}, 
                    "packets_sent": {}, "packets_received": {}, "packet_loss_percent": {}
                },
                "chacha_auth": {
                    "bandwidth": {}, "bandwidth_std": {}, 
                    "receiver_bandwidth": {}, "receiver_bandwidth_std": {},
                    "rtt": {}, "rtt_std": {}, "rtt_min": {}, "rtt_max": {}, 
                    "packets_sent": {}, "packets_received": {}, "packet_loss_percent": {}
                },
                "art_delay": {}
            }
        }
    
    # Update results
    if phase == "art_delay" and loop_count >= 0:
        # Artificial delay results
        if str(loop_count) not in data['results']['art_delay']:
            data['results']['art_delay'][str(loop_count)] = {
                'bandwidth': {}, 'bandwidth_std': {}, 
                'receiver_bandwidth': {}, 'receiver_bandwidth_std': {},
                'rtt': {}, 'rtt_std': {}, 'rtt_min': {}, 'rtt_max': {}, 
                'packets_sent': {}, 'packets_received': {}, 'packet_loss_percent': {}
            }
        
        data['results']['art_delay'][str(loop_count)]['bandwidth'][str(packet_size)] = bw_stats['bandwidth_mbps']
        data['results']['art_delay'][str(loop_count)]['bandwidth_std'][str(packet_size)] = bw_stats['bandwidth_std']
        data['results']['art_delay'][str(loop_count)]['receiver_bandwidth'][str(packet_size)] = bw_stats['receiver_bandwidth_mbps']
        data['results']['art_delay'][str(loop_count)]['receiver_bandwidth_std'][str(packet_size)] = bw_stats['receiver_bandwidth_std']
        data['results']['art_delay'][str(loop_count)]['rtt'][str(packet_size)] = rtt_stats['avg_rtt']
        data['results']['art_delay'][str(loop_count)]['rtt_std'][str(packet_size)] = rtt_stats['std_rtt']
        data['results']['art_delay'][str(loop_count)]['rtt_min'][str(packet_size)] = rtt_stats['min_rtt']
        data['results']['art_delay'][str(loop_count)]['rtt_max'][str(packet_size)] = rtt_stats['max_rtt']
        data['results']['art_delay'][str(loop_count)]['packets_sent'][str(packet_size)] = bw_stats['packets_sent']
        data['results']['art_delay'][str(loop_count)]['packets_received'][str(packet_size)] = bw_stats['packets_received']
        data['results']['art_delay'][str(loop_count)]['packet_loss_percent'][str(packet_size)] = bw_stats['packet_loss_percent']
    else:
        # Standard phase results
        data['results'][phase]['bandwidth'][str(packet_size)] = bw_stats['bandwidth_mbps']
        data['results'][phase]['bandwidth_std'][str(packet_size)] = bw_stats['bandwidth_std']
        data['results'][phase]['receiver_bandwidth'][str(packet_size)] = bw_stats['receiver_bandwidth_mbps']
        data['results'][phase]['receiver_bandwidth_std'][str(packet_size)] = bw_stats['receiver_bandwidth_std']
        data['results'][phase]['rtt'][str(packet_size)] = rtt_stats['avg_rtt']
        data['results'][phase]['rtt_std'][str(packet_size)] = rtt_stats['std_rtt']
        data['results'][phase]['rtt_min'][str(packet_size)] = rtt_stats['min_rtt']
        data['results'][phase]['rtt_max'][str(packet_size)] = rtt_stats['max_rtt']
        data['results'][phase]['packets_sent'][str(packet_size)] = bw_stats['packets_sent']
        data['results'][phase]['packets_received'][str(packet_size)] = bw_stats['packets_received']
        data['results'][phase]['packet_loss_percent'][str(packet_size)] = bw_stats['packet_loss_percent']
    
    # Save to file
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"\n✓ Results saved to: {filename}")

def main():
    parser = argparse.ArgumentParser(
        description="iperf3/Sockperf-based UDP benchmark tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 auth_benchmark.py -d 192.168.100.1 -p 8192 -a no_auth
  python3 auth_benchmark.py -d 192.168.100.1 -p 1024 -m rtt -a ebpf_auth
  python3 auth_benchmark.py -d 192.168.100.1 -p 8192 -a art_delay 100

Requirements:
  - iperf3 server running on destination: iperf3 -s
  - sockperf server running on destination: sockperf server -p 11111
        """
    )
    
    parser.add_argument("-d", "--dst-ip", required=True,
                       help="Destination IP address")
    parser.add_argument("-p", "--packet-size", type=int, default=8192,
                       help="Packet size in bytes (default: 8192)")
    parser.add_argument("-t", "--duration", type=int, default=10,
                       help="Test duration in seconds per run (default: 10)")
    parser.add_argument("-m", "--mode", choices=['both', 'bandwidth', 'rtt'], 
                       default='both',
                       help="Test mode (default: both)")
    parser.add_argument("-i", "--interface", default="eth0",
                       help="Network interface (default: eth0)")
    parser.add_argument("-o", "--output", default="udp_benchmark_results.json",
                       help="Output JSON file (default: udp_benchmark_results.json)")
    parser.add_argument("-a", "--phase", nargs='+', default=['no_auth'],
                       help="Phase: no_auth, ebpf_auth, kernel_auth, crypto_auth, chacha_auth, or 'art_delay N'")
    
    args = parser.parse_args()
    
    # Parse phase and loop count
    phase = args.phase[0]
    loop_count = -1
    
    if phase == "art_delay":
        if len(args.phase) < 2:
            print("Error: art_delay requires loop count")
            print("Usage: -a art_delay 100")
            sys.exit(1)
        try:
            loop_count = int(args.phase[1])
        except ValueError:
            print(f"Error: Invalid loop count: {args.phase[1]}")
            sys.exit(1)
    
    print("="*70)
    print("iperf3/Sockperf-based UDP Benchmark Tool")
    print("="*70)
    print(f"Configuration:")
    print(f"  Destination IP: {args.dst_ip}")
    print(f"  Packet size: {args.packet_size} bytes")
    print(f"  Duration: {args.duration} seconds per run")
    print(f"  Mode: {args.mode}")
    print(f"  Phase: {phase}", end="")
    if loop_count >= 0:
        print(f" (loop_count: {loop_count})")
    else:
        print()
    print(f"  Output: {args.output}")
    print(f"\nNotes:")
    print(f"  - Bandwidth tests use iperf3 (3 runs for std dev)")
    print(f"  - RTT tests use sockperf ping-pong mode")
    
    # Create benchmark instance
    benchmark = HybridBenchmark(args.dst_ip, args.packet_size, 
                                args.duration, args.interface)
    
    # Run tests
    bw_stats = {
        'bandwidth_mbps': 0, 'bandwidth_std': 0, 
        'receiver_bandwidth_mbps': 0, 'receiver_bandwidth_std': 0,
        'packets_sent': 0, 'packets_received': 0, 
        'packet_loss_percent': 0.0, 'duration': 0
    }
    rtt_stats = {
        'avg_rtt': 0, 'std_rtt': 0, 'min_rtt': 0, 'max_rtt': 0, 
        'successful': 0, 'total': 0
    }
    
    if args.mode in ['both', 'bandwidth']:
        print("\n" + "="*70)
        print("Bandwidth Test (iperf3)")
        print("="*70)
        bw_stats = benchmark.run_bandwidth_test()
    
    if args.mode in ['both', 'rtt']:
        print("\n" + "="*70)
        print("RTT Test (sockperf)")
        print("="*70)
        rtt_stats = benchmark.run_rtt_test()
    
    # Print summary
    print("\n" + "="*70)
    print("Summary")
    print("="*70)
    if args.mode in ['both', 'bandwidth']:
        print(f"Sender Bandwidth: {bw_stats['bandwidth_mbps']:.2f} Mbps " +
              f"({bw_stats['bandwidth_mbps']/1000:.2f} Gbps)")
        print(f"Receiver Bandwidth: {bw_stats['receiver_bandwidth_mbps']:.2f} Mbps " +
              f"({bw_stats['receiver_bandwidth_mbps']/1000:.2f} Gbps)")
        print(f"Packets: {bw_stats['packets_sent']} sent, {bw_stats['packets_received']} received")
        print(f"Packet Loss: {bw_stats['packet_loss_percent']:.2f}%")
    
    if args.mode in ['both', 'rtt']:
        print(f"RTT: {rtt_stats['avg_rtt']:.3f} ± {rtt_stats['std_rtt']:.3f} µs")
        print(f"Range: {rtt_stats['min_rtt']:.3f} - {rtt_stats['max_rtt']:.3f} µs")
        print(f"Success: {rtt_stats['successful']}/{rtt_stats['total']}")
    
    # Save results
    write_json_results(args.output, args.dst_ip, args.packet_size, args.duration,
                      bw_stats, rtt_stats, phase, loop_count)
    
    print("\n" + "="*70)
    print("Complete!")
    print("="*70)

if __name__ == "__main__":
    main()
