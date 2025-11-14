#!/usr/bin/env python3
"""
Sockperf-based UDP Benchmark Tool

Uses sockperf for both bandwidth (throughput) and RTT measurements.
Compatible with the same JSON output format as the C version.

Requirements:
  - sockperf installed: sudo apt-get install sockperf
  - Server running: sockperf server -p 11111

Usage:
    python3 sockperf_benchmark.py -d 192.168.100.1 -p 8192 -a no_auth
    python3 sockperf_benchmark.py -d 192.168.100.1 -p 1024 -m rtt -a ebpf_auth
    python3 sockperf_benchmark.py -d 192.168.100.1 -p 8192 -a art_delay 100
"""

import subprocess
import json
import time
import argparse
import re
import sys
import os
from datetime import datetime

class SockperfBenchmark:
    def __init__(self, dst_ip, packet_size, duration=10, interface="eth0"):
        self.dst_ip = dst_ip
        self.packet_size = packet_size
        self.duration = duration
        self.interface = interface
        self.server_port = 11111
        
        # Check if sockperf is available
        if not self.check_sockperf():
            print("Error: sockperf not found. Install with: sudo apt-get install sockperf")
            sys.exit(1)
    
    def check_sockperf(self):
        """Check if sockperf is installed"""
        try:
            subprocess.run(["sockperf", "--version"], 
                          capture_output=True, timeout=5)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def run_bandwidth_test(self):
        """
        Run bandwidth test using sockperf tp (throughput) mode
        
        Returns:
            dict: {bandwidth_mbps, bandwidth_std, packets_sent, duration}
        """
        print(f"\nRunning bandwidth test...")
        print(f"  Duration: {self.duration} seconds")
        print(f"  Packet size: {self.packet_size} bytes")
        
        # sockperf uses message size (payload without headers)
        # Subtract UDP (8) + IP (20) headers
        msg_size = max(self.packet_size - 28, 14)  # minimum 14 bytes
        
        # Run sockperf in throughput (tp) mode
        cmd = [
            "sockperf", "tp",
            "-i", self.dst_ip,
            "-p", str(self.server_port),
            "-t", str(self.duration),
            "-m", str(msg_size),
            "--mps", "max"  # Maximum messages per second
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                   timeout=self.duration + 30)
            
            '''
            # Print raw output for debugging
            print(f"\n--- Sockperf Output ---")
            for line in result.stdout.split('\n'):
                if 'Summary:' in line or 'Total of' in line or 'Message Rate' in line or 'BandWidth' in line:
                    print(f"  {line}")
            print(f"--- End Output ---\n")
            '''
            # Parse output
            bandwidth_mbps, packets_sent = self._parse_throughput_output(result.stdout)
            
            # sockperf doesn't provide per-second breakdown for std dev
            # We'll approximate by doing multiple short runs
            bandwidth_std = 0.0
            
            if bandwidth_mbps > 0:
                print(f"  ✓ Bandwidth: {bandwidth_mbps:.2f} Mbps")
                print(f"  ✓ Packets sent: {packets_sent}")
            else:
                print(f"  ✗ Failed to measure bandwidth")
            
            return {
                'bandwidth_mbps': bandwidth_mbps,
                'bandwidth_std': bandwidth_std,
                'packets_sent': packets_sent,
                'duration': self.duration
            }
            
        except subprocess.TimeoutExpired:
            print(f"  ✗ Test timed out")
            return {
                'bandwidth_mbps': 0.0,
                'bandwidth_std': 0.0,
                'packets_sent': 0,
                'duration': 0.0
            }
        except Exception as e:
            print(f"  ✗ Error: {e}")
            return {
                'bandwidth_mbps': 0.0,
                'bandwidth_std': 0.0,
                'packets_sent': 0,
                'duration': 0.0
            }
    
    def run_rtt_test(self, num_samples=100):
        """
        Run RTT test using sockperf ping-pong mode
        
        Returns:
            dict: {avg_rtt, std_rtt, min_rtt, max_rtt, successful, total}
        """
        print(f"\nRunning RTT test...")
        print(f"  Samples: {num_samples}")
        print(f"  Packet size: {self.packet_size} bytes")
        
        # sockperf uses message size (payload without headers)
        msg_size = max(self.packet_size - 28, 14)
        
        # Run sockperf in ping-pong mode
        cmd = [
            "sockperf", "ping-pong",
            "-i", self.dst_ip,
            "-p", str(self.server_port),
            "-t", str(int(num_samples / 10)),  # Duration in seconds (approx)
            "--msg-size", str(msg_size),
            "--pps", "10"  # 10 packets per second for RTT measurement
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                   timeout=60)
            
            # Parse output
            rtt_stats = self._parse_rtt_output(result.stdout)
            
            if rtt_stats['avg_rtt'] > 0:
                print(f"  ✓ RTT: {rtt_stats['avg_rtt']:.3f} ± {rtt_stats['std_rtt']:3f} µs")
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
                'total': num_samples
            }
        except Exception as e:
            print(f"  ✗ Error: {e}")
            return {
                'avg_rtt': 0.0,
                'std_rtt': 0.0,
                'min_rtt': 0.0,
                'max_rtt': 0.0,
                'successful': 0,
                'total': num_samples
            }
    
    def _parse_throughput_output(self, output):
        """
        Parse sockperf throughput (tp) output
        
        Example output:
            sockperf: Total of 2970017 messages sent in 10.000 sec
            sockperf: Summary: Message Rate is 296989 [msg/sec]
            sockperf: Summary: BandWidth is 72.507 MBps (580.057 Mbps)
        """
        bandwidth_mbps = 0.0
        packets_sent = 0
        
        for line in output.split('\n'):
            # Parse bandwidth line
            # Example: "sockperf: Summary: BandWidth is 72.507 MBps (580.057 Mbps)"
            if 'BandWidth' in line and 'Mbps' in line:
                # Extract the Mbps value in parentheses
                mbps_match = re.search(r'\((\d+\.?\d*)\s*Mbps\)', line)
                if mbps_match:
                    bandwidth_mbps = float(mbps_match.group(1))
                else:
                    # Fallback: try to find MBps and convert
                    mbytes_match = re.search(r'is\s+(\d+\.?\d*)\s*MBps', line)
                    if mbytes_match:
                        bandwidth_mbytes = float(mbytes_match.group(1))
                        bandwidth_mbps = bandwidth_mbytes * 8  # Convert MBps to Mbps
            
            # Parse total messages
            # Example: "sockperf: Total of 2970017 messages sent in 10.000 sec"
            if 'Total of' in line and 'messages sent' in line:
                total_match = re.search(r'Total of\s+(\d+)\s+messages', line)
                if total_match:
                    packets_sent = int(total_match.group(1))
        
        return bandwidth_mbps, packets_sent
    
    def _parse_rtt_output(self, output):
        """Parse sockperf ping-pong output"""
        avg_rtt = 0.0
        std_rtt = 0.0
        min_rtt = 0.0
        max_rtt = 0.0
        successful = 0
        
        for line in output.split('\n'):
            # Example: "====> avg-latency=23.287 (std-dev=1.866)"
            if 'avg-latency' in line:
                avg_match = re.search(r'avg-latency=([\d.]+)', line)
                std_match = re.search(r'std-dev=([\d.]+)', line)
                if avg_match:
                    avg_rtt = float(avg_match.group(1)) #* 1000.0  # Convert usec to ms
                if std_match:
                    std_rtt = float(std_match.group(1)) #* 1000.0
            
            # Example: "---> <MIN> observation =  21.804"
            if '<MIN>' in line:
                min_match = re.search(r'observation\s*=\s*([\d.]+)', line)
                if min_match:
                    min_rtt = float(min_match.group(1)) #* 1000.0
            
            # Example: "---> <MAX> observation =  175.439"
            if '<MAX>' in line:
                max_match = re.search(r'observation\s*=\s*([\d.]+)', line)
                if max_match:
                    max_rtt = float(max_match.group(1)) #* 1000.0
            
            # Count successful messages
            if 'Total' in line and 'messages' in line:
                total_match = re.search(r'Total\s+(\d+)', line)
                if total_match:
                    successful = int(total_match.group(1))
        
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
                "description": "UDP performance benchmark using sockperf",
                "dest_ip": dst_ip,
                "duration": duration
            },
            "results": {
                "no_auth": {
                    "bandwidth": {}, "bandwidth_std": {}, "rtt": {}, 
                    "rtt_std": {}, "rtt_min": {}, "rtt_max": {}, "packets_sent": {}
                },
                "ebpf_auth": {
                    "bandwidth": {}, "bandwidth_std": {}, "rtt": {}, 
                    "rtt_std": {}, "rtt_min": {}, "rtt_max": {}, "packets_sent": {}
                },
                "kernel_auth": {
                    "bandwidth": {}, "bandwidth_std": {}, "rtt": {}, 
                    "rtt_std": {}, "rtt_min": {}, "rtt_max": {}, "packets_sent": {}
                },
                "art_delay": {}
            }
        }
    
    # Update results
    if phase == "art_delay" and loop_count >= 0:
        # Artificial delay results
        if str(loop_count) not in data['results']['art_delay']:
            data['results']['art_delay'][str(loop_count)] = {
                'bandwidth': {}, 'bandwidth_std': {}, 'rtt': {},
                'rtt_std': {}, 'rtt_min': {}, 'rtt_max': {}, 'packets_sent': {}
            }
        
        data['results']['art_delay'][str(loop_count)]['bandwidth'][str(packet_size)] = bw_stats['bandwidth_mbps']
        data['results']['art_delay'][str(loop_count)]['bandwidth_std'][str(packet_size)] = bw_stats['bandwidth_std']
        data['results']['art_delay'][str(loop_count)]['rtt'][str(packet_size)] = rtt_stats['avg_rtt']
        data['results']['art_delay'][str(loop_count)]['rtt_std'][str(packet_size)] = rtt_stats['std_rtt']
        data['results']['art_delay'][str(loop_count)]['rtt_min'][str(packet_size)] = rtt_stats['min_rtt']
        data['results']['art_delay'][str(loop_count)]['rtt_max'][str(packet_size)] = rtt_stats['max_rtt']
        data['results']['art_delay'][str(loop_count)]['packets_sent'][str(packet_size)] = bw_stats['packets_sent']
    else:
        # Standard phase results
        data['results'][phase]['bandwidth'][str(packet_size)] = bw_stats['bandwidth_mbps']
        data['results'][phase]['bandwidth_std'][str(packet_size)] = bw_stats['bandwidth_std']
        data['results'][phase]['rtt'][str(packet_size)] = rtt_stats['avg_rtt']
        data['results'][phase]['rtt_std'][str(packet_size)] = rtt_stats['std_rtt']
        data['results'][phase]['rtt_min'][str(packet_size)] = rtt_stats['min_rtt']
        data['results'][phase]['rtt_max'][str(packet_size)] = rtt_stats['max_rtt']
        data['results'][phase]['packets_sent'][str(packet_size)] = bw_stats['packets_sent']
    
    # Save to file
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"\n✓ Results saved to: {filename}")

def main():
    parser = argparse.ArgumentParser(
        description="Sockperf-based UDP benchmark tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 sockperf_benchmark.py -d 192.168.100.1 -p 8192 -a no_auth
  python3 sockperf_benchmark.py -d 192.168.100.1 -p 1024 -m rtt -a ebpf_auth
  python3 sockperf_benchmark.py -d 192.168.100.1 -p 8192 -a art_delay 100

Note: Requires sockperf server running on destination:
  sockperf server -p 11111
        """
    )
    
    parser.add_argument("-d", "--dst-ip", required=True,
                       help="Destination IP address")
    parser.add_argument("-p", "--packet-size", type=int, default=8192,
                       help="Packet size in bytes (default: 8192)")
    parser.add_argument("-t", "--duration", type=int, default=10,
                       help="Test duration in seconds (default: 10)")
    parser.add_argument("-m", "--mode", choices=['both', 'bandwidth', 'rtt'], 
                       default='both',
                       help="Test mode (default: both)")
    parser.add_argument("-i", "--interface", default="eth0",
                       help="Network interface (default: eth0)")
    parser.add_argument("-o", "--output", default="udp_benchmark_results.json",
                       help="Output JSON file (default: udp_benchmark_results.json)")
    parser.add_argument("-a", "--phase", nargs='+', default=['no_auth'],
                       help="Phase: no_auth, ebpf_auth, kernel_auth, or 'art_delay N'")
    
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
    print("Sockperf-based UDP Benchmark Tool")
    print("="*70)
    print(f"Configuration:")
    print(f"  Destination IP: {args.dst_ip}")
    print(f"  Packet size: {args.packet_size} bytes")
    print(f"  Duration: {args.duration} seconds")
    print(f"  Mode: {args.mode}")
    print(f"  Phase: {phase}", end="")
    if loop_count >= 0:
        print(f" (loop_count: {loop_count})")
    else:
        print()
    print(f"  Output: {args.output}")
    
    # Create benchmark instance
    benchmark = SockperfBenchmark(args.dst_ip, args.packet_size, 
                                  args.duration, args.interface)
    
    # Run tests
    bw_stats = {'bandwidth_mbps': 0, 'bandwidth_std': 0, 'packets_sent': 0, 'duration': 0}
    rtt_stats = {'avg_rtt': 0, 'std_rtt': 0, 'min_rtt': 0, 'max_rtt': 0, 
                 'successful': 0, 'total': 0}
    
    if args.mode in ['both', 'bandwidth']:
        print("\n" + "="*70)
        print("Bandwidth Test")
        print("="*70)
        bw_stats = benchmark.run_bandwidth_test()
    
    if args.mode in ['both', 'rtt']:
        print("\n" + "="*70)
        print("RTT Test")
        print("="*70)
        rtt_stats = benchmark.run_rtt_test()
    
    # Print summary
    print("\n" + "="*70)
    print("Summary")
    print("="*70)
    if args.mode in ['both', 'bandwidth']:
        print(f"Bandwidth: {bw_stats['bandwidth_mbps']:.2f} Mbps " +
              f"({bw_stats['bandwidth_mbps']/1000:.2f} Gbps)")
        print(f"Packets sent: {bw_stats['packets_sent']}")
    
    if args.mode in ['both', 'rtt']:
        print(f"RTT: {rtt_stats['avg_rtt']:.3f} ± {rtt_stats['std_rtt']:.3}f µs")
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
