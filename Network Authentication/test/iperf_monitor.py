#!/usr/bin/env python3
"""
iperf3 Bandwidth Monitor
Runs iperf3 tests multiple times and collects bandwidth distribution
"""

import subprocess
import json
import argparse
import time
import os
import re
from datetime import datetime
from typing import Optional, Dict, List

class Iperf3Monitor:
    def __init__(self, server_ip: str, port: int, msg_size: int, iterations: int,
                 duration: int, bandwidth: str, output_file: str):
        self.server_ip = server_ip
        self.port = port
        self.msg_size = msg_size
        self.iterations = iterations
        self.duration = duration
        self.bandwidth = bandwidth  # e.g., "0" for max, "15" for 15G
        self.output_file = output_file
        self.bandwidth_samples = []
        
    def run_single_test(self, iteration: int) -> Optional[Dict]:
        """Run a single iperf3 test and extract bandwidth"""
        
        # Build iperf3 command
        if self.bandwidth == "0":
            bw_arg = "0"  # Maximum bandwidth
        else:
            bw_arg = f"{self.bandwidth}G"  # e.g., "15G"
        
        cmd = [
            'iperf3',
            '-c', self.server_ip,
            '-p', str(self.port),
            '-u',  # UDP
            '-b', bw_arg,
            '-l', str(self.msg_size),
            '-t', str(self.duration),
            '-J'  # JSON output
        ]
        
        print(f"Iteration {iteration}/{self.iterations}: Running test...", end=' ', flush=True)
        
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=self.duration + 30
            )
            
            if result.returncode != 0:
                print(f"Failed (exit code {result.returncode})")
                print(f"Error: {result.stderr}")
                return None
            
            # Parse JSON output
            data = json.loads(result.stdout)
            
            # Extract sender and receiver statistics
            end_stats = data.get('end', {})
            
            # Sum stream (for UDP, there's typically one stream)
            sum_sent = end_stats.get('sum', {})
            sum_received = end_stats.get('sum_received', {})
            
            sender_bw_bps = sum_sent.get('bits_per_second', 0)
            receiver_bw_bps = sum_received.get('bits_per_second', 0)
            
            # Convert to Mbps
            sender_bw_mbps = sender_bw_bps / 1_000_000
            receiver_bw_mbps = receiver_bw_bps / 1_000_000
            
            # Get packet statistics
            packets_sent = sum_sent.get('packets', 0)
            packets_received = sum_received.get('packets', 0)
            packets_lost = sum_received.get('lost_packets', 0)
            loss_percent = sum_received.get('lost_percent', 0)
            jitter = sum_received.get('jitter_ms', 0)
            
            print(f"Sender: {sender_bw_mbps:.2f} Mbps, Receiver: {receiver_bw_mbps:.2f} Mbps, Loss: {loss_percent:.1f}%")
            
            return {
                'sample': iteration,
                'timestamp': time.time(),
                'sender_bandwidth_mbps': round(sender_bw_mbps, 2),
                'sender_bandwidth_gbps': round(sender_bw_mbps / 1000, 3),
                'receiver_bandwidth_mbps': round(receiver_bw_mbps, 2),
                'receiver_bandwidth_gbps': round(receiver_bw_mbps / 1000, 3),
                'packets_sent': packets_sent,
                'packets_received': packets_received,
                'packets_lost': packets_lost,
                'loss_percent': round(loss_percent, 2),
                'jitter_ms': round(jitter, 3)
            }
            
        except subprocess.TimeoutExpired:
            print(f"Timeout")
            return None
        except json.JSONDecodeError as e:
            print(f"Failed to parse JSON: {e}")
            return None
        except Exception as e:
            print(f"Error: {e}")
            return None
    
    def run_tests(self):
        """Run all iterations"""
        print("="*70)
        print("iperf3 Bandwidth Distribution Test")
        print("="*70)
        print(f"Server: {self.server_ip}:{self.port}")
        print(f"Packet size: {self.msg_size} bytes")
        print(f"Test duration: {self.duration} seconds per iteration")
        print(f"Iterations: {self.iterations}")
        
        if self.bandwidth == "0":
            print(f"Bandwidth: Maximum")
        else:
            print(f"Bandwidth: {self.bandwidth} Gbps")
        
        print("-"*70)
        
        start_time = time.time()
        
        for i in range(1, self.iterations + 1):
            result = self.run_single_test(i)
            
            if result:
                self.bandwidth_samples.append(result)
            else:
                print(f"  Warning: Iteration {i} failed, skipping")
            
            # Small delay between iterations
            if i < self.iterations:
                time.sleep(0.5)
        
        total_time = time.time() - start_time
        
        print("-"*70)
        print(f"Completed {len(self.bandwidth_samples)}/{self.iterations} iterations in {total_time:.1f} seconds")
        
        return len(self.bandwidth_samples) > 0
    
    def calculate_statistics(self) -> Dict:
        """Calculate statistics from bandwidth samples"""
        if not self.bandwidth_samples:
            return {}
        
        # Sender statistics
        sender_bw = [s['sender_bandwidth_mbps'] for s in self.bandwidth_samples]
        sender_avg = sum(sender_bw) / len(sender_bw)
        sender_max = max(sender_bw)
        sender_min = min(sender_bw)
        sender_std = (sum((x - sender_avg) ** 2 for x in sender_bw) / len(sender_bw)) ** 0.5
        
        # Receiver statistics
        receiver_bw = [s['receiver_bandwidth_mbps'] for s in self.bandwidth_samples]
        receiver_avg = sum(receiver_bw) / len(receiver_bw)
        receiver_max = max(receiver_bw)
        receiver_min = min(receiver_bw)
        receiver_std = (sum((x - receiver_avg) ** 2 for x in receiver_bw) / len(receiver_bw)) ** 0.5
        
        # Loss statistics
        loss_pcts = [s['loss_percent'] for s in self.bandwidth_samples]
        avg_loss = sum(loss_pcts) / len(loss_pcts)
        
        # Total packets
        total_sent = sum(s['packets_sent'] for s in self.bandwidth_samples)
        total_received = sum(s['packets_received'] for s in self.bandwidth_samples)
        total_lost = sum(s['packets_lost'] for s in self.bandwidth_samples)
        
        return {
            'sender': {
                'avg_bandwidth_mbps': round(sender_avg, 2),
                'max_bandwidth_mbps': round(sender_max, 2),
                'min_bandwidth_mbps': round(sender_min, 2),
                'std_dev': round(sender_std, 2)
            },
            'receiver': {
                'avg_bandwidth_mbps': round(receiver_avg, 2),
                'max_bandwidth_mbps': round(receiver_max, 2),
                'min_bandwidth_mbps': round(receiver_min, 2),
                'std_dev': round(receiver_std, 2)
            },
            'packets': {
                'total_sent': total_sent,
                'total_received': total_received,
                'total_lost': total_lost,
                'avg_loss_percent': round(avg_loss, 2)
            },
            'sample_count': len(self.bandwidth_samples)
        }
    
    def save_results(self):
        """Save or append results to JSON file"""
        if not self.bandwidth_samples:
            print("No data to save!")
            return
        
        # Calculate statistics
        stats = self.calculate_statistics()
        
        # Create test result
        test_result = {
            'test_info': {
                'server_ip': self.server_ip,
                'port': self.port,
                'msg_size': self.msg_size,
                'duration': self.duration,
                'iterations': self.iterations,
                'bandwidth_limit': f"{self.bandwidth}G" if self.bandwidth != "0" else "maximum",
                'timestamp': datetime.now().isoformat(),
                'test_type': 'iperf3_udp'
            },
            'bandwidth_samples': self.bandwidth_samples,
            'statistics': stats
        }
        
        # Load existing data if file exists
        existing_data = []
        if os.path.exists(self.output_file):
            try:
                with open(self.output_file, 'r') as f:
                    content = f.read().strip()
                    if content:
                        try:
                            existing_data = json.loads(content)
                            if not isinstance(existing_data, list):
                                existing_data = [existing_data]
                        except json.JSONDecodeError:
                            # Handle concatenated format
                            parts = content.replace('}\n{', '}\nSPLIT\n{').replace('}{', '}\nSPLIT\n{').split('SPLIT')
                            for part in parts:
                                part = part.strip()
                                if part:
                                    try:
                                        existing_data.append(json.loads(part))
                                    except:
                                        continue
            except Exception as e:
                print(f"Warning: Could not read existing file: {e}")
                existing_data = []
        
        # Append new result
        existing_data.append(test_result)
        
        # Save to file
        with open(self.output_file, 'w') as f:
            json.dump(existing_data, f, indent=2)
        
        print("\n" + "="*70)
        print(f"Results saved to: {self.output_file}")
        print(f"Total entries in file: {len(existing_data)}")
        print("\nStatistics:")
        print(f"  Sender:")
        print(f"    Average: {stats['sender']['avg_bandwidth_mbps']:.2f} Mbps")
        print(f"    Range: [{stats['sender']['min_bandwidth_mbps']:.2f}, {stats['sender']['max_bandwidth_mbps']:.2f}] Mbps")
        print(f"  Receiver:")
        print(f"    Average: {stats['receiver']['avg_bandwidth_mbps']:.2f} Mbps")
        print(f"    Range: [{stats['receiver']['min_bandwidth_mbps']:.2f}, {stats['receiver']['max_bandwidth_mbps']:.2f}] Mbps")
        print(f"  Packet Loss: {stats['packets']['avg_loss_percent']:.2f}%")
        print("="*70)


def main():
    parser = argparse.ArgumentParser(
        description='iperf3 bandwidth distribution monitor',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test with 8KB packets, 100 iterations, 10 seconds each, maximum bandwidth
  %(prog)s -s 192.168.100.1 -p 5201 -m 8192 -n 100 -t 10 -b 0 -o results.json
  
  # Test with bandwidth limit of 15 Gbps
  %(prog)s -s 192.168.100.1 -p 5201 -m 8192 -n 100 -t 10 -b 15 -o results.json
  
  # Test multiple packet sizes
  for size in 128 1024 8192; do
    python3 %(prog)s -s 192.168.100.1 -m $size -n 100 -t 1 -b 0 -o results.json
  done

Notes:
  - Make sure iperf3 server is running: iperf3 -s -p 5201
  - Results are appended to the JSON file (supports multiple packet sizes)
  - Use -b 0 for maximum bandwidth, or -b <N> to limit to N Gbps
  - JSON format matches sockperf format for compatibility with plotting scripts
        """
    )
    
    parser.add_argument('-s', '--server', required=True, help='iperf3 server IP address')
    parser.add_argument('-p', '--port', type=int, default=5201, help='Server port (default: 5201)')
    parser.add_argument('-m', '--msg-size', type=int, default=8192, help='Packet size in bytes (default: 8192)')
    parser.add_argument('-n', '--iterations', type=int, default=100, help='Number of iterations (default: 100)')
    parser.add_argument('-t', '--time', type=int, default=10, help='Test duration per iteration in seconds (default: 10)')
    parser.add_argument('-b', '--bandwidth', default="0", help='Bandwidth limit in Gbps (0 = maximum, default: 0)')
    parser.add_argument('-o', '--output', default='iperf3_results.json', help='Output JSON file (default: iperf3_results.json)')
    
    args = parser.parse_args()
    
    # Validate bandwidth
    try:
        bw_val = float(args.bandwidth)
        if bw_val < 0:
            print("Error: Bandwidth must be >= 0")
            return
    except ValueError:
        print("Error: Bandwidth must be a number")
        return
    
    monitor = Iperf3Monitor(
        server_ip=args.server,
        port=args.port,
        msg_size=args.msg_size,
        iterations=args.iterations,
        duration=args.time,
        bandwidth=args.bandwidth,
        output_file=args.output
    )
    
    success = monitor.run_tests()
    
    if success:
        monitor.save_results()
    else:
        print("\nAll tests failed!")
        print("Make sure:")
        print(f"1. iperf3 server is running: iperf3 -s -p {args.port}")
        print(f"2. Server {args.server} is reachable")
        print("3. Firewall allows traffic on the port")


if __name__ == '__main__':
    main()
