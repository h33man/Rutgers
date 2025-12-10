#!/usr/bin/env python3
"""
Sockperf Bandwidth Monitor
Runs sockperf throughput test in 1-second intervals and records bandwidth each second
"""

import subprocess
import re
import json
import argparse
import time
from datetime import datetime
from typing import Dict, Optional

class SockperfBandwidthMonitor:
    def __init__(self, server_ip: str, port: int, msg_size: int, duration: int, output_file: str):
        self.server_ip = server_ip
        self.port = port
        self.msg_size = msg_size
        self.duration = duration
        self.output_file = output_file
        self.bandwidth_data = []
        
    def run_single_test(self, test_duration: float = 10.0) -> Optional[float]:
        """Run a single sockperf test for the specified duration and extract bandwidth"""
        cmd = [
            'sockperf',
            'throughput',
            '-i', self.server_ip,
            '-p', str(self.port),
            '-t', str(test_duration),
            '--msg-size', str(self.msg_size)
        ]
        
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                timeout=test_duration + 5  # Add buffer for timeout
            )
            
            # Parse the output to extract bandwidth
            bandwidth_mbps = self._parse_bandwidth(result.stdout)
            return bandwidth_mbps
            
        except subprocess.TimeoutExpired:
            print(f"Warning: Test timed out at second {len(self.bandwidth_data) + 1}")
            return None
        except Exception as e:
            print(f"Error running test: {e}")
            return None
    
    def _parse_bandwidth(self, output: str) -> Optional[float]:
        """Parse sockperf output to extract bandwidth in Mbps"""
        # Look for patterns like:
        # "Summary: Bandwidth is 950.123 MBps"
        # "BandWidth is X.XXX MBps" 
        # "Total X.XXX MBps"
        
        # Try to find MBps (MegaBytes per second)
        mbps_pattern = re.compile(r'(\d+\.?\d*)\s*MBps', re.IGNORECASE)
        match = mbps_pattern.search(output)
        
        if match:
            mbytes_per_sec = float(match.group(1))
            # Convert MBps to Mbps (multiply by 8)
            return mbytes_per_sec * 8
        
        # Try to find Mbps directly
        mbps_direct = re.compile(r'(\d+\.?\d*)\s*Mbps', re.IGNORECASE)
        match = mbps_direct.search(output)
        
        if match:
            return float(match.group(1))
        
        # Try to find message rate and calculate bandwidth
        # Pattern: "X messages in Y seconds"
        msg_pattern = re.compile(r'(\d+)\s+messages.*?(\d+\.?\d*)\s+seconds')
        match = msg_pattern.search(output)
        
        if match:
            messages = int(match.group(1))
            seconds = float(match.group(2))
            msgs_per_sec = messages / seconds
            bytes_per_sec = msgs_per_sec * self.msg_size
            mbps = (bytes_per_sec * 8) / (1024 * 1024)
            return mbps
        
        return None
    
    def run_test(self) -> bool:
        """Run sockperf tests in 1-second intervals for the specified duration"""
        print(f"Starting sockperf bandwidth monitoring...")
        print(f"Server: {self.server_ip}:{self.port}")
        print(f"Message size: {self.msg_size} bytes")
        print(f"Duration: {self.duration} seconds")
        print(f"Recording bandwidth every second...")
        print("-" * 60)
        
        start_time = time.time()
        
        for second in range(1, self.duration + 1):
            iteration_start = time.time()
            
            print(f"Second {second}/{self.duration}...", end=' ', flush=True)
            
            # Run 1-second test
            bandwidth_mbps = self.run_single_test(test_duration=10.0)
            
            elapsed = time.time() - start_time
            
            if bandwidth_mbps is not None:
                self.bandwidth_data.append({
                    'sample': second,
                    'timestamp': elapsed,
                    'bandwidth_mbps': round(bandwidth_mbps, 2),
                    'bandwidth_gbps': round(bandwidth_mbps / 1000, 3)
                })
                print(f"{bandwidth_mbps:.2f} Mbps")
            else:
                self.bandwidth_data.append({
                    'sample': second,
                    'timestamp': elapsed,
                    'bandwidth_mbps': 0.0,
                    'bandwidth_gbps': 0.0,
                    'error': 'Failed to parse bandwidth'
                })
                print("Failed to get bandwidth")
            
            # Small sleep to prevent overwhelming the network
            iteration_time = time.time() - iteration_start
            if iteration_time < 1.0:
                time.sleep(0.1)
        
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(b"ITER_DONE", (self.server_ip, 54321))

        total_time = time.time() - start_time
        print("-" * 60)
        print(f"Test completed in {total_time:.2f} seconds")
        
        return len(self.bandwidth_data) > 0
    
    def save_results(self):
        """Save bandwidth data to JSON file"""
        if not self.bandwidth_data:
            print("No data to save!")
            return
        
        results = {
            'test_info': {
                'server_ip': self.server_ip,
                'port': self.port,
                'msg_size': self.msg_size,
                'duration': self.duration,
                'timestamp': datetime.now().isoformat(),
                'test_type': 'per_second_sampling'
            },
            'bandwidth_samples': self.bandwidth_data,
            'statistics': self._calculate_statistics()
        }
        
        with open(self.output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n{'='*60}")
        print(f"Results saved to: {self.output_file}")
        print(f"Total samples: {len(self.bandwidth_data)}")
        stats = results['statistics']
        print(f"Average bandwidth: {stats['avg_bandwidth_mbps']:.2f} Mbps")
        print(f"Peak bandwidth: {stats['max_bandwidth_mbps']:.2f} Mbps")
        print(f"Min bandwidth: {stats['min_bandwidth_mbps']:.2f} Mbps")
        print(f"Std deviation: {stats['std_dev']:.2f} Mbps")
        print(f"{'='*60}")
    
    def _calculate_statistics(self) -> Dict:
        """Calculate statistics from bandwidth data"""
        bandwidths = [d['bandwidth_mbps'] for d in self.bandwidth_data 
                     if 'bandwidth_mbps' in d and d['bandwidth_mbps'] > 0]
        
        if not bandwidths:
            return {
                'avg_bandwidth_mbps': 0.0,
                'max_bandwidth_mbps': 0.0,
                'min_bandwidth_mbps': 0.0,
                'std_dev': 0.0,
                'sample_count': 0
            }
        
        avg_bw = sum(bandwidths) / len(bandwidths)
        max_bw = max(bandwidths)
        min_bw = min(bandwidths)
        
        # Calculate standard deviation
        variance = sum((x - avg_bw) ** 2 for x in bandwidths) / len(bandwidths)
        std_dev = variance ** 0.5
        
        return {
            'avg_bandwidth_mbps': round(avg_bw, 2),
            'max_bandwidth_mbps': round(max_bw, 2),
            'min_bandwidth_mbps': round(min_bw, 2),
            'std_dev': round(std_dev, 2),
            'sample_count': len(bandwidths)
        }


def main():
    parser = argparse.ArgumentParser(
        description='Monitor sockperf bandwidth over time (per-second sampling)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test with 8KB packets for 30 seconds
  %(prog)s -i 192.168.100.1 -p 11111 -m 8192 -t 30 -o results.json
  
  # Test with 1KB packets for 60 seconds
  %(prog)s -i 192.168.100.1 -p 11111 -m 1024 -t 60 -o bw_1k.json

Note: 
- Make sure sockperf server is running on the target host:
  sockperf server -p 11111
  
- This script runs sockperf once per second to capture per-second bandwidth
- Each test iteration takes ~1 second, so total runtime will be slightly longer than specified duration
        """
    )
    
    parser.add_argument('-i', '--ip', required=True, help='Server IP address')
    parser.add_argument('-p', '--port', type=int, default=11111, help='Server port (default: 11111)')
    parser.add_argument('-m', '--msg-size', type=int, default=8192, help='Message size in bytes (default: 8192)')
    parser.add_argument('-t', '--time', type=int, default=30, help='Test duration in seconds (default: 30)')
    parser.add_argument('-o', '--output', default='bandwidth_results.json', help='Output JSON file (default: bandwidth_results.json)')
    
    args = parser.parse_args()
    
    # Validate message size against MTU
    if args.msg_size > 8972:
        print(f"Warning: Message size {args.msg_size} may exceed MTU (9000 - headers = 8972)")
        print("This may cause fragmentation issues. Consider using --msg-size 8192 or smaller.")
        response = input("Continue anyway? (y/n): ")
        if response.lower() != 'y':
            return
    
    print("\n" + "="*60)
    print("Sockperf Per-Second Bandwidth Monitor")
    print("="*60 + "\n")
    
    monitor = SockperfBandwidthMonitor(
        server_ip=args.ip,
        port=args.port,
        msg_size=args.msg_size,
        duration=args.time,
        output_file=args.output
    )
    
    success = monitor.run_test()
    
    if success:
        monitor.save_results()
        print("\nYou can now plot this data using matplotlib or any other plotting tool.")
        print(f"Example: python plot_bandwidth.py {args.output}")
    else:
        print("\nTest failed or no data collected.")
        print("Make sure:")
        print("1. Sockperf server is running: sockperf server -p 11111")
        print("2. Network connectivity is working")
        print("3. Firewall allows UDP traffic on the specified port")


if __name__ == '__main__':
    main()
