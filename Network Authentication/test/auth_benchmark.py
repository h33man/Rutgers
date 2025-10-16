#!/usr/bin/env python3
"""
eBPF UDP Performance Benchmark Tool with iperf3 and sockperf

This script benchmarks UDP packet performance:
1. Phase 1: Baseline (no authentication)
2. Phase 2: With eBPF SHA-256 authentication and LPM lookup
3. Phase 3: With kernel authentication

Tests measure:
- Bandwidth using iperf3
- RTT using sockperf
- Standard deviation for both metrics

Saves results to JSON compatible with benchmark_plotter.py
"""

import subprocess
import json
import time
import sys
import argparse
import re
from typing import Dict, List, Tuple
import statistics

class UDPBenchmarkHybrid:
    def __init__(self, server_ip: str, duration: int = 10):
        self.server_ip = server_ip
        self.duration = duration
        
        # Packet sizes to test (bytes)
        self.packet_sizes = [128, 256, 512, 1024, 2048, 4096, 8192]
        
        # Results storage
        self.results = {
            "no_auth": {
                "bandwidth": {},
                "bandwidth_std": {},
                "rtt": {},
                "rtt_std": {},
                "rtt_min": {},
                "rtt_max": {},
                "packets_sent": {}
            },
            "ebpf_auth": {
                "bandwidth": {},
                "bandwidth_std": {},
                "rtt": {},
                "rtt_std": {},
                "rtt_min": {},
                "rtt_max": {},
                "packets_sent": {}
            },
            "kernel_auth": {
                "bandwidth": {},
                "bandwidth_std": {},
                "rtt": {},
                "rtt_std": {},
                "rtt_min": {},
                "rtt_max": {},
                "packets_sent": {}
            }
        }
    
    def check_iperf3_available(self) -> bool:
        """Check if iperf3 is available on the system."""
        try:
            subprocess.run(["iperf3", "--version"], 
                         capture_output=True, check=True, timeout=5)
            print("✓ iperf3 is available")
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("✗ iperf3 is not installed or not in PATH")
            print("Please install iperf3: sudo apt-get install iperf3")
            return False
        except subprocess.TimeoutExpired:
            print("✗ iperf3 check timed out")
            return False
    
    def check_sockperf_available(self) -> bool:
        """Check if sockperf is available on the system."""
        try:
            result = subprocess.run(["sockperf", "--version"], 
                                  capture_output=True, timeout=5)
            print("✓ sockperf is available")
            return True
        except FileNotFoundError:
            print("✗ sockperf is not installed or not in PATH")
            print("Please install sockperf: sudo apt-get install sockperf")
            return False
        except subprocess.TimeoutExpired:
            print("✗ sockperf check timed out")
            return False
    
    def check_iperf3_server(self) -> bool:
        """Check if iperf3 server is running on the target."""
        try:
            result = subprocess.run([
                "iperf3", "-c", self.server_ip, "-u", "-t", "1", "-l", "64"
            ], capture_output=True, timeout=10)
            
            if result.returncode == 0:
                print(f"✓ iperf3 server accessible at {self.server_ip}")
                return True
            else:
                print(f"✗ Cannot connect to iperf3 server at {self.server_ip}")
                return False
                
        except subprocess.TimeoutExpired:
            print(f"✗ Connection timeout to iperf3 server")
            return False
        except Exception as e:
            print(f"✗ Connection test failed: {e}")
            return False
    
    def check_sockperf_server(self) -> bool:
        """Check if sockperf server is running on the target."""
        try:
            # Quick ping-pong test to check server
            result = subprocess.run([
                "sockperf", "ping-pong", "-i", self.server_ip, "-p", "11111",
                "-t", "1", "--pps", "10"
            ], capture_output=True, timeout=5)
            
            if "Summary: Latency" in result.stdout.decode() or result.returncode == 0:
                print(f"✓ sockperf server accessible at {self.server_ip}")
                return True
            else:
                print(f"✗ Cannot connect to sockperf server at {self.server_ip}")
                return False
                
        except subprocess.TimeoutExpired:
            print(f"✗ Connection timeout to sockperf server")
            return False
        except Exception as e:
            print(f"✗ sockperf connection test failed: {e}")
            return False
    
    def run_bandwidth_test_iperf3(self, packet_size: int, num_runs: int = 3) -> Tuple[float, float, int]:
        """
        Run bandwidth test using iperf3 multiple times.
        Returns (avg_bandwidth in Mbps, std_dev, packets sent)
        """
        try:
            bandwidths = []
            total_packets = 0
            
            for run in range(num_runs):
                cmd = [
                    "iperf3", "-c", self.server_ip,
                    "-u",  # UDP mode
                    "-t", str(self.duration),
                    "-l", str(packet_size),
                    "-b", "0",  # unlimited bandwidth
                    "-J"  # JSON output
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True, 
                                      timeout=self.duration + 10)
                
                if result.returncode == 0:
                    data = json.loads(result.stdout)
                    bandwidth_mbps = data['end']['sum']['bits_per_second'] / 1_000_000
                    packets = data['end']['sum'].get('packets', 0)
                    bandwidths.append(bandwidth_mbps)
                    total_packets += packets
                
                time.sleep(1)  # Brief pause between runs
            
            if bandwidths:
                avg_bw = statistics.mean(bandwidths)
                std_bw = statistics.stdev(bandwidths) if len(bandwidths) > 1 else 0.0
                print(f"    Bandwidth: {avg_bw:.2f} ± {std_bw:.2f} Mbps ({total_packets} packets)")
                return avg_bw, std_bw, total_packets
            else:
                print(f"    Warning: No successful bandwidth tests")
                return 0.0, 0.0, 0
                
        except subprocess.TimeoutExpired:
            print(f"    Warning: Bandwidth test timeout")
            return 0.0, 0.0, 0
        except json.JSONDecodeError:
            print(f"    Warning: Invalid JSON output")
            return 0.0, 0.0, 0
        except Exception as e:
            print(f"    Warning: Bandwidth test error: {e}")
            return 0.0, 0.0, 0
    
    def run_rtt_test_sockperf(self, packet_size: int) -> Tuple[float, float, float, float]:
        """
        Run RTT test using sockperf ping-pong mode.
        Returns (avg_rtt, std_rtt, min_rtt, max_rtt) in milliseconds
        """
        try:
            # sockperf uses message size (without headers)
            # Subtract UDP (8) + IP (20) headers from packet size
            msg_size = max(packet_size - 28, 14)  # sockperf minimum is 14 bytes
            
            cmd = [
                "sockperf", "ping-pong",
                "-i", self.server_ip,
                "-p", "11111",
                "-t", str(self.duration),
                "--pps", "max",  # Maximum packet rate
                "--msg-size", str(msg_size)
            ]
            
            print(f"    Running RTT test with sockperf (packet size: {packet_size} bytes)...")
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                  timeout=self.duration + 10)
            
            if result.returncode == 0 or "Summary: Latency" in result.stdout:
                output = result.stdout
                
                # Parse sockperf output
                # Format: ====> avg-latency=23.287 (std-dev=1.866)
                # Format: ---> <MAX> observation =  175.439
                # Format: ---> <MIN> observation =   21.804
                
                avg_rtt = 0.0
                min_rtt = 0.0
                max_rtt = 0.0
                std_rtt = 0.0
                
                # Extract average latency and standard deviation from same line
                avg_std_match = re.search(r'avg-latency=([\d.]+)\s+\(std-dev=([\d.]+)\)', output)
                if avg_std_match:
                    avg_rtt = float(avg_std_match.group(1)) / 1000.0  # Convert usec to ms
                    std_rtt = float(avg_std_match.group(2)) / 1000.0  # Convert usec to ms
                
                # Extract min latency
                min_match = re.search(r'<MIN>\s+observation\s*=\s*([\d.]+)', output)
                if min_match:
                    min_rtt = float(min_match.group(1)) / 1000.0
                
                # Extract max latency
                max_match = re.search(r'<MAX>\s+observation\s*=\s*([\d.]+)', output)
                if max_match:
                    max_rtt = float(max_match.group(1)) / 1000.0
                
                print(f"    RTT: avg={avg_rtt:.3f} ± {std_rtt:.3f}ms, min={min_rtt:.3f}ms, max={max_rtt:.3f}ms")
                return avg_rtt, std_rtt, min_rtt, max_rtt
            else:
                print(f"    Warning: RTT test failed")
                return 0.0, 0.0, 0.0, 0.0
                
        except subprocess.TimeoutExpired:
            print(f"    Warning: RTT test timeout")
            return 0.0, 0.0, 0.0, 0.0
        except Exception as e:
            print(f"    Warning: RTT test error: {e}")
            return 0.0, 0.0, 0.0, 0.0
    
    def run_test_suite(self, phase_name: str, phase_key: str) -> None:
        """Run complete test suite for given phase."""
        print(f"\n{'='*70}")
        print(f"PHASE: {phase_name}")
        print(f"{'='*70}")
        
        for packet_size in self.packet_sizes:
            print(f"\nTesting packet size: {packet_size} bytes")
            
            # Warmup
            print("  Warming up...")
            time.sleep(2)
            
            # Run bandwidth test with iperf3 (multiple runs for std dev)
            print("  Running bandwidth tests (3 runs)...")
            avg_bw, std_bw, packets = self.run_bandwidth_test_iperf3(packet_size, num_runs=3)
            self.results[phase_key]["bandwidth"][packet_size] = avg_bw
            self.results[phase_key]["bandwidth_std"][packet_size] = std_bw
            self.results[phase_key]["packets_sent"][packet_size] = packets
            print(f"  ✓ Bandwidth: {avg_bw:.2f} ± {std_bw:.2f} Mbps")
            
            # Brief pause
            time.sleep(2)
            
            # Run RTT test with sockperf
            avg_rtt, std_rtt, min_rtt, max_rtt = self.run_rtt_test_sockperf(packet_size)
            self.results[phase_key]["rtt"][packet_size] = avg_rtt
            self.results[phase_key]["rtt_std"][packet_size] = std_rtt
            self.results[phase_key]["rtt_min"][packet_size] = min_rtt
            self.results[phase_key]["rtt_max"][packet_size] = max_rtt
            print(f"  ✓ RTT: {avg_rtt:.3f} ± {std_rtt:.3f}ms")
            
            # Brief pause between packet sizes
            time.sleep(1)
    
    def save_results(self, filename: str = "udp_benchmark_results.json") -> None:
        """Save results to JSON file."""
        results_with_metadata = {
            "metadata": {
                "server_ip": self.server_ip,
                "test_duration": self.duration,
                "packet_sizes": self.packet_sizes,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "description": "UDP performance benchmark using iperf3 and sockperf"
            },
            "results": self.results
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(results_with_metadata, f, indent=2)
            print(f"\n✓ Results saved to: {filename}")
        except Exception as e:
            print(f"\n✗ Error saving results: {e}")
    
    def print_summary(self) -> None:
        """Print test summary."""
        print(f"\n{'='*70}")
        print("BENCHMARK SUMMARY")
        print(f"{'='*70}")
        
        phases = {
            "no_auth": "Baseline (No Authentication)",
            "ebpf_auth": "eBPF Authentication",
            "kernel_auth": "Kernel Authentication"
        }
        
        for phase_key, phase_name in phases.items():
            if not self.results[phase_key]["bandwidth"]:
                continue
            
            print(f"\n{phase_name}:")
            print("-" * 50)
            
            bws = [v for v in self.results[phase_key]["bandwidth"].values() if v > 0]
            bw_stds = [v for v in self.results[phase_key]["bandwidth_std"].values() if v > 0]
            rtts = [v for v in self.results[phase_key]["rtt"].values() if v > 0]
            rtt_stds = [v for v in self.results[phase_key]["rtt_std"].values() if v > 0]
            
            if bws:
                avg_bw = statistics.mean(bws)
                avg_bw_std = statistics.mean(bw_stds) if bw_stds else 0
                print(f"  Bandwidth - Avg: {avg_bw:.2f} ± {avg_bw_std:.2f} Mbps, Max: {max(bws):.2f} Mbps")
            
            if rtts:
                avg_rtt = statistics.mean(rtts)
                avg_rtt_std = statistics.mean(rtt_stds) if rtt_stds else 0
                print(f"  RTT - Avg: {avg_rtt:.3f} ± {avg_rtt_std:.3f} ms, Min: {min(rtts):.3f} ms")
            
            packets = [v for v in self.results[phase_key]["packets_sent"].values() if v > 0]
            if packets:
                print(f"  Total packets sent: {sum(packets)}")

def main():
    parser = argparse.ArgumentParser(
        description="UDP performance benchmark using iperf3 and sockperf",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Requirements:
  - iperf3 and sockperf installed on sender
  - iperf3 server running on receiver: iperf3 -s
  - sockperf server running on receiver: sockperf server -p 11111

Example usage:
  python udp_benchmark_hybrid.py 192.168.100.1
  python udp_benchmark_hybrid.py 192.168.100.1 --duration 15 --output results.json
        """
    )
    
    parser.add_argument("server_ip", help="IP address of the server (receiver)")
    parser.add_argument("--duration", "-t", type=int, default=10,
                       help="Test duration per packet size in seconds (default: 10)")
    parser.add_argument("--output", "-o", default="udp_benchmark_results.json",
                       help="Output JSON file (default: udp_benchmark_results.json)")
    
    args = parser.parse_args()
    
    print("="*70)
    print("eBPF UDP Performance Benchmark Tool (iperf3 + sockperf)")
    print("="*70)
    print(f"Server IP: {args.server_ip}")
    print(f"Test duration: {args.duration}s per packet size")
    print(f"Output file: {args.output}")
    
    # Initialize benchmark
    benchmark = UDPBenchmarkHybrid(args.server_ip, args.duration)
    
    # Check prerequisites
    print("\nChecking prerequisites...")
    if not benchmark.check_iperf3_available():
        sys.exit(1)
    
    if not benchmark.check_sockperf_available():
        sys.exit(1)
    
    print(f"\nChecking server connections...")
    if not benchmark.check_iperf3_server():
        print("\nPlease ensure iperf3 server is running:")
        print("  iperf3 -s")
        sys.exit(1)
    
    if not benchmark.check_sockperf_server():
        print("\nPlease ensure sockperf server is running:")
        print("  sockperf server -p 11111")
        sys.exit(1)
    
    try:
        # Phase 1: Baseline
        print(f"\n{'='*70}")
        print("PHASE 1: Baseline tests (no authentication)")
        print(f"{'='*70}")
        input("Press Enter to start baseline tests...")
        benchmark.run_test_suite("Baseline (No Authentication)", "no_auth")
        
        # Phase 2: eBPF authentication
        print(f"\n{'='*70}")
        print("PHASE 2: eBPF Authentication")
        print("\nOn RECEIVER side:")
        print("1. Load eBPF program with SHA-256 authentication")
        print("2. Load LPM_TRIE_MAP with lookup keys")
        print("3. Ensure eBPF program is attached and active")
        
        input("\nPress Enter when eBPF authentication is ready...")
        benchmark.run_test_suite("eBPF Authentication", "ebpf_auth")
        
        # Phase 3: Kernel authentication
        print(f"\n{'='*70}")
        print("PHASE 3: Kernel Authentication")
        print("\nOn RECEIVER side:")
        print("1. Unload eBPF program")
        print("2. Load kernel-level authentication")
        print("3. Ensure kernel authentication is active")
        
        input("\nPress Enter when kernel authentication is ready...")
        benchmark.run_test_suite("Kernel Authentication", "kernel_auth")
        
        # Save results and show summary
        benchmark.save_results(args.output)
        benchmark.print_summary()
        
        print(f"\n{'='*70}")
        print("Benchmark completed successfully!")
        print(f"Plot results: python3 benchmark_plotter.py {args.output}")
        print(f"{'='*70}")
        
    except KeyboardInterrupt:
        print(f"\n\n⚠️  Benchmark interrupted by user")
        has_results = any(
            benchmark.results[phase]["bandwidth"]
            for phase in ["no_auth", "ebpf_auth", "kernel_auth"]
        )
        if has_results:
            benchmark.save_results(args.output)
            print("Partial results saved.")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
