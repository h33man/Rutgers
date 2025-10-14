#!/usr/bin/env python3
import subprocess
import matplotlib.pyplot as plt
import numpy as np
import json
import time
from typing import List, Dict, Tuple

class LatencyTester:
    def __init__(self, target_host: str = "10.11.1.1", target_port: int = 2000, test_duration: int = 30):
        self.target_host = target_host
        self.target_port = target_port
        self.test_duration = test_duration
        self.testenv_script = "sudo /home/ubuntu/Authentication/testenv/testenv.sh"
        
    def run_netperf_test(self, packet_size: int, ebpf_enabled: bool = False) -> Tuple[float, float]:
        """
        Run a single netperf test and return mean latency 
        """
        cmd = [
            "sudo", "/home/ubuntu/Authentication/testenv/testenv.sh", "exec", "--",
            "netperf",
            "-H", self.target_host,
            "-l", "-1000",  # Single packet test
            "-p", str(self.target_port),
            "-t", "UDP_RR",
            "--",
            "-o", "mean_latency",
            "-r", f"{packet_size},{packet_size}"  # Request and response size
        ]
        
        try:
            print(f"Running test - Packet size: {packet_size}B, eBPF: {'ON' if ebpf_enabled else 'OFF'}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.test_duration + 30)
            
            if result.returncode != 0:
                print(f"Error running netperf: {result.stderr}")
                return None
                
            # Parse the output to extract mean latency
            output_lines = result.stdout.strip().split('\n')
            for line in output_lines:
                if line.strip() and not line.startswith('MIGRATED'):
                    try:
                        latency = float(line.strip())
                        return latency
                    except ValueError:
                        continue
            
            print(f"Could not parse latency from output: {result.stdout}")
            return None
            
        except subprocess.TimeoutExpired:
            print(f"Test timed out for packet size {packet_size}")
            return None, None
        except Exception as e:
            print(f"Error running test: {e}")
            return None, None
    
    def run_test_suite(self, packet_sizes: List[int], iterations: int = 100) -> Dict:
        """
        Run complete test suite for both eBPF enabled/disabled scenarios
        """
        results = {
            'packet_sizes': packet_sizes,
            'without_ebpf': [],
            'with_ebpf': [],
            'timestamps': []  # Track when each test was run
        }
        
        print("=== Testing WITHOUT eBPF module ===")
        input("Make sure eBPF module is DISABLED and press Enter to continue...")
        
        start_time = time.time()
        
        for size in packet_sizes:
            latencies = []
            timestamps = []
            
            for i in range(iterations):
                print(f"Packet size {size}B - Iteration {i+1}/{iterations}")
                current_time = time.time() - start_time
                mean_lat = self.run_netperf_test(size, ebpf_enabled=False)
                
                if mean_lat is not None: 
                    latencies.append(mean_lat)
                    timestamps.append(current_time)
                
                time.sleep(0.1)  # Brief pause between tests
            
            if latencies:
                results['without_ebpf'].append(latencies)
                #print(f"Packet size {size}B - Mean: {sum(latencies)/len(latencies):.2f}µs") #, Std: {np.std(latencies):.2f}µs")
                print(f"Packet size {size}B - Mean: {np.mean(latencies):.2f}µs, Std: {np.std(latencies):.2f}µs")
            else:
                results['without_ebpf'].append([])
                print(f"Packet size {size}B - No valid results")
        
        # Store timestamps for without_ebpf tests
        results['timestamps_without'] = timestamps
        
        print("\n=== Testing WITH eBPF module ===")
        input("Make sure eBPF module is ENABLED and press Enter to continue...")
        
        start_time = time.time()
        
        for size in packet_sizes:
            latencies = []
            timestamps = []
            
            for i in range(iterations):
                print(f"Packet size {size}B - Iteration {i+1}/{iterations}")
                current_time = time.time() - start_time
                mean_lat = self.run_netperf_test(size, ebpf_enabled=True)
                
                if mean_lat is not None:
                    latencies.append(mean_lat)
                    timestamps.append(current_time)
                
                time.sleep(0.1)  # Brief pause between tests
            
            if latencies:
                results['with_ebpf'].append(latencies)
                #print(f"Packet size {size}B - Mean: {sum(latencies)/len(latencies):.2f}µs") #, Std: {np.std(latencies):.2f}µs")
                print(f"Packet size {size}B - Mean: {np.mean(latencies):.2f}µs, Std: {np.std(latencies):.2f}µs")
            else:
                results['with_ebpf'].append([])
                print(f"Packet size {size}B - No valid results")
        
        # Store timestamps for with_ebpf tests
        results['timestamps_with'] = timestamps
        
        return results
    
    def save_results(self, results: Dict, filename: str = "latency_results.json"):
        """Save results to JSON file"""
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Results saved to {filename}")
    
    def load_results(self, filename: str = "latency_results.json") -> Dict:
        """Load results from JSON file"""
        try:
            with open(filename, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"File {filename} not found")
            return None

def create_mean_latency_bar_plot(results: Dict):
    """Create mean latency bar plot comparison"""
    packet_sizes = results['packet_sizes']
    without_ebpf = results['without_ebpf']
    with_ebpf = results['with_ebpf']
    
    plt.figure(figsize=(12, 8))
    
    x_pos = np.arange(len(packet_sizes))
    width = 0.35
    
    means_without = [np.mean(latencies) if latencies else 0 for latencies in without_ebpf]
    means_with = [np.mean(latencies) if latencies else 0 for latencies in with_ebpf]
    
    bars1 = plt.bar(x_pos - width/2, means_without, width, label='Without eBPF', color='blue', alpha=0.7)
    bars2 = plt.bar(x_pos + width/2, means_with, width, label='With eBPF', color='red', alpha=0.7)
    
    plt.xlabel('Packet Size (bytes)', fontsize=12)
    plt.ylabel('Mean Latency (µs)', fontsize=12)
    plt.title('Mean Latency Comparison by Packet Size', fontsize=14, fontweight='bold')
    plt.xticks(x_pos, packet_sizes)
    plt.legend(fontsize=11)
    plt.grid(True, alpha=0.3)
    
    # Add value labels on bars
    for bars in [bars1, bars2]:
        for bar in bars:
            height = bar.get_height()
            if height > 0:
                plt.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                        f'{height:.1f}', ha='center', va='bottom', fontsize=10)
    
    plt.tight_layout()
    plt.savefig('ebpf_mean_latency_bars.png', dpi=300, bbox_inches='tight')
    plt.show()

def create_box_plot_comparison(results: Dict):
    """Create box plot comparison by packet size"""
    packet_sizes = results['packet_sizes']
    without_ebpf = results['without_ebpf']
    with_ebpf = results['with_ebpf']
    
    plt.figure(figsize=(14, 8))
    
    positions_without = [i - 0.2 for i in range(len(packet_sizes))]
    positions_with = [i + 0.2 for i in range(len(packet_sizes))]
    
    without_data = [latencies for latencies in without_ebpf if latencies]
    with_data = [latencies for latencies in with_ebpf if latencies]
    
    if without_data:
        bp1 = plt.boxplot(without_data, positions=positions_without, widths=0.3, 
                         patch_artist=True, boxprops=dict(facecolor='blue', alpha=0.7))
    if with_data:
        bp2 = plt.boxplot(with_data, positions=positions_with, widths=0.3,
                         patch_artist=True, boxprops=dict(facecolor='red', alpha=0.7))
    
    plt.xlabel('Packet Size (bytes)', fontsize=12)
    plt.ylabel('Latency (µs)', fontsize=12)
    plt.title('Latency Distribution Comparison by Packet Size', fontsize=14, fontweight='bold')
    plt.xticks(range(len(packet_sizes)), packet_sizes)
    plt.grid(True, alpha=0.3)
    
    # Create legend
    if without_data and with_data:
        plt.legend([bp1["boxes"][0], bp2["boxes"][0]], ['Without eBPF', 'With eBPF'], fontsize=11)
    
    plt.tight_layout()
    plt.savefig('ebpf_latency_boxplot.png', dpi=300, bbox_inches='tight')
    plt.show()

def create_line_plot_comparison(results: Dict):
    """Create line plot showing mean latency trends"""
    packet_sizes = results['packet_sizes']
    without_ebpf = results['without_ebpf']
    with_ebpf = results['with_ebpf']
    
    plt.figure(figsize=(12, 8))
    
    means_without = [np.mean(latencies) if latencies else 0 for latencies in without_ebpf]
    means_with = [np.mean(latencies) if latencies else 0 for latencies in with_ebpf]
    
    plt.plot(packet_sizes, means_without, 'o-', color='blue', linewidth=3, markersize=10, 
             label='Without eBPF', markerfacecolor='lightblue', markeredgecolor='blue', markeredgewidth=2)
    plt.plot(packet_sizes, means_with, 'o-', color='red', linewidth=3, markersize=10, 
             label='With eBPF', markerfacecolor='lightcoral', markeredgecolor='red', markeredgewidth=2)
    
    plt.xlabel('Packet Size (bytes)', fontsize=12)
    plt.ylabel('Mean Latency (µs)', fontsize=12)
    plt.title('Mean Latency Trends vs Packet Size', fontsize=14, fontweight='bold')
    plt.legend(fontsize=11)
    plt.grid(True, alpha=0.3)
    plt.xscale('log')
    
    # Add value annotations
    for i, (size, without, with_val) in enumerate(zip(packet_sizes, means_without, means_with)):
        if without > 0:
            plt.annotate(f'{without:.1f}µs', (size, without), textcoords="offset points", 
                        xytext=(0,15), ha='center', color='blue', fontsize=9)
        if with_val > 0:
            plt.annotate(f'{with_val:.1f}µs', (size, with_val), textcoords="offset points", 
                        xytext=(0,-20), ha='center', color='red', fontsize=9)
    
    plt.tight_layout()
    plt.savefig('ebpf_latency_trends.png', dpi=300, bbox_inches='tight')
    plt.show()

def create_overhead_plot(results: Dict):
    """Create overhead calculation plot"""
    packet_sizes = results['packet_sizes']
    without_ebpf = results['without_ebpf']
    with_ebpf = results['with_ebpf']
    
    plt.figure(figsize=(12, 8))
    
    overhead = []
    valid_sizes = []
    for i, size in enumerate(packet_sizes):
        if without_ebpf[i] and with_ebpf[i]:
            mean_without = np.mean(without_ebpf[i])
            mean_with = np.mean(with_ebpf[i])
            overhead_pct = ((mean_with - mean_without) / mean_without) * 100
            overhead.append(overhead_pct)
            valid_sizes.append(size)
    
    if overhead:
        colors = ['green' if x < 0 else 'red' for x in overhead]
        bars = plt.bar(range(len(valid_sizes)), overhead, color=colors, alpha=0.7)
        
        plt.xlabel('Packet Size (bytes)', fontsize=12)
        plt.ylabel('Overhead (%)', fontsize=12)
        plt.title('eBPF Module Overhead by Packet Size', fontsize=14, fontweight='bold')
        plt.xticks(range(len(valid_sizes)), valid_sizes)
        plt.grid(True, alpha=0.3)
        plt.axhline(y=0, color='black', linestyle='-', linewidth=1)
        
        # Add value labels on bars
        for i, (bar, val) in enumerate(zip(bars, overhead)):
            plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + (0.2 if val > 0 else -0.8),
                    f'{val:.1f}%', ha='center', va='bottom' if val > 0 else 'top', fontsize=11, fontweight='bold')
        
        # Add legend
        from matplotlib.patches import Patch
        legend_elements = [Patch(facecolor='red', alpha=0.7, label='Overhead (slower)'),
                          Patch(facecolor='green', alpha=0.7, label='Improvement (faster)')]
        plt.legend(handles=legend_elements, fontsize=11)
    
    plt.tight_layout()
    plt.savefig('ebpf_overhead_analysis.png', dpi=300, bbox_inches='tight')
    plt.show()

def create_time_series_plot(results: Dict):
    """Create time series plot showing latency distribution over time"""
    packet_sizes = results['packet_sizes']
    without_ebpf = results['without_ebpf']
    with_ebpf = results['with_ebpf']
    
    plt.figure(figsize=(16, 8))
    
    # Combine all data points with timestamps for time series
    all_times_without = []
    all_latencies_without = []
    all_times_with = []
    all_latencies_with = []
    all_packet_sizes_without = []
    all_packet_sizes_with = []
    
    # Collect data from all packet sizes with color coding
    time_offset = 0
    for i, size in enumerate(packet_sizes):
        if without_ebpf[i]:
            for j, lat in enumerate(without_ebpf[i]):
                all_times_without.append(time_offset + j * 0.1)  # 0.1s between tests
                all_latencies_without.append(lat)
                all_packet_sizes_without.append(size)
            time_offset += len(without_ebpf[i]) * 0.1 + 5  # 5s gap between packet sizes
        
        if with_ebpf[i]:
            for j, lat in enumerate(with_ebpf[i]):
                all_times_with.append(time_offset + j * 0.1)
                all_latencies_with.append(lat)
                all_packet_sizes_with.append(size)
            time_offset += len(with_ebpf[i]) * 0.1 + 5
    
    # Create scatter plot with different colors for different packet sizes
    colors = ['blue', 'cyan', 'green', 'yellow', 'orange', 'red']
    size_to_color = {size: colors[i % len(colors)] for i, size in enumerate(packet_sizes)}
    
    # Plot without eBPF data
    for size in packet_sizes:
        times_for_size = [t for t, s in zip(all_times_without, all_packet_sizes_without) if s == size]
        lats_for_size = [l for l, s in zip(all_latencies_without, all_packet_sizes_without) if s == size]
        if times_for_size:
            plt.scatter(times_for_size, lats_for_size, alpha=0.6, s=15, 
                       color=size_to_color[size], marker='o', label=f'{size}B (no eBPF)')
    
    # Plot with eBPF data
    for size in packet_sizes:
        times_for_size = [t for t, s in zip(all_times_with, all_packet_sizes_with) if s == size]
        lats_for_size = [l for l, s in zip(all_latencies_with, all_packet_sizes_with) if s == size]
        if times_for_size:
            plt.scatter(times_for_size, lats_for_size, alpha=0.6, s=15, 
                       color=size_to_color[size], marker='x', label=f'{size}B (with eBPF)')
    
    plt.xlabel('Time Elapsed (seconds)', fontsize=12)
    plt.ylabel('Measured RTT Latency (µs)', fontsize=12)
    plt.title('Latency Distribution Over Time by Packet Size', fontsize=14, fontweight='bold')
    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left', fontsize=9)
    plt.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig('ebpf_latency_timeseries.png', dpi=300, bbox_inches='tight')
    plt.show()

def create_summary_statistics_plot(results: Dict):
    """Create a summary statistics comparison table as a plot"""
    packet_sizes = results['packet_sizes']
    without_ebpf = results['without_ebpf']
    with_ebpf = results['with_ebpf']
    
    fig, ax = plt.subplots(figsize=(14, 8))
    ax.axis('tight')
    ax.axis('off')
    
    # Prepare data for table
    table_data = []
    headers = ['Packet Size (B)', 'Without eBPF\nMean ± Std (µs)', 'With eBPF\nMean ± Std (µs)', 'Overhead (%)', 'Status']
    
    for i, size in enumerate(packet_sizes):
        if without_ebpf[i] and with_ebpf[i]:
            mean_without = np.mean(without_ebpf[i])
            std_without = np.std(without_ebpf[i])
            mean_with = np.mean(with_ebpf[i])
            std_with = np.std(with_ebpf[i])
            overhead_pct = ((mean_with - mean_without) / mean_without) * 100
            
            status = "↑ Slower" if overhead_pct > 0 else "↓ Faster"
            
            table_data.append([
                f'{size}',
                f'{mean_without:.2f} ± {std_without:.2f}',
                f'{mean_with:.2f} ± {std_with:.2f}',
                f'{overhead_pct:+.1f}%',
                status
            ])
    
    # Create table
    table = ax.table(cellText=table_data, colLabels=headers, loc='center', cellLoc='center')
    table.auto_set_font_size(False)
    table.set_fontsize(11)
    table.scale(1.2, 2)
    
    # Style the table
    for i in range(len(headers)):
        table[(0, i)].set_facecolor('#4CAF50')
        table[(0, i)].set_text_props(weight='bold', color='white')
    
    for i in range(1, len(table_data) + 1):
        for j in range(len(headers)):
            if j == 4:  # Status column
                if 'Slower' in table_data[i-1][j]:
                    table[(i, j)].set_facecolor('#ffcccb')
                else:
                    table[(i, j)].set_facecolor('#ccffcc')
            elif j == 3:  # Overhead column
                overhead_val = float(table_data[i-1][j].replace('%', '').replace('+', ''))
                if overhead_val > 0:
                    table[(i, j)].set_facecolor('#ffeeee')
                else:
                    table[(i, j)].set_facecolor('#eeffee')
    
    plt.title('eBPF Latency Impact - Summary Statistics', fontsize=16, fontweight='bold', pad=20)
    plt.savefig('ebpf_summary_statistics.png', dpi=300, bbox_inches='tight')
    plt.show()

def create_comparison_plots(results: Dict):
    """Create all comparison plots separately"""
    print("Creating individual plots...")
    
    # Create each plot separately
    create_mean_latency_bar_plot(results)
    create_box_plot_comparison(results)
    create_line_plot_comparison(results)
    create_overhead_plot(results)
    create_time_series_plot(results)
    create_summary_statistics_plot(results)
    
    # Print summary statistics to console
    print("\n=== SUMMARY STATISTICS ===")
    packet_sizes = results['packet_sizes']
    without_ebpf = results['without_ebpf']
    with_ebpf = results['with_ebpf']
    
    for i, size in enumerate(packet_sizes):
        if without_ebpf[i] and with_ebpf[i]:
            mean_without = np.mean(without_ebpf[i])
            mean_with = np.mean(with_ebpf[i])
            print(f"Packet size {size}B:")
            print(f"  Without eBPF: {mean_without:.2f} ± {np.std(without_ebpf[i]):.2f} µs")
            print(f"  With eBPF:    {mean_with:.2f} ± {np.std(with_ebpf[i]):.2f} µs")
            print(f"  Overhead:     {((mean_with - mean_without) / mean_without) * 100:.1f}%")
            print()
    
    print("All plots have been saved as separate PNG files:")
    print("- ebpf_mean_latency_bars.png")
    print("- ebpf_latency_boxplot.png") 
    print("- ebpf_latency_trends.png")
    print("- ebpf_overhead_analysis.png")
    print("- ebpf_latency_timeseries.png")
    print("- ebpf_summary_statistics.png")

def main():
    # Configuration
    packet_sizes = [64, 128, 256, 512, 1024, 1500]  # Common packet sizes
    iterations = 100  # Number of iterations per test
    
    tester = LatencyTester()
    
    print("eBPF Latency Testing Tool")
    print("=" * 40)
    print(f"Target: {tester.target_host}:{tester.target_port}")
    print(f"Single packet test per iteration (-l -1000)")
    print(f"Iterations per packet size: {iterations}")
    print(f"Packet sizes: {packet_sizes}")
    print()
    
    choice = input("Choose option:\n1. Run new tests\n2. Load existing results\nEnter choice (1/2): ")
    
    if choice == "1":
        results = tester.run_test_suite(packet_sizes, iterations)
        tester.save_results(results)
        create_comparison_plots(results)
    elif choice == "2":
        filename = input("Enter filename (default: latency_results.json): ").strip()
        if not filename:
            filename = "latency_results.json"
        results = tester.load_results(filename)
        if results is None:
            return
        create_comparison_plots(results)
    else:
        print("Invalid choice")
        return

if __name__ == "__main__":
    main()
