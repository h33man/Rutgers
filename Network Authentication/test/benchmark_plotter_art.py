#!/usr/bin/env python3
"""
Plot Artificial Delay Results vs CPU Usage

Plots bandwidth and RTT as a function of added CPU usage (in nanoseconds).
Each loop adds 9ns of delay.

Usage:
    python3 plot_art_delay_cpu.py udp_benchmark_results.json
    python3 plot_art_delay_cpu.py results.json --ns-per-loop 9
"""

import json
import sys
import argparse
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict

def load_results(filename):
    """Load results from JSON file"""
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in '{filename}': {e}")
        sys.exit(1)

def extract_art_delay_data(results, ns_per_loop):
    """
    Extract artificial delay data organized by packet size
    
    Returns:
        dict: {packet_size: [(cpu_usage_ns, bandwidth, bw_std, rtt, rtt_std), ...]}
    """
    art_delay = results.get('results', {}).get('art_delay', {})
    
    if not art_delay:
        return {}
    
    # Organize data by packet size
    data_by_packet_size = defaultdict(list)
    
    for loop_count_str, loop_data in art_delay.items():
        try:
            loop_count = int(loop_count_str)
            cpu_usage_ns = loop_count * ns_per_loop
            
            # Check the structure - could be nested or flat
            # New structure: art_delay -> loop_count -> metric_type -> packet_size -> value
            # Example: art_delay["0"]["bandwidth"]["128"] = 342.7
            
            if isinstance(loop_data, dict):
                # Get bandwidth dict
                bandwidth_dict = loop_data.get('bandwidth', {})
                bw_std_dict = loop_data.get('bandwidth_std', {})
                rtt_dict = loop_data.get('rtt', {})
                rtt_std_dict = loop_data.get('rtt_std', {})
                
                # Extract all packet sizes from bandwidth dict
                for packet_size_str, bandwidth in bandwidth_dict.items():
                    try:
                        packet_size = int(packet_size_str)
                        bw_std = bw_std_dict.get(packet_size_str, 0)
                        rtt = rtt_dict.get(packet_size_str, 0)
                        rtt_std = rtt_std_dict.get(packet_size_str, 0)
                        
                        # Only include if we have valid data
                        if bandwidth > 0 or rtt > 0:
                            data_by_packet_size[packet_size].append({
                                'cpu_usage_ns': cpu_usage_ns,
                                'loop_count': loop_count,
                                'bandwidth': bandwidth,
                                'bw_std': bw_std,
                                'rtt': rtt,
                                'rtt_std': rtt_std
                            })
                    except (ValueError, TypeError) as e:
                        print(f"Warning: Skipping packet_size_str={packet_size_str}: {e}")
                        continue
        
        except (ValueError, TypeError) as e:
            print(f"Warning: Skipping loop_count_str={loop_count_str}: {e}")
            continue
    
    # Sort by CPU usage for each packet size
    for packet_size in data_by_packet_size:
        data_by_packet_size[packet_size].sort(key=lambda x: x['cpu_usage_ns'])
    
    return dict(data_by_packet_size)

def plot_bandwidth_vs_cpu(data_by_packet_size, output_file, ebpf_delay_ns=None):
    """Plot bandwidth vs CPU usage for different packet sizes"""
    
    if not data_by_packet_size:
        print("No data to plot for bandwidth")
        return
    
    fig, ax = plt.subplots(figsize=(14, 8))
    
    # Color palette for different packet sizes
    packet_sizes_sorted = sorted(data_by_packet_size.keys())
    colors = plt.cm.viridis(np.linspace(0, 0.9, len(packet_sizes_sorted)))
    
    # Markers for different packet sizes
    markers = ['o', 's', '^', 'D', 'v', '<', '>', 'p', '*', 'h', 'X', 'd']
    
    for idx, packet_size in enumerate(packet_sizes_sorted):
        data = data_by_packet_size[packet_size]
        cpu_usage = [d['cpu_usage_ns'] for d in data]
        bandwidths = [d['bandwidth'] for d in data]
        bw_stds = [d['bw_std'] for d in data]
        
        # Skip if no valid bandwidth data
        if not any(b > 0 for b in bandwidths):
            continue
        
        color = colors[idx]
        marker = 'o' #markers[idx % len(markers)]
        
        # FIX: Use proper keyword arguments for color
        ax.plot(cpu_usage, bandwidths, 
                marker=marker,
                linestyle='-',
                color=color,
                label=f'{packet_size} bytes', 
                linewidth=2, 
                markersize=6)
        """
       eb1 = ax.errorbar(self.packet_sizes, no_auth_rtt, yerr=no_auth_std,
               fmt='o-', linewidth=2.5, markersize=8, label='No Authentication',
               color='#4169E1', alpha=0.8, capsize=5, capthick=1.5,
               elinewidth=1.5, ecolor='gray')
        ax.errorbar(cpu_usage, bandwidths, yerr=bw_stds,
                alpha=0.8,
                marker=marker,
                linestyle='-',
                color=color,
                label=f'{packet_size} bytes', 
                linewidth=2, 
                markersize=6)

        ax.errorbar(cpu_usage, bandwidths, yerr=bw_stds, linestyle='-',
                    marker=marker, markersize=6, linewidth=2, capsize=4,
                    label=f'{packet_size} bytes', color=color, alpha=0.85,
                    markeredgewidth=1.5, markeredgecolor='white')
        """
    
    # Add vertical line for eBPF authentication delay
    if ebpf_delay_ns is not None:
        ax.axvline(x=ebpf_delay_ns, color='red', linestyle='--', linewidth=2.5, 
                   label=f'eBPF Auth Delay ({ebpf_delay_ns} ns)', zorder=1000)
        # Add text annotation
        y_pos = ax.get_ylim()[1] * 0.95
        ax.text(ebpf_delay_ns + 50, y_pos, f'eBPF Auth Overhead\n{ebpf_delay_ns} ns',
                color='red', fontsize=10, fontweight='bold', 
                verticalalignment='top')
    
    ax.set_xlabel('Added CPU Usage (ns)', fontsize=16, fontweight='bold')
    ax.set_ylabel('Bandwidth (Mbps)', fontsize=16, fontweight='bold')
    ax.set_title('Bandwidth vs CPU Processing Overhead', fontsize=18, fontweight='bold', pad=20)
    ax.legend(title='Packet Size', fontsize=13, title_fontsize=13, loc='best', 
              ncol=2, framealpha=0.95)
    ax.grid(True, alpha=0.3, linestyle='--')
    
    # Format x-axis to show values nicely
    ax.tick_params(axis='both', labelsize=14)
    ax.ticklabel_format(style='plain', axis='x')
    
    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"✓ Saved: {output_file}")
    plt.close()

def plot_rtt_vs_cpu(data_by_packet_size, output_file, ebpf_delay_ns=None):
    """Plot RTT vs CPU usage for different packet sizes"""
    
    if not data_by_packet_size:
        print("No data to plot for RTT")
        return
    
    fig, ax = plt.subplots(figsize=(14, 8))
    
    # Color palette for different packet sizes
    packet_sizes_sorted = sorted(data_by_packet_size.keys())
    colors = plt.cm.viridis(np.linspace(0, 0.9, len(packet_sizes_sorted)))
    
    # Markers for different packet sizes
    markers = ['o', 's', '^', 'D', 'v', '<', '>', 'p', '*', 'h', 'X', 'd']
    
    for idx, packet_size in enumerate(packet_sizes_sorted):
        data = data_by_packet_size[packet_size]
        cpu_usage = [d['cpu_usage_ns'] for d in data]
        rtts = [d['rtt']/1000 for d in data]
        rtt_stds = [d['rtt_std']/1000 for d in data]
        
        # Skip if no valid RTT data
        if not any(r > 0 for r in rtts):
            continue
        
        color = colors[idx]
        marker = 'o' #markers[idx % len(markers)]
        
        # FIX: Use proper keyword arguments for color
        """
        ax.plot(cpu_usage, rtts,
                marker=marker,
                linestyle='-',
                color=color,
                label=f'{packet_size} bytes', 
                linewidth=2, 
                markersize=6)
        """
        ax.errorbar(cpu_usage, rtts, yerr=rtt_stds, linestyle='-',
                    marker=marker, markersize=6, linewidth=2, capsize=4,
                    label=f'{packet_size} bytes', color=color, alpha=0.85,
                    markeredgewidth=1.5, markeredgecolor='white')
    
    # Add vertical line for eBPF authentication delay
    if ebpf_delay_ns is not None:
        ax.axvline(x=ebpf_delay_ns, color='red', linestyle='--', linewidth=2.5, 
                   label=f'eBPF Auth Delay ({ebpf_delay_ns} ns)', zorder=1000)
        # Add text annotation
        y_pos = ax.get_ylim()[1] * 0.95
        ax.text(ebpf_delay_ns + 50, y_pos, f'eBPF Auth Overhead\n{ebpf_delay_ns} ns',
                color='red', fontsize=10, fontweight='bold',
                verticalalignment='top')
    
    ax.set_xlabel('Added CPU Usage (ns)', fontsize=16, fontweight='bold')
    #ax.set_ylabel('Round Trip Time (µs)', fontsize=14, fontweight='bold')
    ax.set_ylabel('Round Trip Time (ms)', fontsize=16, fontweight='bold')
    ax.set_title('RTT vs CPU Processing Overhead', fontsize=18, fontweight='bold', pad=20)
    ax.legend(title='Packet Size', fontsize=13, title_fontsize=13, loc='best',
              ncol=2, framealpha=0.95)
    ax.grid(True, alpha=0.3, linestyle='--')
    
    # Format x-axis to show values nicely
    ax.tick_params(axis='both', labelsize=14)
    ax.ticklabel_format(style='plain', axis='x')
    
    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"✓ Saved: {output_file}")
    plt.close()

def plot_combined(data_by_packet_size, output_file, ebpf_delay_ns=None):
    """Plot bandwidth and RTT in one figure with two subplots"""
    
    if not data_by_packet_size:
        return
    
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 12))
    
    # Color palette and markers
    packet_sizes_sorted = sorted(data_by_packet_size.keys())
    colors = plt.cm.viridis(np.linspace(0, 0.9, len(packet_sizes_sorted)))
    markers = ['o', 's', '^', 'D', 'v', '<', '>', 'p', '*', 'h', 'X', 'd']
    
    # Plot bandwidth
    for idx, packet_size in enumerate(packet_sizes_sorted):
        data = data_by_packet_size[packet_size]
        cpu_usage = [d['cpu_usage_ns'] for d in data]
        bandwidths = [d['bandwidth'] for d in data]
        bw_stds = [d['bw_std'] for d in data]
        
        if not any(b > 0 for b in bandwidths):
            continue
        
        color = colors[idx]
        marker = markers[idx % len(markers)]
        
        if packet_size >= 1024:
            label = f'{packet_size // 1024} KB'
        else:
            label = f'{packet_size} B'
        
        ax1.errorbar(cpu_usage, bandwidths, yerr=bw_stds,
                    marker=marker, markersize=7, linewidth=2.5, capsize=4,
                    label=label, color=color, alpha=0.85,
                    markeredgewidth=1.5, markeredgecolor='white')
    
    # Add eBPF delay line to bandwidth plot
    if ebpf_delay_ns is not None:
        ax1.axvline(x=ebpf_delay_ns, color='red', linestyle='--', linewidth=2.5,
                   label=f'eBPF Auth ({ebpf_delay_ns} ns)', zorder=1000)
        y_pos = ax1.get_ylim()[1] * 0.95
        ax1.text(ebpf_delay_ns + 50, y_pos, f'eBPF Auth\n{ebpf_delay_ns} ns',
                color='red', fontsize=9, fontweight='bold', verticalalignment='top')
    
    ax1.set_xlabel('Added CPU Usage (ns)', fontsize=13, fontweight='bold')
    ax1.set_ylabel('Bandwidth (Mbps)', fontsize=13, fontweight='bold')
    ax1.set_title('Bandwidth vs CPU Overhead', fontsize=14, fontweight='bold')
    ax1.legend(title='Packet Size', fontsize=9, title_fontsize=10, ncol=2, loc='best')
    ax1.grid(True, alpha=0.3, linestyle='--')
    ax1.ticklabel_format(style='plain', axis='x')
    
    # Plot RTT
    for idx, packet_size in enumerate(packet_sizes_sorted):
        data = data_by_packet_size[packet_size]
        cpu_usage = [d['cpu_usage_ns'] for d in data]
        rtts = [d['rtt'] for d in data]
        rtt_stds = [d['rtt_std'] for d in data]
        
        if not any(r > 0 for r in rtts):
            continue
        
        color = colors[idx]
        marker = markers[idx % len(markers)]
        
        if packet_size >= 1024:
            label = f'{packet_size // 1024} KB'
        else:
            label = f'{packet_size} B'
        
        ax2.errorbar(cpu_usage, rtts, yerr=rtt_stds,
                    marker=marker, markersize=7, linewidth=2.5, capsize=4,
                    label=label, color=color, alpha=0.85,
                    markeredgewidth=1.5, markeredgecolor='white')
    
    # Add eBPF delay line to RTT plot
    if ebpf_delay_ns is not None:
        ax2.axvline(x=ebpf_delay_ns, color='red', linestyle='--', linewidth=2.5,
                   label=f'eBPF Auth ({ebpf_delay_ns} ns)', zorder=1000)
        y_pos = ax2.get_ylim()[1] * 0.95
        ax2.text(ebpf_delay_ns + 50, y_pos, f'eBPF Auth\n{ebpf_delay_ns} ns',
                color='red', fontsize=9, fontweight='bold', verticalalignment='top')
    
    ax2.set_xlabel('Added CPU Usage (ns)', fontsize=13, fontweight='bold')
    ax2.set_ylabel('Round Trip Time ( \u00B5 s)', fontsize=13, fontweight='bold')
    ax2.set_title('RTT vs CPU Overhead', fontsize=14, fontweight='bold')
    ax2.legend(title='Packet Size', fontsize=9, title_fontsize=10, ncol=2, loc='best')
    ax2.grid(True, alpha=0.3, linestyle='--')
    ax2.ticklabel_format(style='plain', axis='x')
    
    plt.suptitle('Impact of CPU Processing Overhead on UDP Performance',
                fontsize=17, fontweight='bold', y=0.995)
    
    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"✓ Saved: {output_file}")
    plt.close()

def print_summary(data_by_packet_size, ns_per_loop):
    """Print summary statistics"""
    
    print("\n" + "="*70)
    print("SUMMARY - Artificial Delay Impact")
    print("="*70)
    print(f"CPU overhead per loop: {ns_per_loop} ns\n")
    
    for packet_size in sorted(data_by_packet_size.keys()):
        data = data_by_packet_size[packet_size]
        
        if not data:
            continue
        
        # Convert packet size to readable format
        if packet_size >= 1024:
            size_str = f'{packet_size // 1024} KB'
        else:
            size_str = f'{packet_size} B'
        
        print(f"Packet Size: {size_str} ({packet_size} bytes)")
        print("-" * 50)
        
        cpu_usages = [d['cpu_usage_ns'] for d in data]
        bandwidths = [d['bandwidth'] for d in data if d['bandwidth'] > 0]
        rtts = [d['rtt'] for d in data if d['rtt'] > 0]
        
        print(f"  CPU usage range: {min(cpu_usages)} - {max(cpu_usages)} ns")
        print(f"  Number of tests: {len(data)}")
        
        if bandwidths:
            bw_values = [d['bandwidth'] for d in data]
            min_bw_idx = bw_values.index(min(bandwidths))
            max_bw_idx = bw_values.index(max(bandwidths))
            
            print(f"  Bandwidth:")
            print(f"    Min: {min(bandwidths):.2f} Mbps (at {data[min_bw_idx]['cpu_usage_ns']} ns)")
            print(f"    Max: {max(bandwidths):.2f} Mbps (at {data[max_bw_idx]['cpu_usage_ns']} ns)")
            if len(bandwidths) > 1 and max(bandwidths) > 0:
                degradation = ((max(bandwidths) - min(bandwidths)) / max(bandwidths)) * 100
                print(f"    Degradation: {degradation:.1f}%")
        
        if rtts:
            print(f"  RTT:")
            print(f"    Min: {min(rtts):.3f} \u00B5 s")
            print(f"    Max: {max(rtts):.3f} \u00B5 s")
            if len(rtts) > 1 and min(rtts) > 0:
                increase = ((max(rtts) - min(rtts)) / min(rtts)) * 100
                print(f"    Increase: {increase:.1f}%")
        
        print()

def main():
    parser = argparse.ArgumentParser(
        description="Plot artificial delay results vs CPU usage",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
  python3 plot_art_delay_cpu.py udp_benchmark_results.json
  python3 plot_art_delay_cpu.py results.json --ns-per-loop 9 -o my_results
  python3 plot_art_delay_cpu.py results.json --ebpf-delay 2600
        """
    )
    
    parser.add_argument("json_file", help="JSON results file")
    parser.add_argument("--ns-per-loop", type=float, default=90.0,
                       help="Nanoseconds added per loop iteration (default: 90)")
    parser.add_argument("--ebpf-delay", type=float, default=2600.0,
                       help="eBPF authentication delay in ns (default: 2600)")
    parser.add_argument("--output-prefix", "-o", default=None,
                       help="Output file prefix (default: based on input filename)")
    
    args = parser.parse_args()
    
    # Load results
    print(f"Loading results from: {args.json_file}")
    results = load_results(args.json_file)
    
    # Extract data
    print(f"Extracting artificial delay data (CPU overhead: {args.ns_per_loop} ns per loop)...")
    data_by_packet_size = extract_art_delay_data(results, args.ns_per_loop)
    
    if not data_by_packet_size:
        print("Error: No artificial delay data found in results")
        sys.exit(1)
    
    print(f"\nFound data for {len(data_by_packet_size)} packet size(s):")
    for packet_size in sorted(data_by_packet_size.keys()):
        if packet_size >= 1024:
            print(f"  - {packet_size // 1024} KB ({packet_size} bytes): {len(data_by_packet_size[packet_size])} data points")
        else:
            print(f"  - {packet_size} B: {len(data_by_packet_size[packet_size])} data points")
    
    # Determine output prefix
    if args.output_prefix:
        prefix = args.output_prefix
    else:
        prefix = args.json_file.replace('.json', '_art_delay_cpu')
    
    # Generate plots
    print("\nGenerating plots...")
    plot_bandwidth_vs_cpu(data_by_packet_size, f"bandwidth_comparison_art.png", args.ebpf_delay)
    plot_rtt_vs_cpu(data_by_packet_size, f"rtt_comparison_art.png", args.ebpf_delay)
    plot_combined(data_by_packet_size, f"combined_comparison_art.png", args.ebpf_delay)
    
    # Print summary
    print_summary(data_by_packet_size, args.ns_per_loop)
    print("="*70)
    print("COMPLETE!")
    print("="*70)
    print(f"\nGenerated plots:")
    print(f"  - {prefix}_bandwidth.png")
    print(f"  - {prefix}_rtt.png")
    print(f"  - {prefix}_combined.png")
    print(f"\neBPF authentication delay marked at {args.ebpf_delay} ns")

if __name__ == "__main__":
    main()
