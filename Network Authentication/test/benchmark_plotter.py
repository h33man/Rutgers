#!/usr/bin/env python3
"""
eBPF Benchmark Results Plotter

Creates performance comparison charts for four authentication methods:
1. Bandwidth vs Packet Size comparison
2. RTT vs Packet Size comparison  
3. Performance impact analysis
"""

import json
import matplotlib.pyplot as plt
import numpy as np
import argparse
import sys
from pathlib import Path
from typing import Dict, List, Tuple

class BenchmarkPlotter:
    def __init__(self, results_file: str):
        self.results_file = results_file
        self.results = None
        self.packet_sizes = None
        
        # Color scheme
        self.colors = {
            'no_auth': '#87CEEB',      # Light blue
            'ebpf_auth': '#DDA0DD',    # Plum
            'kernel_auth': '#F0B6C1',  # Light pink
            'chacha_auth': '#98FB98'   # Pale green
        }
        
        # Style settings
        plt.rcParams.update({
            'font.size': 12,
            'axes.titlesize': 14,
            'axes.labelsize': 12,
            'xtick.labelsize': 10,
            'ytick.labelsize': 10,
            'legend.fontsize': 11,
            'figure.titlesize': 16
        })
    
    def load_results(self) -> bool:
        """Load benchmark results from JSON file."""
        try:
            with open(self.results_file, 'r') as f:
                data = json.load(f)
            
            self.results = data.get('results', data)
            
            # Extract packet sizes from the data
            if 'no_auth' in self.results and 'bandwidth' in self.results['no_auth']:
                self.packet_sizes = sorted([int(k) for k in self.results['no_auth']['bandwidth'].keys()])
            else:
                print("Error: Invalid results file format")
                return False
            
            print(f"Loaded results from {self.results_file}")
            print(f"Found data for {len(self.packet_sizes)} packet sizes: {self.packet_sizes}")
            return True
            
        except FileNotFoundError:
            print(f"Error: Results file '{self.results_file}' not found")
            return False
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in results file: {e}")
            return False
        except Exception as e:
            print(f"Error loading results: {e}")
            return False
    
    def extract_data_arrays(self, test_type: str, metric: str) -> np.array:
        """Extract data array for given test type and metric."""
        if test_type not in self.results or metric not in self.results[test_type]:
            return np.zeros(len(self.packet_sizes))
        
        data = []
        for size in self.packet_sizes:
            value = self.results[test_type][metric].get(str(size), 0)
            data.append(value)
        
        return np.array(data)
    
    def plot_bandwidth_comparison(self) -> plt.Figure:
        """Create bandwidth comparison plot with four phases using log scale and error bars."""
        fig, ax = plt.subplots(figsize=(14, 8))
        
        # Extract data for all four phases
        no_auth_bw = self.extract_data_arrays('no_auth', 'bandwidth')
        ebpf_auth_bw = self.extract_data_arrays('ebpf_auth', 'bandwidth')
        kernel_auth_bw = self.extract_data_arrays('kernel_auth', 'bandwidth')
        chacha_auth_bw = self.extract_data_arrays('chacha_auth', 'bandwidth')
        
        # Extract standard deviations
        no_auth_std = self.extract_data_arrays('no_auth', 'bandwidth_std')
        ebpf_auth_std = self.extract_data_arrays('ebpf_auth', 'bandwidth_std')
        kernel_auth_std = self.extract_data_arrays('kernel_auth', 'bandwidth_std')
        chacha_auth_std = self.extract_data_arrays('chacha_auth', 'bandwidth_std')
        
        # Convert packet sizes to log2 for equal spacing
        x_positions = np.arange(len(self.packet_sizes))
        width = 0.15 # Adjusted for 4 bars
        
        # Create bars for four phases with error bars
        bars1 = ax.bar(x_positions - 1.5*width, no_auth_bw, width,
                      yerr=no_auth_std, label='No Authentication', 
                      color=self.colors['no_auth'], alpha=0.8, edgecolor='black', 
                      linewidth=0.5, capsize=5, error_kw={'linewidth': 1.5, 'ecolor': 'gray'})
        
        bars2 = ax.bar(x_positions - 0.5*width, ebpf_auth_bw, width,
                      yerr=ebpf_auth_std, label='eBPF SHA-256 Auth',
                      color=self.colors['ebpf_auth'], alpha=0.8, edgecolor='black', 
                      linewidth=0.5, capsize=5, error_kw={'linewidth': 1.5, 'ecolor': 'gray'})
        
        bars3 = ax.bar(x_positions + 0.5*width, kernel_auth_bw, width,
<<<<<<< HEAD
                      yerr=kernel_auth_std, label='Kernel Authentication',
=======
                      yerr=kernel_auth_std, label='Kernel SHA-256 Auth',
>>>>>>> 03ddeb4 (Adde Chacha20 kernel module)
                      color=self.colors['kernel_auth'], alpha=0.8, edgecolor='black', 
                      linewidth=0.5, capsize=5, error_kw={'linewidth': 1.5, 'ecolor': 'gray'})

        bars4 = ax.bar(x_positions + 1.5*width, chacha_auth_bw, width,
<<<<<<< HEAD
                      yerr=chacha_auth_std, label='Chacha Authentication',
=======
                      yerr=chacha_auth_std, label='Kernel Chacha20 Auth',
>>>>>>> 03ddeb4 (Adde Chacha20 kernel module)
                      color=self.colors['chacha_auth'], alpha=0.8, edgecolor='black', 
                      linewidth=0.5, capsize=5, error_kw={'linewidth': 1.5, 'ecolor': 'gray'})
        
        # Customize plot
        ax.set_xlabel('Packet Size (bytes)', fontweight='bold')
        ax.set_ylabel('Bandwidth (Mbps)', fontweight='bold')
        ax.set_title('Bandwidth Vs Packet Size', fontweight='bold', pad=20)
        
        # Set x-axis labels with logarithmic spacing
        ax.set_xticks(x_positions)
        ax.set_xticklabels([str(size) for size in self.packet_sizes])
        
        # Add legend
        ax.legend(loc='upper left', framealpha=0.9)
        
        # Add grid
        ax.grid(True, alpha=0.3, linestyle='-', linewidth=0.5, axis='y')
        ax.set_axisbelow(True)
        ax.set_ylim(bottom=0)
        
        plt.tight_layout()
        return fig
    
    def plot_rtt_comparison2(self) -> plt.Figure:
        """Create RTT comparison plot with four phases using log scale and error bars."""
        fig, ax = plt.subplots(figsize=(14, 8))
        
        # Extract data for all four phases
        no_auth_rtt = self.extract_data_arrays('no_auth', 'rtt')
        ebpf_auth_rtt = self.extract_data_arrays('ebpf_auth', 'rtt')
        kernel_auth_rtt = self.extract_data_arrays('kernel_auth', 'rtt')
        chacha_auth_rtt = self.extract_data_arrays('chacha_auth', 'rtt')
        
        # Extract standard deviations
        no_auth_std = self.extract_data_arrays('no_auth', 'rtt_std')
        ebpf_auth_std = self.extract_data_arrays('ebpf_auth', 'rtt_std')
        kernel_auth_std = self.extract_data_arrays('kernel_auth', 'rtt_std')
        chacha_auth_std = self.extract_data_arrays('chacha_auth', 'rtt_std')
        
        x_positions = np.arange(len(self.packet_sizes))
        width = 0.15 # Adjusted for 4 bars
        
        # Create bars
        bars1 = ax.bar(x_positions - 1.5*width, no_auth_rtt, width,
                      yerr=no_auth_std, label='No Authentication', 
                      color=self.colors['no_auth'], alpha=0.8, edgecolor='black', 
                      linewidth=0.5, capsize=5, error_kw={'linewidth': 1.5, 'ecolor': 'gray'})
        
        bars2 = ax.bar(x_positions - 0.5*width, ebpf_auth_rtt, width,
                      yerr=ebpf_auth_std, label='eBPF SHA-256 Auth',
                      color=self.colors['ebpf_auth'], alpha=0.8, edgecolor='black', 
                      linewidth=0.5, capsize=5, error_kw={'linewidth': 1.5, 'ecolor': 'gray'})
        
        bars3 = ax.bar(x_positions + 0.5*width, kernel_auth_rtt, width,
<<<<<<< HEAD
                      yerr=kernel_auth_std, label='Kernel Authentication',
=======
                      yerr=kernel_auth_std, label='Kernel SHA-256 Auth',
>>>>>>> 03ddeb4 (Adde Chacha20 kernel module)
                      color=self.colors['kernel_auth'], alpha=0.8, edgecolor='black', 
                      linewidth=0.5, capsize=5, error_kw={'linewidth': 1.5, 'ecolor': 'gray'})

        bars4 = ax.bar(x_positions + 1.5*width, chacha_auth_rtt, width,
<<<<<<< HEAD
                      yerr=chacha_auth_std, label='Chacha Authentication',
=======
                      yerr=chacha_auth_std, label='Kernel Chacha20 Auth',
>>>>>>> 03ddeb4 (Adde Chacha20 kernel module)
                      color=self.colors['chacha_auth'], alpha=0.8, edgecolor='black', 
                      linewidth=0.5, capsize=5, error_kw={'linewidth': 1.5, 'ecolor': 'gray'})
        
        # Customize plot
        ax.set_xlabel('Packet Size (bytes)', fontweight='bold')
        ax.set_ylabel('Round Trip Time (ms)', fontweight='bold')
        ax.set_title('Round Trip Time Vs Packet Size', fontweight='bold', pad=20)
        
        # Set x-axis labels with logarithmic spacing
        ax.set_xticks(x_positions)
        ax.set_xticklabels([str(size) for size in self.packet_sizes])
        
        # Add legend
        ax.legend(loc='upper left', framealpha=0.9)
        
        # Add grid
        ax.grid(True, alpha=0.3, linestyle='-', linewidth=0.5, axis='y')
        ax.set_axisbelow(True)
        ax.set_ylim(bottom=0)
        
        plt.tight_layout()
        return fig

    def plot_rtt_comparison(self) -> plt.Figure:
        """Create RTT comparison plot for four phases with log x-scale but clean numeric labels."""
        fig, ax = plt.subplots(figsize=(14, 8))

        # Extract RTT data
        no_auth_rtt = self.extract_data_arrays('no_auth', 'rtt')
        ebpf_auth_rtt = self.extract_data_arrays('ebpf_auth', 'rtt')
        kernel_auth_rtt = self.extract_data_arrays('kernel_auth', 'rtt')
        chacha_auth_rtt = self.extract_data_arrays('chacha_auth', 'rtt')
<<<<<<< HEAD
=======

        # Extract standard deviations
        no_auth_std = self.extract_data_arrays('no_auth', 'rtt_std')
        ebpf_auth_std = self.extract_data_arrays('ebpf_auth', 'rtt_std')
        kernel_auth_std = self.extract_data_arrays('kernel_auth', 'rtt_std')
        chacha_auth_std = self.extract_data_arrays('chacha_auth', 'rtt_std')
>>>>>>> 03ddeb4 (Adde Chacha20 kernel module)

        # X labels
        x_labels = [str(size) for size in self.packet_sizes]

        # Error bar kwargs — consistent with bandwidth plot style
        eb_kw = dict(linewidth=1.5, ecolor='gray')
        
<<<<<<< HEAD
        # Line plot for RTT
        ax.plot(self.packet_sizes, no_auth_rtt, 'o-', 
               linewidth=2.5, markersize=8, label='No Authentication', 
               color='#4169E1', alpha=0.8)
        
        ax.plot(self.packet_sizes, ebpf_auth_rtt, 's-', 
               linewidth=2.5, markersize=8, label='eBPF SHA-256 Auth', 
               color='#DC143C', alpha=0.8)
        
        ax.plot(self.packet_sizes, kernel_auth_rtt, '^-',
               linewidth=2.5, markersize=8, label='Kernel Authentication',
               color='#FF8C00', alpha=0.8)
=======
        # Line plot for RTT with error bars
        ax.errorbar(self.packet_sizes, no_auth_rtt, yerr=no_auth_std,
               fmt='o-', linewidth=2.5, markersize=8, label='No Authentication',
               color='#4169E1', alpha=0.8, capsize=5, capthick=1.5,
               elinewidth=1.5, ecolor='gray')

        ax.errorbar(self.packet_sizes, ebpf_auth_rtt, yerr=ebpf_auth_std,
               fmt='s-', linewidth=2.5, markersize=8, label='eBPF SHA-256 Auth',
               color='#DC143C', alpha=0.8, capsize=5, capthick=1.5,
               elinewidth=1.5, ecolor='gray')

        ax.errorbar(self.packet_sizes, kernel_auth_rtt, yerr=kernel_auth_std,
               fmt='^-', linewidth=2.5, markersize=8, label='Kernel SHA-256 Auth',
               color='#FF8C00', alpha=0.8, capsize=5, capthick=1.5,
               elinewidth=1.5, ecolor='gray')

        ax.errorbar(self.packet_sizes, chacha_auth_rtt, yerr=chacha_auth_std,
               fmt='d-', linewidth=2.5, markersize=8, label='Kernel Chacha20 Auth',
               color='#32CD32', alpha=0.8, capsize=5, capthick=1.5,
               elinewidth=1.5, ecolor='gray') # LimeGreen
>>>>>>> 03ddeb4 (Adde Chacha20 kernel module)

        ax.plot(self.packet_sizes, chacha_auth_rtt, 'd-',
               linewidth=2.5, markersize=8, label='Chacha Authentication',
               color='#32CD32', alpha=0.8) # LimeGreen

        # Customize plot
        ax.set_xlabel('Packet Size (bytes)', fontweight='bold')
        ax.set_ylabel('Round Trip Time (ms)', fontweight='bold')
        ax.set_title('Round Trip Time Vs Packet Size', fontweight='bold', pad=20)

        # Logarithmic X-scale, but pretty labels
        ax.set_xscale('log')
        ax.set_xticks(self.packet_sizes)
        ax.set_xticklabels(x_labels)

        # Add legend
        ax.legend(loc='best', framealpha=0.9)

        # Grid and formatting
        ax.grid(True, alpha=0.3, linestyle='-', linewidth=0.5)
        ax.set_axisbelow(True)
        ax.set_ylim(bottom=0)

        plt.tight_layout()
        return fig
    
    def plot_performance_impact(self) -> plt.Figure:
        """Create performance impact analysis plot comparing all phases with log scale."""
        fig, ((ax1, ax2), (ax3, ax4), (ax5, ax6)) = plt.subplots(3, 2, figsize=(16, 18))
        
        # Extract data for all phases
        no_auth_bw = self.extract_data_arrays('no_auth', 'bandwidth')
        ebpf_auth_bw = self.extract_data_arrays('ebpf_auth', 'bandwidth')
        kernel_auth_bw = self.extract_data_arrays('kernel_auth', 'bandwidth')
        chacha_auth_bw = self.extract_data_arrays('chacha_auth', 'bandwidth')
        
        no_auth_rtt = self.extract_data_arrays('no_auth', 'rtt')
        ebpf_auth_rtt = self.extract_data_arrays('ebpf_auth', 'rtt')
        kernel_auth_rtt = self.extract_data_arrays('kernel_auth', 'rtt')
        chacha_auth_rtt = self.extract_data_arrays('chacha_auth', 'rtt')
        
        # Calculate impacts
        ebpf_bw_impact = np.where(no_auth_bw > 0, ((no_auth_bw - ebpf_auth_bw) / no_auth_bw) * 100, 0)
        ebpf_rtt_impact = np.where(no_auth_rtt > 0, ((ebpf_auth_rtt - no_auth_rtt) / no_auth_rtt) * 100, 0)
        
        kernel_bw_impact = np.where(no_auth_bw > 0, ((no_auth_bw - kernel_auth_bw) / no_auth_bw) * 100, 0)
        kernel_rtt_impact = np.where(no_auth_rtt > 0, ((kernel_auth_rtt - no_auth_rtt) / no_auth_rtt) * 100, 0)

        chacha_bw_impact = np.where(no_auth_bw > 0, ((no_auth_bw - chacha_auth_bw) / no_auth_bw) * 100, 0)
        chacha_rtt_impact = np.where(no_auth_rtt > 0, ((chacha_auth_rtt - no_auth_rtt) / no_auth_rtt) * 100, 0)
        
        # Plot 1: eBPF Bandwidth Impact
        ax1.plot(self.packet_sizes, ebpf_bw_impact, 'o-', linewidth=2.5, markersize=8, color=self.colors['ebpf_auth'], alpha=0.8)
        ax1.set_xscale('log')
        ax1.set_xticks(self.packet_sizes)
        ax1.set_xticklabels([str(size) for size in self.packet_sizes])
        ax1.set_title('eBPF: Bandwidth Overhead vs Baseline', fontweight='bold')
        ax1.set_ylabel('Overhead (%)')
        ax1.grid(True, alpha=0.3)
        ax1.axhline(y=0, color='black', linestyle='-', linewidth=1, alpha=0.5)
        
        # Plot 2: Kernel Bandwidth Impact
        ax2.plot(self.packet_sizes, kernel_bw_impact, 's-', linewidth=2.5, markersize=8, color=self.colors['kernel_auth'], alpha=0.8)
        ax2.set_xscale('log')
        ax2.set_xticks(self.packet_sizes)
        ax2.set_xticklabels([str(size) for size in self.packet_sizes])
        ax2.set_title('Kernel: Bandwidth Overhead vs Baseline', fontweight='bold')
        ax2.set_ylabel('Overhead (%)')
        ax2.grid(True, alpha=0.3)
        ax2.axhline(y=0, color='black', linestyle='-', linewidth=1, alpha=0.5)
        
        # Plot 3: eBPF RTT Impact
        ax3.plot(self.packet_sizes, ebpf_rtt_impact, 'o-', linewidth=2.5, markersize=8, color=self.colors['ebpf_auth'], alpha=0.8)
        ax3.set_xscale('log')
        ax3.set_xticks(self.packet_sizes)
        ax3.set_xticklabels([str(size) for size in self.packet_sizes])
        ax3.set_title('eBPF: RTT Overhead vs Baseline', fontweight='bold')
        ax3.set_ylabel('Overhead (%)')
        ax3.grid(True, alpha=0.3)
        ax3.axhline(y=0, color='black', linestyle='-', linewidth=1, alpha=0.5)
        
        # Plot 4: Kernel RTT Impact
        ax4.plot(self.packet_sizes, kernel_rtt_impact, 's-', linewidth=2.5, markersize=8, color=self.colors['kernel_auth'], alpha=0.8)
        ax4.set_xscale('log')
        ax4.set_xticks(self.packet_sizes)
        ax4.set_xticklabels([str(size) for size in self.packet_sizes])
        ax4.set_title('Kernel: RTT Overhead vs Baseline', fontweight='bold')
        ax4.set_ylabel('Overhead (%)')
        ax4.grid(True, alpha=0.3)
        ax4.axhline(y=0, color='black', linestyle='-', linewidth=1, alpha=0.5)

        # Plot 5: Chacha Bandwidth Impact
        ax5.plot(self.packet_sizes, chacha_bw_impact, 'd-', linewidth=2.5, markersize=8, color=self.colors['chacha_auth'], alpha=0.8)
        ax5.set_xscale('log')
        ax5.set_xticks(self.packet_sizes)
        ax5.set_xticklabels([str(size) for size in self.packet_sizes])
        ax5.set_title('Chacha: Bandwidth Overhead vs Baseline', fontweight='bold')
        ax5.set_xlabel('Packet Size (bytes)')
        ax5.set_ylabel('Overhead (%)')
        ax5.grid(True, alpha=0.3)
        ax5.axhline(y=0, color='black', linestyle='-', linewidth=1, alpha=0.5)

        # Plot 6: Chacha RTT Impact
        ax6.plot(self.packet_sizes, chacha_rtt_impact, 'd-', linewidth=2.5, markersize=8, color=self.colors['chacha_auth'], alpha=0.8)
        ax6.set_xscale('log')
        ax6.set_xticks(self.packet_sizes)
        ax6.set_xticklabels([str(size) for size in self.packet_sizes])
        ax6.set_title('Chacha: RTT Overhead vs Baseline', fontweight='bold')
        ax6.set_xlabel('Packet Size (bytes)')
        ax6.set_ylabel('Overhead (%)')
        ax6.grid(True, alpha=0.3)
        ax6.axhline(y=0, color='black', linestyle='-', linewidth=1, alpha=0.5)
        
        plt.tight_layout()
        return fig
    
    def create_all_plots(self, output_dir: str = "/tmp/plots") -> None:
        """Create all plots and save them."""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        print(f"Creating performance comparison plots...")
        
        print("  Creating bandwidth comparison plot...")
        fig1 = self.plot_bandwidth_comparison()
        fig1.savefig(output_path / "bandwidth_comparison.png", dpi=300, bbox_inches='tight')
        plt.close(fig1)
        
        print("  Creating RTT comparison plot...")
        fig2 = self.plot_rtt_comparison()
        fig2.savefig(output_path / "rtt_comparison.png", dpi=300, bbox_inches='tight')
        plt.close(fig2)
        fig3 = self.plot_rtt_comparison2()
        fig3.savefig(output_path / "rtt_comparison2.png", dpi=300, bbox_inches='tight')
        plt.close(fig3)
        
        print("  Creating performance impact analysis...")
        fig4 = self.plot_performance_impact()
        fig4.savefig(output_path / "performance_impact.png", dpi=300, bbox_inches='tight')
        plt.close(fig4)
        
        print("  Generating summary report...")
        summary = self.generate_summary_report()
        with open(output_path / "performance_summary.txt", 'w') as f:
            f.write(summary)
        
        print(f"\nAll plots saved to '{output_dir}/' directory")

    def generate_summary_report(self) -> str:
        """Generate a text summary of the performance impact for all phases."""
        no_auth_bw = self.extract_data_arrays('no_auth', 'bandwidth')
        ebpf_auth_bw = self.extract_data_arrays('ebpf_auth', 'bandwidth')
        kernel_auth_bw = self.extract_data_arrays('kernel_auth', 'bandwidth')
        chacha_auth_bw = self.extract_data_arrays('chacha_auth', 'bandwidth')
        
        no_auth_rtt = self.extract_data_arrays('no_auth', 'rtt')
        ebpf_auth_rtt = self.extract_data_arrays('ebpf_auth', 'rtt')
        kernel_auth_rtt = self.extract_data_arrays('kernel_auth', 'rtt')
        chacha_auth_rtt = self.extract_data_arrays('chacha_auth', 'rtt')
        
        report = []
        report.append("=" * 90)
        report.append("UDP BENCHMARK PERFORMANCE SUMMARY - FOUR AUTHENTICATION METHODS")
        report.append("=" * 90)
        
        # Overall bandwidth comparison
        report.append("\nBANDWIDTH ANALYSIS (Mbps):")
        report.append("-" * 90)
        
        if len(no_auth_bw[no_auth_bw > 0]) > 0:
            avg_no_auth_bw = np.mean(no_auth_bw[no_auth_bw > 0])
            avg_ebpf_bw = np.mean(ebpf_auth_bw[ebpf_auth_bw > 0]) if len(ebpf_auth_bw[ebpf_auth_bw > 0]) > 0 else 0
            avg_kernel_bw = np.mean(kernel_auth_bw[kernel_auth_bw > 0]) if len(kernel_auth_bw[kernel_auth_bw > 0]) > 0 else 0
            avg_chacha_bw = np.mean(chacha_auth_bw[chacha_auth_bw > 0]) if len(chacha_auth_bw[chacha_auth_bw > 0]) > 0 else 0
            
            report.append(f"Baseline (No Auth):         {avg_no_auth_bw:>8.2f} Mbps (reference)")
            if avg_ebpf_bw > 0:
                report.append(f"eBPF Authentication:       {avg_ebpf_bw:>8.2f} Mbps ({(1 - avg_ebpf_bw/avg_no_auth_bw)*100:>6.1f}% overhead)")
            if avg_kernel_bw > 0:
<<<<<<< HEAD
                report.append(f"Kernel Authentication:     {avg_kernel_bw:>8.2f} Mbps ({(1 - avg_kernel_bw/avg_no_auth_bw)*100:>6.1f}% overhead)")
            if avg_chacha_bw > 0:
                report.append(f"Chacha Authentication:     {avg_chacha_bw:>8.2f} Mbps ({(1 - avg_chacha_bw/avg_no_auth_bw)*100:>6.1f}% overhead)")
=======
                report.append(f"Kernel SHA-256 Auth:     {avg_kernel_bw:>8.2f} Mbps ({(1 - avg_kernel_bw/avg_no_auth_bw)*100:>6.1f}% overhead)")
            if avg_chacha_bw > 0:
                report.append(f"Kernel Chacha20 Auth:     {avg_chacha_bw:>8.2f} Mbps ({(1 - avg_chacha_bw/avg_no_auth_bw)*100:>6.1f}% overhead)")
>>>>>>> 03ddeb4 (Adde Chacha20 kernel module)
        
        # Overall RTT comparison
        report.append("\nROUND TRIP TIME ANALYSIS (ms):")
        report.append("-" * 90)
        
        if len(no_auth_rtt[no_auth_rtt > 0]) > 0:
            avg_no_auth_rtt = np.mean(no_auth_rtt[no_auth_rtt > 0])
            avg_ebpf_rtt = np.mean(ebpf_auth_rtt[ebpf_auth_rtt > 0]) if len(ebpf_auth_rtt[ebpf_auth_rtt > 0]) > 0 else 0
            avg_kernel_rtt = np.mean(kernel_auth_rtt[kernel_auth_rtt > 0]) if len(kernel_auth_rtt[kernel_auth_rtt > 0]) > 0 else 0
            avg_chacha_rtt = np.mean(chacha_auth_rtt[chacha_auth_rtt > 0]) if len(chacha_auth_rtt[chacha_auth_rtt > 0]) > 0 else 0

            report.append(f"Baseline (No Auth):         {avg_no_auth_rtt:>8.3f} ms (reference)")
            if avg_ebpf_rtt > 0:
                report.append(f"eBPF Authentication:       {avg_ebpf_rtt:>8.3f} ms ({(avg_ebpf_rtt/avg_no_auth_rtt - 1)*100:>6.1f}% overhead)")
            if avg_kernel_rtt > 0:
<<<<<<< HEAD
                report.append(f"Kernel Authentication:     {avg_kernel_rtt:>8.3f} ms ({(avg_kernel_rtt/avg_no_auth_rtt - 1)*100:>6.1f}% overhead)")
            if avg_chacha_rtt > 0:
                report.append(f"Chacha Authentication:     {avg_chacha_rtt:>8.3f} ms ({(avg_chacha_rtt/avg_no_auth_rtt - 1)*100:>6.1f}% overhead)")
=======
                report.append(f"Kernel SHA-256 Auth:     {avg_kernel_rtt:>8.3f} ms ({(avg_kernel_rtt/avg_no_auth_rtt - 1)*100:>6.1f}% overhead)")
            if avg_chacha_rtt > 0:
                report.append(f"Kernel Chacha20 Auth:     {avg_chacha_rtt:>8.3f} ms ({(avg_chacha_rtt/avg_no_auth_rtt - 1)*100:>6.1f}% overhead)")
>>>>>>> 03ddeb4 (Adde Chacha20 kernel module)
        
        # Detailed breakdown
        report.append("\n" + "=" * 90)
        report.append("DETAILED BREAKDOWN BY PACKET SIZE:")
        report.append("=" * 90)
        report.append(f"{'Size':<8} {'No Auth':<10} {'eBPF':<10} {'Kernel':<10} {'Chacha':<10} {'eBPF RTT':<10} {'K RTT':<10} {'C RTT':<10}")
        report.append(f"{'(B)':<8} {'(Mbps)':<10} {'(Mbps)':<10} {'(Mbps)':<10} {'(Mbps)':<10} {'(ms)':<10} {'(ms)':<10} {'(ms)':<10}")
        report.append("-" * 90)
        
        for i, size in enumerate(self.packet_sizes):
            report.append(f"{size:<8} {no_auth_bw[i]:>8.2f}  {ebpf_auth_bw[i]:>8.2f}  {kernel_auth_bw[i]:>8.2f}  {chacha_auth_bw[i]:>8.2f}  {ebpf_auth_rtt[i]:>8.3f}  {kernel_auth_rtt[i]:>8.3f}  {chacha_auth_rtt[i]:>8.3f}")
        
        return "\n".join(report)

def main():
    parser = argparse.ArgumentParser(
        description="Plot eBPF benchmark results for four authentication methods",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python benchmark_plotter.py udp_benchmark_results.json
  python benchmark_plotter.py results.json --output-dir my_plots
  python benchmark_plotter.py results.json --show-summary
        """
    )
    
    parser.add_argument("results_file", 
                       help="JSON file containing benchmark results")
    parser.add_argument("--output-dir", "-o", default="plots",
                       help="Output directory for plots (default: plots)")
    parser.add_argument("--show-summary", "-s", action="store_true",
                       help="Print performance summary to console")
    
    args = parser.parse_args()
    
    if not Path(args.results_file).exists():
        print(f"Error: Results file '{args.results_file}' not found")
        sys.exit(1)
    
    plotter = BenchmarkPlotter(args.results_file)
    
    if not plotter.load_results():
        sys.exit(1)
    
    plotter.create_all_plots(args.output_dir)
    
    if args.show_summary:
        print(f"\n{plotter.generate_summary_report()}")

if __name__ == "__main__":
    main()
