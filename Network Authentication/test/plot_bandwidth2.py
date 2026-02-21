#!/usr/bin/env python3
"""
Plot bandwidth distribution from sockperf results
Creates histograms showing percentage of samples in buckets
Supports multiple packet sizes in one file
"""

import json
import argparse
import matplotlib.pyplot as plt
import numpy as np
from typing import List, Dict, Tuple
import math

class BandwidthPlotter:
    def __init__(self, input_file: str, bucket_size: int = 10):
        self.input_file = input_file
        self.bucket_size = bucket_size
        self.datasets = []  # List of datasets, one per packet size
        
    def load_data(self) -> bool:
        """Load bandwidth data from JSON file - supports multiple test results"""
        try:
            with open(self.input_file, 'r') as f:
                content = f.read()
            
            # Try to parse as array of results first
            try:
                data = json.loads(content)
                
                # Check if it's a single test result or array of results
                if isinstance(data, dict) and 'test_info' in data:
                    # Single test result
                    self.datasets = [data]
                elif isinstance(data, list):
                    # Array of test results
                    self.datasets = data
                else:
                    print("Error: Unexpected JSON structure")
                    return False
                    
            except json.JSONDecodeError:
                # Try to parse multiple JSON objects separated by newlines or closing/opening braces
                # Handle format like: {...}{...}{...}
                json_objects = []
                
                # Split by }{ pattern and reconstruct valid JSON
                parts = content.replace('}\n{', '}\nSPLIT\n{').replace('}{', '}\nSPLIT\n{').split('SPLIT')
                
                for part in parts:
                    part = part.strip()
                    if part:
                        try:
                            obj = json.loads(part)
                            if 'test_info' in obj and 'bandwidth_samples' in obj:
                                json_objects.append(obj)
                        except:
                            continue
                
                if not json_objects:
                    print("Error: Could not parse JSON file")
                    return False
                
                self.datasets = json_objects
            
            # Validate datasets
            valid_datasets = []
            for i, dataset in enumerate(self.datasets):
                if 'bandwidth_samples' not in dataset:
                    print(f"Warning: Dataset {i} missing bandwidth_samples, skipping")
                    continue
                if 'test_info' not in dataset:
                    print(f"Warning: Dataset {i} missing test_info, skipping")
                    continue
                valid_datasets.append(dataset)
            
            self.datasets = valid_datasets
            
            if not self.datasets:
                print("Error: No valid datasets found")
                return False
            
            print(f"Loaded {len(self.datasets)} test result(s)")
            for i, dataset in enumerate(self.datasets):
                msg_size = dataset['test_info'].get('msg_size', 'N/A')
                sample_count = len(dataset['bandwidth_samples'])
                print(f"  Dataset {i+1}: {sample_count} samples, packet size: {msg_size} bytes")
            
            return True
            
        except FileNotFoundError:
            print(f"Error: File '{self.input_file}' not found")
            return False
        except Exception as e:
            print(f"Error loading file: {e}")
            return False
    
    def extract_bandwidth_values(self, dataset: Dict) -> Tuple[List[float], Dict]:
        """Extract bandwidth values and test info from a dataset"""
        bandwidths = []
        
        for sample in dataset['bandwidth_samples']:
            if 'bandwidth_mbps' in sample and sample['bandwidth_mbps'] > 0:
                bandwidths.append(sample['bandwidth_mbps'])
        
        return bandwidths, dataset.get('test_info', {})
    
    def create_buckets(self, bandwidths: List[float]) -> Dict:
        """Create bandwidth buckets and calculate percentages"""
        if not bandwidths:
            return {}
        
        min_bw = min(bandwidths)
        max_bw = max(bandwidths)
        
        # Calculate bucket range
        min_bucket = int(min_bw // self.bucket_size) * self.bucket_size
        max_bucket = int(max_bw // self.bucket_size) * self.bucket_size + self.bucket_size
        
        # Create buckets
        buckets = {}
        bucket_start = min_bucket
        
        while bucket_start <= max_bucket:
            bucket_end = bucket_start + self.bucket_size
            bucket_label = f"{bucket_start}-{bucket_end}"
            buckets[bucket_label] = {
                'start': bucket_start,
                'end': bucket_end,
                'count': 0,
                'samples': []
            }
            bucket_start += self.bucket_size
        
        # Assign samples to buckets
        total_samples = len(bandwidths)
        
        for bw in bandwidths:
            bucket_start = int(bw // self.bucket_size) * self.bucket_size
            bucket_label = f"{bucket_start}-{bucket_start + self.bucket_size}"
            
            if bucket_label in buckets:
                buckets[bucket_label]['count'] += 1
                buckets[bucket_label]['samples'].append(bw)
        
        # Calculate percentages
        for bucket in buckets.values():
            bucket['percentage'] = (bucket['count'] / total_samples) * 100
        
        return buckets
    
    def plot_single_distribution(self, ax, bandwidths: List[float], test_info: Dict, dataset_index: int = 0):
        """Plot a single bandwidth distribution on given axes"""
        if not bandwidths:
            ax.text(0.5, 0.5, 'No valid data', ha='center', va='center', transform=ax.transAxes)
            return
        
        # Create buckets
        buckets = self.create_buckets(bandwidths)
        
        # Prepare data for plotting
        bucket_labels = []
        percentages = []
        counts = []
        
        for label in sorted(buckets.keys(), key=lambda x: buckets[x]['start']):
            bucket_labels.append(label)
            percentages.append(buckets[label]['percentage'])
            counts.append(buckets[label]['count'])
        
        # Create bar chart
        x_pos = np.arange(len(bucket_labels))
        bars = ax.bar(x_pos, percentages, color='steelblue', edgecolor='black', linewidth=1.2)
        
        # Customize plot
        ax.set_xlabel('Bandwidth Range (Mbps)', fontsize=10, fontweight='bold')
        ax.set_ylabel('Percentage of Samples (%)', fontsize=10, fontweight='bold')
        
        # Get test info for title
        n = len(bandwidths)
        s = test_info.get('msg_size', 'N/A')
        
        ax.set_title(f'Bandwidth Distribution of {n} samples of {s} byte packet size', 
                    fontsize=11, fontweight='bold', pad=10)
        ax.set_xticks(x_pos)
        ax.set_xticklabels(bucket_labels, rotation=45, ha='right', fontsize=8)
        ax.grid(axis='y', alpha=0.3, linestyle='--')
        
        # Add percentage labels on top of bars (only if not too many bars)
        if len(bars) <= 15:
            for i, (bar, pct, count) in enumerate(zip(bars, percentages, counts)):
                height = bar.get_height()
                if height > 0:
                    ax.text(bar.get_x() + bar.get_width()/2., height,
                           f'{pct:.1f}%\n({count})',
                           ha='center', va='bottom', fontsize=7, fontweight='bold')
        
        # Add statistics text box
        stats_text = self._get_statistics_text(bandwidths, test_info, compact=True)
        ax.text(0.98, 0.97, stats_text,
               transform=ax.transAxes,
               fontsize=8,
               verticalalignment='top',
               horizontalalignment='right',
               bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8))
    
    def plot_all_distributions(self, output_file: str = None, individual_plots: bool = True):
        """Plot all datasets - both individual plots and subplots"""
        if not self.datasets:
            print("No data to plot")
            return
        
        print("Plotting o plot")
        # Plot individual distributions
        if individual_plots:
            for i, dataset in enumerate(self.datasets):
                bandwidths, test_info = self.extract_bandwidth_values(dataset)
                
                if not bandwidths:
                    print(f"No valid bandwidth data in dataset {i+1}")
                    continue
                
                fig, ax = plt.subplots(figsize=(12, 7))
                self.plot_single_distribution(ax, bandwidths, test_info, i)
                plt.tight_layout()
                
                # Save individual plot if output file specified
                if output_file:
                    base_name = output_file.rsplit('.', 1)[0]
                    ext = output_file.rsplit('.', 1)[1] if '.' in output_file else 'png'
                    msg_size = test_info.get('msg_size', i)
                    individual_file = f"{base_name}_size_{msg_size}.{ext}"
                    plt.savefig(individual_file, dpi=300, bbox_inches='tight')
                    print(f"Individual plot saved to: {individual_file}")
                
                plt.show()
        
        # Plot all as subplots
        if len(self.datasets) > 1:
            self.plot_subplots(output_file)
    
    def plot_subplots(self, output_file: str = None):
        """Plot all datasets as subplots in a single figure"""
        n_datasets = len(self.datasets)
        
        # Calculate subplot grid dimensions
        n_cols = min(2, n_datasets)
        n_rows = math.ceil(n_datasets / n_cols)
        
        fig, axes = plt.subplots(n_rows, n_cols, figsize=(14, 6 * n_rows))
        
        # Handle case of single subplot
        if n_datasets == 1:
            axes = np.array([axes])
        
        # Flatten axes array for easier iteration
        axes_flat = axes.flatten() if n_datasets > 1 else axes
        
        # Plot each dataset
        for i, dataset in enumerate(self.datasets):
            bandwidths, test_info = self.extract_bandwidth_values(dataset)
            ax = axes_flat[i]
            self.plot_single_distribution(ax, bandwidths, test_info, i)
        
        # Hide empty subplots
        for i in range(n_datasets, len(axes_flat)):
            axes_flat[i].set_visible(False)
        
        # Add overall title
        fig.suptitle('Bandwidth Distribution Comparison Across Packet Sizes', 
                    fontsize=16, fontweight='bold', y=0.995)
        
        plt.tight_layout(rect=[0, 0, 1, 0.99])
        
        # Save combined plot
        if output_file:
            base_name = output_file.rsplit('.', 1)[0]
            ext = output_file.rsplit('.', 1)[1] if '.' in output_file else 'png'
            combined_file = f"{base_name}_combined.{ext}"
            plt.savefig(combined_file, dpi=300, bbox_inches='tight')
            print(f"Combined subplot saved to: {combined_file}")
        
        plt.show()
    
    def _get_statistics_text(self, bandwidths: List[float], test_info: Dict, compact: bool = False) -> str:
        """Generate statistics text for the plot"""
        avg_bw = np.mean(bandwidths)
        max_bw = np.max(bandwidths)
        min_bw = np.min(bandwidths)
        std_bw = np.std(bandwidths)
        median_bw = np.median(bandwidths)
        
        msg_size = test_info.get('msg_size', 'N/A')
        duration = test_info.get('duration', 'N/A')
        
        if compact:
            stats_text = f"Stats:\n"
            stats_text += f"Avg: {avg_bw:.2f}\n"
            stats_text += f"Med: {median_bw:.2f}\n"
            stats_text += f"Max: {max_bw:.2f}\n"
            stats_text += f"Min: {min_bw:.2f}\n"
            stats_text += f"σ: {std_bw:.2f}"
        else:
            stats_text = f"Statistics:\n"
            stats_text += f"Samples: {len(bandwidths)}\n"
            stats_text += f"Avg: {avg_bw:.2f} Mbps\n"
            stats_text += f"Median: {median_bw:.2f} Mbps\n"
            stats_text += f"Max: {max_bw:.2f} Mbps\n"
            stats_text += f"Min: {min_bw:.2f} Mbps\n"
            stats_text += f"Std Dev: {std_bw:.2f} Mbps\n"
            stats_text += f"\nTest Info:\n"
            stats_text += f"Msg Size: {msg_size} bytes\n"
            stats_text += f"Duration: {duration} sec"
        
        return stats_text
    
    def print_bucket_summary(self):
        """Print text summary for all datasets"""
        for i, dataset in enumerate(self.datasets):
            bandwidths, test_info = self.extract_bandwidth_values(dataset)
            
            if not bandwidths:
                continue
            
            msg_size = test_info.get('msg_size', 'N/A')
            
            print("\n" + "="*60)
            print(f"Bandwidth Distribution Summary - Packet Size: {msg_size} bytes")
            print("="*60)
            
            buckets = self.create_buckets(bandwidths)
            
            print(f"{'Bucket (Mbps)':<20} {'Count':<10} {'Percentage':<15} {'Bar'}")
            print("-"*60)
            
            for label in sorted(buckets.keys(), key=lambda x: buckets[x]['start']):
                bucket = buckets[label]
                count = bucket['count']
                pct = bucket['percentage']
                bar = '█' * int(pct / 2)
                
                print(f"{label:<20} {count:<10} {pct:>6.2f}%        {bar}")
            
            # Print statistics
            avg_bw = np.mean(bandwidths)
            print("-"*60)
            print(f"Average: {avg_bw:.2f} Mbps | Samples: {len(bandwidths)}")
            print("="*60)


def main():
    parser = argparse.ArgumentParser(
        description='Plot bandwidth distribution from sockperf results (supports multiple packet sizes)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Plot all packet sizes (individual + subplots)
  %(prog)s results.json
  
  # Only show subplots, skip individual plots
  %(prog)s results.json --no-individual
  
  # Plot with 20 Mbps buckets and save
  %(prog)s results.json -b 20 -o bandwidth_plot.png
  
  # Just print text summary
  %(prog)s results.json --no-plot

File format: Supports both single test result and multiple results in one file
  - Array format: [{"test_info": {...}, "bandwidth_samples": [...]}, {...}]
  - Concatenated format: {...}{...}{...}
        """
    )
    
    parser.add_argument('input', help='Input JSON file from sockperf monitor')
    parser.add_argument('-b', '--bucket-size', type=int, default=10, 
                       help='Bucket size in Mbps (default: 10)')
    parser.add_argument('-o', '--output', default=None,
                       help='Output file for plots (e.g., plot.png)')
    parser.add_argument('--no-plot', action='store_true',
                       help='Only print text summary, do not create plots')
    parser.add_argument('--no-individual', action='store_true',
                       help='Skip individual plots, only show subplots')
    
    args = parser.parse_args()
    
    plotter = BandwidthPlotter(args.input, args.bucket_size)
    
    if not plotter.load_data():
        return
    
    # Print text summary
    #plotter.print_bucket_summary()
    
    # Create plots if requested
    if not args.no_plot:
        individual = not args.no_individual
        plotter.plot_all_distributions(args.output, individual_plots=individual)


if __name__ == '__main__':
    main()
