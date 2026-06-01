#!/usr/bin/env python3
"""
Plot bandwidth distribution from iperf3 results
Shows sender (client) and receiver (server) from same file
"""

import json
import argparse
import matplotlib.pyplot as plt
import numpy as np
import os


class BandwidthPlotter:
    def __init__(self, data_file, bucket_size=10):
        self.data_file = data_file
        self.bucket_size = bucket_size
        self.datasets = []

        # Style settings
        plt.rcParams.update({
            'font.size': 14,
            'axes.titlesize': 16,
            'axes.labelsize': 16,
            'xtick.labelsize': 14,
            'ytick.labelsize': 14,
            'legend.fontsize': 13,
            'figure.titlesize': 18
        })
    
    def load_data(self):
        """Load data file containing both sender and receiver bandwidth"""
        with open(self.data_file, "r") as f:
            data = json.load(f)

        if isinstance(data, dict):
            self.datasets = [data]
        else:
            self.datasets = data

        print(f"Loaded {len(self.datasets)} dataset(s)")
        for ds in self.datasets:
            msg_size = ds.get("test_info", {}).get("msg_size", "unknown")
            samples = len(ds.get("bandwidth_samples", []))
            print(f"  - Packet size {msg_size}: {samples} samples")

    def extract_sender_values(self, dataset):
        """Extract sender (client) bandwidth values"""
        bw = []
        
        if "bandwidth_samples" in dataset:
            for sample in dataset["bandwidth_samples"]:
                # Try sender_bandwidth_mbps first (iperf3 format)
                if "sender_bandwidth_mbps" in sample:
                    bw.append(sample["sender_bandwidth_mbps"])
                # Fallback to bandwidth_mbps (old sockperf format)
                elif "bandwidth_mbps" in sample:
                    bw.append(sample["bandwidth_mbps"])
        
        return bw
    
    def extract_receiver_values(self, dataset):
        """Extract receiver (server) bandwidth values"""
        bw = []
        
        if "bandwidth_samples" in dataset:
            for sample in dataset["bandwidth_samples"]:
                # Look for receiver_bandwidth_mbps (iperf3 format)
                if "receiver_bandwidth_mbps" in sample:
                    bw.append(sample["receiver_bandwidth_mbps"])
        
        return bw

    def create_buckets(self, values):
        """Create bandwidth buckets and calculate percentages"""
        if not values:
            return {}

        min_v = min(values)
        max_v = max(values)
        min_bucket = int(min_v // self.bucket_size) * self.bucket_size
        max_bucket = int(max_v // self.bucket_size) * self.bucket_size + self.bucket_size

        buckets = {}
        start = min_bucket
        while start <= max_bucket:
            buckets[f"{start}-{start+self.bucket_size}"] = {"count": 0, "start": start}
            start += self.bucket_size

        total = len(values)
        for v in values:
            b = int(v // self.bucket_size) * self.bucket_size
            key = f"{b}-{b+self.bucket_size}"
            if key in buckets:
                buckets[key]["count"] += 1

        for k in buckets:
            buckets[k]["percentage"] = (buckets[k]["count"] / total) * 100

        return buckets

    def plot_subplot(self, ax, sender_bw, receiver_bw, pkt_size):
        """Plot a single bandwidth distribution comparison"""
        if not sender_bw:
            ax.text(0.5, 0.5, f'No data for {pkt_size} bytes',
                   ha='center', va='center', transform=ax.transAxes)
            return

        # Find the overall min/max to cover BOTH distributions
        all_values = sender_bw.copy()
        if receiver_bw:
            all_values.extend(receiver_bw)
        
        overall_min = min(all_values)
        overall_max = max(all_values)
        
        # Create unified bucket range
        min_bucket = int(overall_min // self.bucket_size) * self.bucket_size
        max_bucket = int(overall_max // self.bucket_size) * self.bucket_size + self.bucket_size
        
        # Create all bucket labels
        all_labels = []
        bucket = min_bucket
        while bucket <= max_bucket:
            all_labels.append(f"{bucket}-{bucket+self.bucket_size}")
            bucket += self.bucket_size
        
        # Create sender buckets
        sender_buckets = self.create_buckets(sender_bw)
        sender_percent = [sender_buckets.get(label, {"percentage": 0})["percentage"] for label in all_labels]

        # Create receiver buckets
        receiver_percent = []
        if receiver_bw:
            receiver_buckets = self.create_buckets(receiver_bw)
            receiver_percent = [receiver_buckets.get(label, {"percentage": 0})["percentage"] for label in all_labels]

        x = np.arange(len(all_labels))

        # Plot sender as semi-transparent blue bars (OVERLAPPING, not side-by-side)
        ax.bar(
            x,
            sender_percent,
            width=0.8,  # Full width
            color="steelblue",
            alpha=0.6,  # Semi-transparent
            edgecolor="darkblue",
            linewidth=1.5,
            label="Client (Sender)"
        )

        # Plot receiver as semi-transparent red bars (OVERLAPPING at same position)
        if receiver_bw:
            ax.bar(
                x,  # Same position as sender (not offset)
                receiver_percent,
                width=0.8,  # Full width
                color="red",
                alpha=0.5,  # Semi-transparent
                edgecolor="darkred",
                linewidth=1.5,
                label="Server (Receiver)"
            )
            
            # Where they overlap, you'll see purple/brown color

        # Title and labels — inherit sizes from rcParams, no hardcoded overrides
        ax.set_title(f"Bandwidth Distribution - Packet Size {pkt_size} bytes",
                    fontweight="bold")
        ax.set_ylabel("Percentage of Samples (%)", fontweight="bold")
        ax.set_xlabel("Bandwidth Range (Mbps)", fontweight="bold")

        # Thin out x-ticks automatically when there are too many labels
        max_ticks = 20
        n_labels = len(all_labels)
        if n_labels > max_ticks:
            step = int(np.ceil(n_labels / max_ticks))
            visible_indices = list(range(0, n_labels, step))
            if (n_labels - 1) not in visible_indices:
                visible_indices.append(n_labels - 1)
            ax.set_xticks([x[i] for i in visible_indices])
            ax.set_xticklabels([all_labels[i] for i in visible_indices], rotation=45, ha="right")
        else:
            ax.set_xticks(x)
            ax.set_xticklabels(all_labels, rotation=45, ha="right")

        ax.grid(axis='y', linestyle='--', alpha=0.4)

        # Statistics box in top right — inherits rcParams font size
        n_samples = len(sender_bw)
        avg_sender = np.mean(sender_bw)

        legend_lines = [
            f"Packet Size: {pkt_size} bytes",
            f"Samples: {n_samples}",
            f"Client Avg: {avg_sender:.2f} Mbps"
        ]

        if receiver_bw:
            avg_receiver = np.mean(receiver_bw)
            legend_lines.append(f"Server Avg: {avg_receiver:.2f} Mbps")
            loss_pct = ((avg_sender - avg_receiver) / avg_sender) * 100
            legend_lines.append(f"Avg Loss: {loss_pct:.1f}%")

        stats_text = "\n".join(legend_lines)
        ax.text(0.98, 0.97, stats_text,
               transform=ax.transAxes,
               verticalalignment='top',
               horizontalalignment='right',
               bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8))

        # Color legend in top left
        ax.legend(loc='upper left')

    def plot_all(self, output_file):
        """Plot all datasets"""
        num_plots = len(self.datasets)
        
        if num_plots == 0:
            print("ERROR: No datasets to plot")
            return
        
        fig, axes = plt.subplots(num_plots, 1, figsize=(15, num_plots * 5),
                                 squeeze=False)
        axes = axes.flatten()

        for i, dataset in enumerate(self.datasets):
            test_info = dataset.get("test_info", {})
            pkt_size = test_info.get("msg_size", "unknown")
            
            sender_bw = self.extract_sender_values(dataset)
            receiver_bw = self.extract_receiver_values(dataset)

            print(f"\nPlotting packet size {pkt_size}:")
            print(f"  Sender samples: {len(sender_bw)}")
            print(f"  Receiver samples: {len(receiver_bw)}")

            self.plot_subplot(axes[i], sender_bw, receiver_bw, pkt_size)

        plt.suptitle("Client vs Server Bandwidth Distribution Comparison", 
                    fontsize=18, fontweight="bold", y=0.995)
        plt.tight_layout(rect=[0, 0, 1, 0.99])
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        print(f"\n{'='*60}")
        print(f"Plot saved → {output_file}")
        print(f"{'='*60}")


def main():
    parser = argparse.ArgumentParser(
        description="Plot bandwidth distribution from iperf3 results (sender and receiver from same file)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Plot iperf3 results (contains both sender and receiver data)
  %(prog)s results.json -o comparison.png
  
  # Use 20 Mbps buckets
  %(prog)s results.json -b 20 -o comparison.png

Supported JSON formats:
  - iperf3 format with sender_bandwidth_mbps and receiver_bandwidth_mbps
  - Old sockperf format with bandwidth_mbps (shows as client only)
        """
    )
    parser.add_argument("input", help="Input JSON file with bandwidth data")
    parser.add_argument("-b", "--bucket", type=int, default=10, 
                       help="Bucket size in Mbps (default: 10)")
    parser.add_argument("-o", "--output", default="bandwidth_comparison.png",
                        help="Output image filename (default: bandwidth_comparison.png)")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"ERROR: Input file not found: {args.input}")
        return

    plotter = BandwidthPlotter(args.input, args.bucket)
    plotter.load_data()
    plotter.plot_all(args.output)


if __name__ == "__main__":
    main()
