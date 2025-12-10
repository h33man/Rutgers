#!/usr/bin/env python3
"""
Plot bandwidth distribution comparing:
  - Client sockperf results (blue bars)
  - Server tcpdump throughput results (transparent red bars)
Produces a single image with subplots for each packet size.
"""

import json
import argparse
import matplotlib.pyplot as plt
import numpy as np
import os


class BandwidthPlotter:
    def __init__(self, client_file, server_file, bucket_size=10):
        self.client_file = client_file
        self.server_file = server_file
        self.bucket_size = bucket_size
        self.client_datasets = []
        self.server_datasets = []

    # ---------------------------------------------------------
    def load_client_data(self):
        with open(self.client_file, "r") as f:
            data = json.load(f)

        if isinstance(data, dict):
            self.client_datasets = [data]
        else:
            self.client_datasets = data

        print(f"Loaded {len(self.client_datasets)} client dataset(s)")
        for ds in self.client_datasets:
            msg_size = ds.get("test_info", {}).get("msg_size", "unknown")
            samples = len(ds.get("bandwidth_samples", []))
            print(f"  - Packet size {msg_size}: {samples} samples")

    # ---------------------------------------------------------
    def load_server_data(self):
        if not self.server_file:
            print("No server file provided, skipping server data")
            return

        with open(self.server_file, "r") as f:
            data = json.load(f)

        # Handle both array and single object
        if isinstance(data, dict):
            self.server_datasets = [data]
        else:
            self.server_datasets = data

        print(f"Loaded {len(self.server_datasets)} server dataset(s)")
        for ds in self.server_datasets:
            # Handle both formats: direct test_info or nested in server_statistics
            if "test_info" in ds:
                # Check for both 'msg_size' and 'packet_size'
                test_info = ds["test_info"]
                msg_size = test_info.get("msg_size") or test_info.get("packet_size", "unknown")
                
                # Check if it has server_throughput array (new tcpdump format)
                if "server_throughput" in ds:
                    samples = len(ds["server_throughput"])
                # Or bandwidth_samples (client format)
                elif "bandwidth_samples" in ds:
                    samples = len(ds["bandwidth_samples"])
                # Or server_statistics (old format)
                elif "server_statistics" in ds:
                    samples = 1
                else:
                    samples = 0
            else:
                msg_size = "unknown"
                samples = 0
            print(f"  - Packet size {msg_size}: {samples} iteration(s)")

    # ---------------------------------------------------------
    def extract_client_values(self, dataset):
        bw = [s["bandwidth_mbps"] for s in dataset.get("bandwidth_samples", [])]
        info = dataset.get("test_info", {})
        return bw, info

    # ---------------------------------------------------------
    def extract_server_values(self, pkt_size):
        """Extract server bandwidth values for a given packet size"""
        if not self.server_datasets:
            return []

        server_bw = []
        
        for dataset in self.server_datasets:
            # Check test_info for matching packet size
            test_info = dataset.get("test_info", {})
            
            # Handle both 'msg_size' (client format) and 'packet_size' (server format)
            msg_size = test_info.get("msg_size") or test_info.get("packet_size")
            
            if msg_size == pkt_size:
                # Check if this has server_throughput array (tcpdump format)
                if "server_throughput" in dataset:
                    # Multiple iterations
                    for entry in dataset["server_throughput"]:
                        server_bw.append(entry.get("throughput_mbps", 0))
                
                # Or if this is the old format with server_statistics
                elif "server_statistics" in dataset:
                    # Single measurement from tcpdump
                    stats = dataset["server_statistics"]
                    server_bw.append(stats.get("throughput_mbps", 0))
                
                # Or if it's the same format as client (bandwidth_samples)
                elif "bandwidth_samples" in dataset:
                    # Multiple samples
                    for sample in dataset["bandwidth_samples"]:
                        server_bw.append(sample.get("bandwidth_mbps", 0))

        return server_bw

    # ---------------------------------------------------------
    def create_buckets(self, values):
        if not values:
            return {}

        min_v = min(values)
        max_v = max(values)
        min_bucket = int(min_v // self.bucket_size) * self.bucket_size
        max_bucket = int(max_v // self.bucket_size) * self.bucket_size + self.bucket_size

        buckets = {}
        start = min_bucket
        while start <= max_bucket:
            buckets[f"{start}-{start+self.bucket_size}"] = {"count": 0}
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

    # ---------------------------------------------------------
    def plot_subplot(self, ax, client_bw, server_bw, pkt_size):
        if not client_bw:
            ax.text(0.5, 0.5, f'No client data for {pkt_size} bytes',
                   ha='center', va='center', transform=ax.transAxes)
            return

        # ------ Create client buckets ------
        client_buckets = self.create_buckets(client_bw)
        labels = list(client_buckets.keys())
        client_percent = [client_buckets[k]["percentage"] for k in labels]

        x = np.arange(len(labels))

        # ------ Plot client as blue bars ------
        bars1 = ax.bar(
            x,
            client_percent,
            width=0.4,
            color="steelblue",
            edgecolor="black",
            label=f"Client (n={len(client_bw)})"
        )

        # ------ Server as transparent red bars (side-by-side) ------
        if server_bw:
            server_buckets = self.create_buckets(server_bw)
            server_percent = [
                server_buckets.get(k, {"percentage": 0})["percentage"]
                for k in labels
            ]

            bars2 = ax.bar(
                x + 0.42,                  # side-by-side offset
                server_percent,
                width=0.4,
                color="red",
                alpha=0.35,               # transparent
                edgecolor="darkred",
                label=f"Server (n={len(server_bw)})"
            )

        # ------ Formatting ------
        n_client = len(client_bw)
        avg_client = np.mean(client_bw)
        title_parts = [f"Packet Size {pkt_size} bytes"]
        title_parts.append(f"Client: {n_client} samples, avg={avg_client:.2f} Mbps")
        
        if server_bw:
            n_server = len(server_bw)
            avg_server = np.mean(server_bw)
            title_parts.append(f"Server: {n_server} samples, avg={avg_server:.2f} Mbps")
        
        ax.set_title("\n".join(title_parts), fontsize=11, fontweight="bold")
        ax.set_ylabel("Percentage of Samples (%)", fontsize=10, fontweight="bold")
        ax.set_xlabel("Bandwidth Range (Mbps)", fontsize=10, fontweight="bold")
        ax.set_xticks(x + 0.21 if server_bw else x)
        ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=8)
        ax.grid(axis='y', linestyle='--', alpha=0.4)
        ax.legend(loc='upper right')

    # ---------------------------------------------------------
    def plot_all(self, output_file):
        num_plots = len(self.client_datasets)
        
        if num_plots == 0:
            print("ERROR: No client datasets to plot")
            return
        
        fig, axes = plt.subplots(num_plots, 1, figsize=(15, num_plots * 5),
                                 squeeze=False)
        axes = axes.flatten()

        for i, dataset in enumerate(self.client_datasets):
            client_bw, test_info = self.extract_client_values(dataset)
            pkt_size = test_info.get("msg_size")
            server_bw = self.extract_server_values(pkt_size)

            print(f"\nPlotting packet size {pkt_size}:")
            print(f"  Client samples: {len(client_bw)}")
            print(f"  Server samples: {len(server_bw)}")

            self.plot_subplot(axes[i], client_bw, server_bw, pkt_size)

        plt.suptitle("Client vs Server Bandwidth Distribution Comparison", 
                    fontsize=16, fontweight="bold", y=0.995)
        plt.tight_layout(rect=[0, 0, 1, 0.99])
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        print(f"\n{'='*60}")
        print(f"Plot saved → {output_file}")
        print(f"{'='*60}")


# ======================================================================
# MAIN
# ======================================================================
def main():
    parser = argparse.ArgumentParser(
        description="Client/Server bandwidth comparison plotter.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Plot only client data
  %(prog)s client_results.json -o comparison.png
  
  # Plot client vs server comparison
  %(prog)s client_results.json --server server_results.json -o comparison.png
  
  # Use 20 Mbps buckets
  %(prog)s client_results.json --server server_results.json -b 20 -o comparison.png

Supported JSON formats:
  - Client/Server with bandwidth_samples array
  - Server with server_statistics object (from tcpdump monitor)
        """
    )
    parser.add_argument("client", help="Client JSON file")
    parser.add_argument("--server", help="Server JSON file (optional)")
    parser.add_argument("-b", "--bucket", type=int, default=10, 
                       help="Bucket size in Mbps (default: 10)")
    parser.add_argument("-o", "--output", default="bandwidth_comparison.png",
                        help="Output image filename (default: bandwidth_comparison.png)")
    args = parser.parse_args()

    if not os.path.exists(args.client):
        print(f"ERROR: Client file not found: {args.client}")
        return

    if args.server and not os.path.exists(args.server):
        print(f"ERROR: Server file not found: {args.server}")
        return

    plotter = BandwidthPlotter(args.client, args.server, args.bucket)
    plotter.load_client_data()
    plotter.load_server_data()
    plotter.plot_all(args.output)


if __name__ == "__main__":
    main()
