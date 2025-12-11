#!/usr/bin/env python3
"""
Calculate Kullback-Leibler (K-L) Divergence between two bandwidth distributions
Supports client-client, server-server, or client-server comparisons
"""

import json
import argparse
import numpy as np
from scipy import stats
from typing import List, Dict, Tuple
import sys


class KLDivergenceCalculator:
    def __init__(self, file1: str, file2: str, bucket_size: int = 10):
        self.file1 = file1
        self.file2 = file2
        self.bucket_size = bucket_size
        self.datasets1 = []
        self.datasets2 = []
        
    def load_data(self, filename: str) -> List[Dict]:
        """Load JSON data from file"""
        with open(filename, 'r') as f:
            data = json.load(f)
        
        # Handle both single object and array
        if isinstance(data, dict):
            return [data]
        return data
    
    def extract_bandwidth_values(self, dataset: Dict) -> Tuple[List[float], Dict]:
        """Extract bandwidth values from a dataset (handles multiple formats)"""
        values = []
        test_info = dataset.get("test_info", {})
        
        # Format 1: bandwidth_samples array (client format)
        if "bandwidth_samples" in dataset:
            for sample in dataset["bandwidth_samples"]:
                values.append(sample.get("bandwidth_mbps", 0))
        
        # Format 2: server_throughput array (server tcpdump format)
        elif "server_throughput" in dataset:
            for entry in dataset["server_throughput"]:
                values.append(entry.get("throughput_mbps", 0))
        
        # Format 3: server_statistics single object (old server format)
        elif "server_statistics" in dataset:
            stats = dataset["server_statistics"]
            values.append(stats.get("throughput_mbps", 0))
        
        return values, test_info
    
    def get_packet_size(self, test_info: Dict) -> int:
        """Get packet size from test_info (handles both msg_size and packet_size)"""
        return test_info.get("msg_size") or test_info.get("packet_size", 0)
    
    def create_probability_distribution(self, values: List[float]) -> Tuple[np.ndarray, List[str]]:
        """Create probability distribution from bandwidth values using buckets"""
        if not values:
            return None, None
        
        min_val = min(values)
        max_val = max(values)
        
        # Create bucket ranges
        min_bucket = int(min_val // self.bucket_size) * self.bucket_size
        max_bucket = int(max_val // self.bucket_size) * self.bucket_size + self.bucket_size
        
        # Create bins
        bins = []
        labels = []
        bucket = min_bucket
        while bucket <= max_bucket:
            bins.append(bucket)
            labels.append(f"{bucket}-{bucket + self.bucket_size}")
            bucket += self.bucket_size
        bins.append(bucket)  # Add final edge
        
        # Count values in each bucket
        counts, _ = np.histogram(values, bins=bins)
        
        # Convert to probability distribution
        # Add small epsilon to avoid zeros (important for K-L divergence)
        epsilon = 1e-10
        probabilities = (counts + epsilon) / (np.sum(counts) + epsilon * len(counts))
        
        return probabilities, labels
    
    def calculate_kl_divergence(self, p: np.ndarray, q: np.ndarray) -> float:
        """
        Calculate K-L Divergence: D_KL(P || Q) = sum(P(i) * log(P(i) / Q(i)))
        Measures how much P diverges from Q
        """
        # Ensure no zeros (add small epsilon if needed)
        epsilon = 1e-10
        p = np.where(p == 0, epsilon, p)
        q = np.where(q == 0, epsilon, q)
        
        # Normalize
        p = p / np.sum(p)
        q = q / np.sum(q)
        
        # Calculate K-L divergence
        kl_div = np.sum(p * np.log(p / q))
        
        return kl_div
    
    def align_distributions(self, values1: List[float], values2: List[float]) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """Create aligned probability distributions with same bucket ranges"""
        if not values1 or not values2:
            return None, None, None
        
        # Find overall min and max
        min_val = min(min(values1), min(values2))
        max_val = max(max(values1), max(values2))
        
        # Create unified bucket ranges
        min_bucket = int(min_val // self.bucket_size) * self.bucket_size
        max_bucket = int(max_val // self.bucket_size) * self.bucket_size + self.bucket_size
        
        # Create bins
        bins = []
        labels = []
        bucket = min_bucket
        while bucket <= max_bucket:
            bins.append(bucket)
            labels.append(f"{bucket}-{bucket + self.bucket_size}")
            bucket += self.bucket_size
        bins.append(bucket)
        
        # Histogram both distributions with same bins
        counts1, _ = np.histogram(values1, bins=bins)
        counts2, _ = np.histogram(values2, bins=bins)
        
        # Convert to probabilities with epsilon
        epsilon = 1e-10
        p1 = (counts1 + epsilon) / (np.sum(counts1) + epsilon * len(counts1))
        p2 = (counts2 + epsilon) / (np.sum(counts2) + epsilon * len(counts2))
        
        return p1, p2, labels
    
    def compare_datasets(self):
        """Compare datasets and calculate K-L divergence for matching packet sizes"""
        self.datasets1 = self.load_data(self.file1)
        self.datasets2 = self.load_data(self.file2)
        
        print("=" * 80)
        print("K-L Divergence Analysis")
        print("=" * 80)
        print(f"File 1: {self.file1} ({len(self.datasets1)} dataset(s))")
        print(f"File 2: {self.file2} ({len(self.datasets2)} dataset(s))")
        print(f"Bucket size: {self.bucket_size} Mbps")
        print()
        
        results = []
        
        # Find matching packet sizes
        for ds1 in self.datasets1:
            values1, info1 = self.extract_bandwidth_values(ds1)
            pkt_size1 = self.get_packet_size(info1)
            
            if not values1:
                print(f"Warning: No bandwidth values in dataset 1 for packet size {pkt_size1}")
                continue
            
            # Find matching dataset in file 2
            matched = False
            for ds2 in self.datasets2:
                values2, info2 = self.extract_bandwidth_values(ds2)
                pkt_size2 = self.get_packet_size(info2)
                
                if pkt_size1 == pkt_size2:
                    matched = True
                    
                    if not values2:
                        print(f"Warning: No bandwidth values in dataset 2 for packet size {pkt_size2}")
                        continue
                    
                    print("-" * 80)
                    print(f"Packet Size: {pkt_size1} bytes")
                    print("-" * 80)
                    print(f"Distribution 1: {len(values1)} samples")
                    print(f"  Mean: {np.mean(values1):.2f} Mbps, Std: {np.std(values1):.2f} Mbps")
                    print(f"  Range: [{np.min(values1):.2f}, {np.max(values1):.2f}] Mbps")
                    
                    print(f"\nDistribution 2: {len(values2)} samples")
                    print(f"  Mean: {np.mean(values2):.2f} Mbps, Std: {np.std(values2):.2f} Mbps")
                    print(f"  Range: [{np.min(values2):.2f}, {np.max(values2):.2f}] Mbps")
                    
                    # Create aligned distributions
                    p1, p2, labels = self.align_distributions(values1, values2)
                    
                    if p1 is None or p2 is None:
                        print("\nError: Could not create distributions")
                        continue
                    
                    # Calculate K-L divergences (both directions)
                    kl_1_to_2 = self.calculate_kl_divergence(p1, p2)
                    kl_2_to_1 = self.calculate_kl_divergence(p2, p1)
                    
                    # Calculate symmetric K-L divergence (average of both directions)
                    kl_symmetric = (kl_1_to_2 + kl_2_to_1) / 2
                    
                    # Calculate JS divergence (symmetric version based on K-L)
                    m = (p1 + p2) / 2
                    js_div = (self.calculate_kl_divergence(p1, m) + self.calculate_kl_divergence(p2, m)) / 2
                    
                    print(f"\n{'Metric':<30} {'Value'}")
                    print("-" * 50)
                    print(f"{'K-L Divergence (1 → 2):':<30} {kl_1_to_2:.6f}")
                    print(f"{'K-L Divergence (2 → 1):':<30} {kl_2_to_1:.6f}")
                    print(f"{'Symmetric K-L Divergence:':<30} {kl_symmetric:.6f}")
                    print(f"{'Jensen-Shannon Divergence:':<30} {js_div:.6f}")
                    print(f"{'JS Distance (sqrt):':<30} {np.sqrt(js_div):.6f}")
                    
                    # Interpretation
                    print(f"\nInterpretation:")
                    if kl_symmetric < 0.01:
                        interpretation = "Distributions are very similar (KL < 0.01)"
                    elif kl_symmetric < 0.1:
                        interpretation = "Distributions are somewhat similar (0.01 ≤ KL < 0.1)"
                    elif kl_symmetric < 1.0:
                        interpretation = "Distributions are moderately different (0.1 ≤ KL < 1.0)"
                    else:
                        interpretation = "Distributions are very different (KL ≥ 1.0)"
                    print(f"  → {interpretation}")
                    
                    results.append({
                        'packet_size': pkt_size1,
                        'kl_1_to_2': kl_1_to_2,
                        'kl_2_to_1': kl_2_to_1,
                        'kl_symmetric': kl_symmetric,
                        'js_divergence': js_div,
                        'js_distance': np.sqrt(js_div),
                        'interpretation': interpretation,
                        'distribution_1': {
                            'samples': len(values1),
                            'mean': float(np.mean(values1)),
                            'std': float(np.std(values1)),
                            'min': float(np.min(values1)),
                            'max': float(np.max(values1))
                        },
                        'distribution_2': {
                            'samples': len(values2),
                            'mean': float(np.mean(values2)),
                            'std': float(np.std(values2)),
                            'min': float(np.min(values2)),
                            'max': float(np.max(values2))
                        }
                    })
                    
                    print()
            
            if not matched:
                print(f"Warning: No matching packet size {pkt_size1} found in file 2")
        
        # Summary
        if results:
            print("=" * 80)
            print("Summary")
            print("=" * 80)
            print(f"{'Packet Size':<15} {'KL (1→2)':<12} {'KL (2→1)':<12} {'Symmetric KL':<15} {'JS Div':<12}")
            print("-" * 80)
            for r in results:
                print(f"{r['packet_size']:<15} {r['kl_1_to_2']:<12.6f} {r['kl_2_to_1']:<12.6f} "
                      f"{r['kl_symmetric']:<15.6f} {r['js_divergence']:<12.6f}")
            print("=" * 80)
            
            # Create comprehensive output JSON
            output_data = {
                'metadata': {
                    'file1': self.file1,
                    'file2': self.file2,
                    'bucket_size_mbps': self.bucket_size,
                    'num_comparisons': len(results)
                },
                'results': results
            }
            
            # Save results to JSON
            output_file = "kl_divergence_results.json"
            with open(output_file, 'w') as f:
                json.dump(output_data, f, indent=2)
            print(f"\nDetailed results saved to: {output_file}")
        else:
            print("No matching packet sizes found to compare")


def main():
    parser = argparse.ArgumentParser(
        description='Calculate K-L Divergence between two bandwidth distributions',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Compare client vs server
  %(prog)s client_results.json server_results.json
  
  # Compare two client runs
  %(prog)s client_run1.json client_run2.json
  
  # Compare with custom bucket size
  %(prog)s client.json server.json -b 20

About K-L Divergence:
  - K-L(P || Q) measures how much P diverges from Q
  - NOT symmetric: K-L(P || Q) ≠ K-L(Q || P)
  - Symmetric K-L = (K-L(P||Q) + K-L(Q||P)) / 2
  - JS Divergence: Symmetric variant, ranges [0, 1]
  - Lower values = more similar distributions
  
Interpretation:
  < 0.01:  Very similar distributions
  < 0.1:   Somewhat similar
  < 1.0:   Moderately different
  ≥ 1.0:   Very different distributions
        """
    )
    
    parser.add_argument('file1', help='First JSON file (P distribution)')
    parser.add_argument('file2', help='Second JSON file (Q distribution)')
    parser.add_argument('-b', '--bucket-size', type=int, default=10,
                       help='Bucket size in Mbps for distribution (default: 10)')
    parser.add_argument('-o', '--output', default='kl_divergence_results.json',
                       help='Output JSON file for results (default: kl_divergence_results.json)')
    
    args = parser.parse_args()
    
    calculator = KLDivergenceCalculator(args.file1, args.file2, args.bucket_size)
    calculator.compare_datasets()


if __name__ == '__main__':
    main()
