#!/usr/bin/env python3
"""
eBPF Lookup Table Builder

Creates realistic data center prefix distributions for testing eBPF authentication.
Generates 1000 prefixes with appropriate CIDR distributions and random hash keys.
"""

import subprocess
import random
import ipaddress
import sys
import time
from typing import List, Tuple
import argparse

class LookupTableBuilder:
    def __init__(self, user_program_path: str = "/tmp/xdp_bpf_user"):
        self.user_program = user_program_path
        self.prefixes_added = 0
        
        # Data center typical prefix distribution
        # Based on real-world data center routing tables
        self.prefix_distribution = {
            "/32": 0.45,  # 45% - Host routes, loopbacks, specific services
            "/24": 0.30,  # 30% - Subnet routes, VLANs
            "/16": 0.15,  # 15% - Network aggregation, larger subnets  
            "/20": 0.05,  # 5% - Medium aggregation
            "/8":  0.03,  # 3% - Large network blocks
            "/12": 0.02,  # 2% - Other aggregation sizes
        }
        
        # Data center IP ranges (RFC 1918 private addresses)
        self.dc_networks = [
            "10.0.0.0/8",       # Large enterprise networks
            "172.16.0.0/12",    # Medium networks  
            "192.168.0.0/16",   # Small networks/lab environments
        ]
    
    def generate_random_key(self) -> str:
        """Generate a random 32-byte (256-bit) hex key for SHA-256."""
        return ''.join([f"{random.randint(0, 255):02x}" for _ in range(16)])
    
    def generate_realistic_prefixes(self, count: int = 1000) -> List[Tuple[str, int]]:
        """Generate realistic data center prefixes with proper distribution."""
        prefixes = []
        
        for prefix_len_str, percentage in self.prefix_distribution.items():
            prefix_len = int(prefix_len_str[1:])  # Remove '/' 
            prefix_count = int(count * percentage)
            
            print(f"Generating {prefix_count} prefixes with /{prefix_len}...")
            
            for _ in range(prefix_count):
                # Choose a random data center network as base
                base_network = random.choice(self.dc_networks)
                base_net = ipaddress.IPv4Network(base_network, strict=False)
                
                # Generate a random subnet within this network
                try:
                    if prefix_len >= base_net.prefixlen:
                        # Create subnet within the base network
                        subnet = list(base_net.subnets(new_prefix=prefix_len))[
                            random.randint(0, min(99, 2**(prefix_len - base_net.prefixlen) - 1))
                        ]
                        prefixes.append((str(subnet.network_address), prefix_len))
                    else:
                        # For larger networks (smaller prefix length), use base directly
                        prefixes.append((str(base_net.network_address), prefix_len))
                        
                except (ValueError, IndexError):
                    # Fallback: generate random IP in the base network
                    random_ip = base_net.network_address + random.randint(0, base_net.num_addresses - 1)
                    prefixes.append((str(random_ip), prefix_len))
        
        # Fill remaining slots with /24 prefixes (most common)
        while len(prefixes) < count:
            base_network = random.choice(self.dc_networks)
            base_net = ipaddress.IPv4Network(base_network, strict=False)
            subnet = list(base_net.subnets(new_prefix=24))[random.randint(0, min(255, 2**(24 - base_net.prefixlen) - 1))]
            prefixes.append((str(subnet.network_address), 24))
        
        # Remove duplicates while preserving order
        seen = set()
        unique_prefixes = []
        for prefix, length in prefixes:
            key = f"{prefix}/{length}"
            if key not in seen:
                seen.add(key)
                unique_prefixes.append((prefix, length))
        
        return unique_prefixes[:count]
    
    def check_user_program(self) -> bool:
        """Check if the user program exists and is executable."""
        try:
            result = subprocess.run([self.user_program, "--help"], 
                                  capture_output=True, timeout=5)
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
            return False
    
    def add_prefix_to_table(self, ip_address: str, prefix_len: int, hash_key: str) -> bool:
        """Add a single prefix to the lookup table."""
        try:
            prefix = f"{ip_address}/{prefix_len}"
            cmd = [self.user_program, "add-hex", prefix, hash_key]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                return True
            else:
                print(f"    Error adding {prefix}: {result.stderr.strip()}")
                return False
                
        except subprocess.TimeoutExpired:
            print(f"    Timeout adding {prefix}")
            return False
        except Exception as e:
            print(f"    Exception adding {prefix}: {e}")
            return False
    
    def clear_table(self) -> bool:
        """Clear the existing lookup table."""
        try:
            print("Clearing existing lookup table...")
            result = subprocess.run([self.user_program, "clear"], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except Exception as e:
            print(f"Warning: Could not clear table: {e}")
            return False
    
    def build_lookup_table(self, prefix_count: int = 1000, clear_first: bool = True) -> None:
        """Build the complete lookup table."""
        print(f"🏗️  Building lookup table with {prefix_count} prefixes...")
        print(f"User program: {self.user_program}")
        
        if not self.check_user_program():
            print(f"❌ Error: Cannot execute user program at {self.user_program}")
            print("Please ensure:")
            print("1. The path is correct")
            print("2. The program is compiled and executable")
            print("3. You have necessary permissions (may need sudo)")
            sys.exit(1)
        
        if clear_first:
            self.clear_table()
        
        # Generate prefixes
        print(f"\n📊 Generating {prefix_count} prefixes with data center distribution...")
        prefixes = self.generate_realistic_prefixes(prefix_count)
        
        print(f"\n📝 Prefix distribution summary:")
        dist_count = {}
        for _, prefix_len in prefixes:
            key = f"/{prefix_len}"
            dist_count[key] = dist_count.get(key, 0) + 1
        
        for prefix_len, count in sorted(dist_count.items()):
            percentage = (count / len(prefixes)) * 100
            print(f"  {prefix_len:>3}: {count:>4} prefixes ({percentage:>5.1f}%)")
        
        # Add prefixes to table
        print(f"\n🔧 Adding prefixes to lookup table...")
        success_count = 0
        
        for i, (ip_address, prefix_len) in enumerate(prefixes, 1):
            hash_key = self.generate_random_key()
            
            if self.add_prefix_to_table(ip_address, prefix_len, hash_key):
                success_count += 1
                if i % 50 == 0:  # Progress update every 50 prefixes
                    print(f"    ✅ Added {i}/{len(prefixes)} prefixes...")
            else:
                print(f"    ❌ Failed to add {ip_address}/{prefix_len}")
            
            # Small delay to avoid overwhelming the program
            time.sleep(0.01)
        
        print(f"\n🎉 Lookup table built successfully!")
        print(f"✅ Added: {success_count}/{len(prefixes)} prefixes")
        
        if success_count < len(prefixes):
            print(f"⚠️  Warning: {len(prefixes) - success_count} prefixes failed to add")
    
    def show_table_stats(self) -> None:
        """Show current lookup table statistics."""
        try:
            result = subprocess.run([self.user_program, "show"], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                print("\n📊 Current lookup table contents:")
                print(result.stdout)
            else:
                print("Could not retrieve table statistics")
        except Exception as e:
            print(f"Error retrieving table stats: {e}")
    
    def generate_test_config(self, filename: str = "test_prefixes.txt") -> None:
        """Generate a test configuration file with the prefixes."""
        prefixes = self.generate_realistic_prefixes(1000)
        
        with open(filename, 'w') as f:
            f.write("# eBPF Authentication Test Prefixes\n")
            f.write("# Format: IP_ADDRESS/PREFIX_LENGTH HASH_KEY\n")
            f.write(f"# Generated {len(prefixes)} prefixes\n\n")
            
            for ip_address, prefix_len in prefixes:
                hash_key = self.generate_random_key()
                f.write(f"{ip_address}/{prefix_len} {hash_key}\n")
        
        print(f"✅ Test configuration saved to: {filename}")

def main():
    parser = argparse.ArgumentParser(
        description="Build eBPF lookup table with realistic data center prefixes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python lookup_table_builder.py --build 1000
  python lookup_table_builder.py --build 500 --user-program ./my_xdp_program  
  python lookup_table_builder.py --generate-config test_config.txt
  python lookup_table_builder.py --show-stats
        """
    )
    
    parser.add_argument("--build", "-b", type=int, metavar="COUNT",
                       help="Build lookup table with COUNT prefixes (default: 1000)")
    parser.add_argument("--user-program", "-u", default="/tmp/xdp_bpf_user",
                       help="Path to the user program (default: /tmp/xdp_bpf_user)")
    parser.add_argument("--no-clear", action="store_true",
                       help="Don't clear existing table before building")
    parser.add_argument("--generate-config", "-g", metavar="FILE",
                       help="Generate test configuration file")
    parser.add_argument("--show-stats", "-s", action="store_true",
                       help="Show current lookup table statistics")
    
    args = parser.parse_args()
    
    builder = LookupTableBuilder(args.user_program)
    
    if args.show_stats:
        builder.show_table_stats()
    elif args.generate_config:
        builder.generate_test_config(args.generate_config)
    elif args.build is not None:
        builder.build_lookup_table(args.build, not args.no_clear)
        if args.build > 0:
            builder.show_table_stats()
    else:
        # Default action
        builder.build_lookup_table(1000, True)
        builder.show_table_stats()

if __name__ == "__main__":
    main()
