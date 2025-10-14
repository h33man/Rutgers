#!/usr/bin/env python3
"""
UDP Echo Server for eBPF Benchmark Testing

This server receives UDP packets and echoes them back to the sender.
Used for RTT measurements in the benchmark tool.

The server listens on a specified port and returns all received packets
to the sender's source address/port, preserving the payload.

Usage:
    python udp_echo_server.py --port 5201 --bind 0.0.0.0
    python udp_echo_server.py --port 5201 --bind 192.168.1.100
"""

import socket
import argparse
import sys
import signal
import time
from typing import Tuple

class UDPEchoServer:
    def __init__(self, bind_address: str = "0.0.0.0", port: int = 5201, timeout: int = None):
        self.bind_address = bind_address
        self.port = port
        self.timeout = timeout
        self.sock = None
        self.running = True
        self.packets_received = 0
        self.packets_sent = 0
        self.bytes_received = 0
        self.bytes_sent = 0
        self.start_time = None
    
    def setup_socket(self) -> bool:
        """Setup and bind the UDP socket."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            if self.timeout:
                self.sock.settimeout(self.timeout)
            
            self.sock.bind((self.bind_address, self.port))
            print(f"✓ UDP Echo Server started")
            print(f"  Listening on {self.bind_address}:{self.port}")
            print(f"  Waiting for packets...")
            return True
        
        except socket.error as e:
            print(f"✗ Socket error: {e}")
            return False
        except PermissionError:
            print(f"✗ Permission denied: Cannot bind to port {self.port}")
            print(f"  Try using a port > 1024 or run with sudo")
            return False
        except Exception as e:
            print(f"✗ Unexpected error setting up socket: {e}")
            return False
    
    def handle_packet(self, data: bytes, client_address: Tuple[str, int]) -> bool:
        """
        Handle a single received packet by echoing it back.
        Returns True if successful, False otherwise.
        """
        try:
            # Echo the packet back to the sender
            self.sock.sendto(data, client_address)
            
            self.packets_received += 1
            self.packets_sent += 1
            self.bytes_received += len(data)
            self.bytes_sent += len(data)
            
            return True
        
        except socket.error as e:
            print(f"✗ Error sending echo: {e}")
            return False
        except Exception as e:
            print(f"✗ Unexpected error handling packet: {e}")
            return False
    
    def run(self) -> None:
        """Main server loop."""
        if not self.setup_socket():
            sys.exit(1)
        
        self.start_time = time.time()
        
        try:
            while self.running:
                try:
                    # Receive UDP packet
                    data, client_address = self.sock.recvfrom(65535)
                    
                    # Echo packet back
                    #self.handle_packet(data, client_address)
                    self.sock.sendto(data, ("192.168.100.2", client_address[1]))
                    
                    '''
                    # Print progress every 1000 packets
                    if self.packets_received % 1000 == 0:
                        elapsed = time.time() - self.start_time
                        rate = self.packets_received / elapsed if elapsed > 0 else 0
                        print(f"  Received {self.packets_received} packets "
                              f"({rate:.0f} pps, {self.bytes_received / (1024*1024):.2f} MB)")
                    '''
                except socket.timeout:
                    # Timeout is normal if no packets arrive
                    continue
                except KeyboardInterrupt:
                    print("\n\nShutting down...")
                    break
                except Exception as e:
                    print(f"✗ Error in main loop: {e}")
                    continue
        
        finally:
            self.shutdown()
    
    def shutdown(self) -> None:
        """Clean shutdown."""
        self.running = False
        
        elapsed = time.time() - self.start_time if self.start_time else 0
        
        print(f"\n{'='*60}")
        print("Server Statistics:")
        print(f"{'='*60}")
        print(f"Uptime: {elapsed:.2f} seconds")
        print(f"Packets received: {self.packets_received}")
        print(f"Packets echoed back: {self.packets_sent}")
        print(f"Data received: {self.bytes_received / (1024*1024):.2f} MB")
        print(f"Data sent: {self.bytes_sent / (1024*1024):.2f} MB")
        
        if elapsed > 0:
            print(f"Average rate: {self.packets_received / elapsed:.0f} packets/sec")
        
        if self.sock:
            self.sock.close()
            print(f"\n✓ Server stopped")

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully."""
    print("\n\nReceived shutdown signal")
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(
        description="UDP Echo Server for eBPF benchmark testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python udp_echo_server.py
  python udp_echo_server.py --port 5201 --bind 0.0.0.0
  python udp_echo_server.py --port 12345 --bind 192.168.1.100
  
Run on receiver side while benchmark tool runs on sender side.
The server will echo back all UDP packets received.
        """
    )
    
    parser.add_argument("--port", "-p", type=int, default=5201,
                       help="UDP port to listen on (default: 5201)")
    parser.add_argument("--bind", "-b", default="0.0.0.0",
                       help="IP address to bind to (default: 0.0.0.0 = all interfaces)")
    parser.add_argument("--timeout", "-t", type=int, default=None,
                       help="Socket timeout in seconds (default: None = blocking)")
    
    args = parser.parse_args()
    
    # Setup signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print("="*60)
    print("UDP Echo Server")
    print("="*60)
    
    server = UDPEchoServer(args.bind, args.port, args.timeout)
    server.run()

if __name__ == "__main__":
    main()
