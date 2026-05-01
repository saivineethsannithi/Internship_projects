#!/usr/bin/env python3
"""
Network Scanner - Inlighn Tech Project (Windows Compatible)
Scans a local network to identify active devices using ARP requests and ICMP ping.
Retrieves IP addresses, MAC addresses, and hostnames.

Requirements:
    pip install scapy
    Run with Administrator privileges on Windows

Usage:
    python network_scanner.py (Windows will prompt for admin)
    sudo python network_scanner.py (Linux/Mac)
"""

import socket
import threading
import ipaddress
import subprocess
import platform
from queue import Queue
import sys

try:
    import scapy.all as scapy
    from scapy.layers.l2 import getmacbyip
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[!] scapy not installed. Run: pip install scapy")


def is_host_alive(ip: str) -> bool:
    """
    Check if a host is alive using ICMP ping.
    
    Args:
        ip (str): Target IP address to ping.
        
    Returns:
        bool: True if host is reachable, False otherwise.
    """
    try:
        # Windows uses -n, Linux/Mac use -c
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', '-w', '1000', ip]
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=3
        )
        return result.returncode == 0
    except Exception:
        return False


def get_mac_address(ip: str) -> str:
    """
    Get MAC address for a given IP using ARP.
    
    Args:
        ip (str): Target IP address.
        
    Returns:
        str: MAC address or "Unknown" if not found.
    """
    try:
        # Try using scapy's getmacbyip
        mac = getmacbyip(ip)
        if mac and mac != "ff:ff:ff:ff:ff:ff":
            return mac
    except Exception:
        pass
    
    # Fallback: Send ARP request
    try:
        arp = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp
        
        answered, _ = scapy.srp(packet, timeout=1, verbose=False)
        
        for sent, received in answered:
            return received.hwsrc
    except Exception:
        pass
    
    return "Unknown"


def get_hostname(ip: str) -> str:
    """
    Resolve hostname from IP address via reverse DNS lookup.
    
    Args:
        ip (str): Target IP address.
        
    Returns:
        str: Hostname or "Unknown" if resolution fails.
    """
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except (socket.herror, socket.error, OSError):
        return "Unknown"


def scan_network(cidr: str, result_queue: Queue, progress_queue: Queue) -> None:
    """
    Scan network by pinging each host and collecting device info.
    
    Args:
        cidr (str): Network range in CIDR notation.
        result_queue (Queue): Queue to store discovered devices.
        progress_queue (Queue): Queue to track scanning progress.
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        print(f"[!] Invalid CIDR notation: {e}")
        return
    
    hosts = list(network.hosts())
    total_hosts = len(hosts)
    
    def scan_single_host(ip: str, index: int) -> None:
        """Scan a single host."""
        try:
            # First, ping to check if host is alive
            if is_host_alive(str(ip)):
                mac = get_mac_address(str(ip))
                hostname = get_hostname(str(ip))
                
                result_queue.put({
                    "ip": str(ip),
                    "mac": mac,
                    "hostname": hostname
                })
            
            # Update progress
            progress_queue.put(index + 1)
        except Exception as e:
            progress_queue.put(index + 1)
    
    print(f"\n[*] Scanning {total_hosts} hosts on {cidr}...")
    print("[*] This may take a few moments — please wait.\n")
    
    threads = []
    
    # Create threads for parallel scanning
    for idx, ip in enumerate(hosts):
        t = threading.Thread(target=scan_single_host, args=(ip, idx))
        t.daemon = True
        t.start()
        threads.append(t)
    
    # Monitor progress
    completed = 0
    while completed < total_hosts:
        try:
            _ = progress_queue.get(timeout=1)
            completed += 1
            # Optional: Print progress every 50 hosts
            if completed % 50 == 0 or completed == total_hosts:
                print(f"[*] Progress: {completed}/{total_hosts} hosts checked")
        except:
            # Check if all threads are done
            if all(not t.is_alive() for t in threads):
                break
    
    # Wait for all threads to complete
    for t in threads:
        t.join()


def print_result(devices: list) -> None:
    """
    Display scan results in a formatted table.
    
    Args:
        devices (list): List of discovered device dicts.
    """
    if not devices:
        print("\n[!] No active devices found on the network.")
        print("[*] Troubleshooting tips:")
        print("    - Ensure you're running as Administrator on Windows")
        print("    - Try a smaller subnet (e.g., 192.168.1.0/25)")
        print("    - Verify your network CIDR is correct")
        print("    - Some networks may block ARP/ICMP requests\n")
        return
    
    col_ip = 18
    col_mac = 20
    col_host = 35
    
    separator = "+" + "-" * col_ip + "+" + "-" * col_mac + "+" + "-" * col_host + "+"
    header = f"|{'IP Address':^{col_ip}}|{'MAC Address':^{col_mac}}|{'Hostname':^{col_host}}|"
    
    print("\n" + "=" * len(separator))
    print(f"  Network Scan Results — {len(devices)} device(s) found")
    print("=" * len(separator))
    print(separator)
    print(header)
    print(separator)
    
    # Sort by IP address
    for device in sorted(devices, key=lambda d: tuple(map(int, d["ip"].split(".")))):
        ip_str = device["ip"]
        mac_str = device["mac"]
        host_str = device["hostname"]
        
        # Truncate long hostnames
        if len(host_str) > col_host - 2:
            host_str = host_str[:col_host - 5] + "..."
        
        print(f"|{ip_str:^{col_ip}}|{mac_str:^{col_mac}}|{host_str:^{col_host}}|")
    
    print(separator + "\n")


def main():
    """Main entry point."""
    print("=" * 55)
    print("    Network Scanner — Inlighn Tech Project (v2.0)")
    print("=" * 55)
    
    if not SCAPY_AVAILABLE:
        print("\n[!] scapy is not installed.")
        print("[*] Install it with: pip install scapy")
        sys.exit(1)
    
    # Get network input
    print("\n[!] IMPORTANT: Run this script as Administrator (Windows) or with sudo (Linux/Mac)")
    cidr = input("\nEnter network CIDR (e.g., 192.168.1.0/24): ").strip()
    
    if not cidr:
        cidr = "192.168.1.0/24"
        print(f"[*] Using default: {cidr}")
    
    # Validate CIDR
    try:
        ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        print(f"[!] Invalid CIDR notation: {cidr}")
        sys.exit(1)
    
    result_queue = Queue()
    progress_queue = Queue()
    
    # Run the scan
    scan_network(cidr, result_queue, progress_queue)
    
    # Collect results
    devices = []
    while not result_queue.empty():
        devices.append(result_queue.get())
    
    # Display results
    print_result(devices)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[*] Scan cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        sys.exit(1)
