#!/usr/bin/env python3
"""
Port Scanner - Starter Template for Students
Assignment 2: Network Security

This is a STARTER TEMPLATE to help you get started.
You should expand and improve upon this basic implementation.

TODO for students:
1. Implement multi-threading for faster scans
2. Add banner grabbing to detect services
3. Add support for CIDR notation (e.g., 192.168.1.0/24)
4. Add different scan types (SYN scan, UDP scan, etc.)
5. Add output formatting (JSON, CSV, etc.)
6. Implement timeout and error handling
7. Add progress indicators
8. Add service fingerprinting
"""

import socket
import argparse
import json
import time
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


def scan_port(target, port, timeout=1.0, grab_banner_flag=False):
    """Scan a single port and optionally grab banner"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        if sock.connect_ex((target, port)) == 0:
            banner = ""
            
            if grab_banner_flag:
                try:
                    # Some services send banner immediately, others need a probe
                    sock.settimeout(2.0)  # Give more time for banner
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    
                    # If no banner, try sending a probe for HTTP-like services
                    if not banner and port in [80, 443, 8080, 5000, 8000]:
                        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                except:
                    pass
            
            sock.close()
            
            # Common service mapping
            services = {
                22: 'SSH', 80: 'HTTP', 443: 'HTTPS', 3306: 'MySQL',
                5000: 'Flask/HTTP', 6379: 'Redis', 8080: 'HTTP-Alt', 2222: 'SSH-Alt'
            }
            
            return {
                'port': port,
                'status': 'open',
                'service': services.get(port, 'unknown'),
                'banner': banner
            }
        
        sock.close()
        return None
    except:
        return None


def scan_host(target, start_port, end_port, threads=100, timeout=1.0, 
              grab_banner_flag=False, verbose=False):
    """Scan a range of ports on a single host"""
    open_ports = []
    total_ports = end_port - start_port + 1
    scanned = 0
    
    print(f"\n[*] Scanning {target} (ports {start_port}-{end_port})")
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_port, target, port, timeout, grab_banner_flag): port
            for port in range(start_port, end_port + 1)
        }
        
        for future in as_completed(futures):
            scanned += 1
            result = future.result()
            
            if result:
                open_ports.append(result)
                banner_info = f" - {result['banner'][:50]}" if result['banner'] else ""
                print(f"[+] Port {result['port']}/tcp open  {result['service']}{banner_info}")
            elif verbose:
                port = futures[future]
                print(f"[-] Port {port}/tcp closed")
            
            # Progress update every 100 ports or at end
            if scanned % 100 == 0 or scanned == total_ports:
                progress = (scanned / total_ports) * 100
                print(f"    Progress: {scanned}/{total_ports} ({progress:.1f}%)")
    
    elapsed = time.time() - start_time
    print(f"[✓] {target} completed in {elapsed:.2f}s - {len(open_ports)} open ports")
    
    return sorted(open_ports, key=lambda x: x['port'])


def parse_ports(port_spec):
    """Parse port specification (range or comma-separated)"""
    if ',' in port_spec:
        ports = [int(p.strip()) for p in port_spec.split(',')]
        return min(ports), max(ports)
    elif '-' in port_spec:
        start, end = map(int, port_spec.split('-'))
        return start, end
    else:
        port = int(port_spec)
        return port, port


def parse_targets(target_spec):
    """Parse target (single IP, hostname, or CIDR)"""
    try:
        network = ipaddress.ip_network(target_spec, strict=False)
        targets = [str(ip) for ip in network.hosts()]
        return targets if targets else [str(network.network_address)]
    except ValueError:
        return [target_spec]


def main():
    parser = argparse.ArgumentParser(
        description='Advanced Port Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''Examples:
  %(prog)s 172.20.0.10
  %(prog)s 172.20.0.10 -p 1-100
  %(prog)s 172.20.0.10 -p 80,443,3306
  %(prog)s 172.20.0.10 --banner
  %(prog)s 172.20.0.0/24 -p 22,80,443 --host-threads 8
        ''')
    
    parser.add_argument('target', help='Target IP, hostname, or CIDR (e.g., 172.20.0.0/24)')
    parser.add_argument('-p', '--ports', default='1-10000',
                        help='Port range (1-1024) or comma-separated (default: 1-10000)')
    parser.add_argument('-t', '--threads', type=int, default=100,
                        help='Threads per host (default: 100)')
    parser.add_argument('--host-threads', type=int, default=4,
                        help='Concurrent hosts to scan (default: 4)')
    parser.add_argument('--timeout', type=float, default=1.0,
                        help='Connection timeout in seconds (default: 1.0)')
    parser.add_argument('-b', '--banner', action='store_true',
                        help='Enable banner grabbing')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show closed ports')
    parser.add_argument('-o', '--output', help='Save results to JSON file')
    
    args = parser.parse_args()
    
    # Parse inputs
    start_port, end_port = parse_ports(args.ports)
    targets = parse_targets(args.target)
    
    # Print header
    print("=" * 60)
    print("Port Scanner")
    print(f"Target: {args.target}")
    if len(targets) > 1:
        print(f"Hosts: {len(targets)}")
    print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    # Scan all targets
    all_results = []
    
    if len(targets) > 1 and args.host_threads > 1:
        # Parallel host scanning
        print(f"\n[*] Scanning {len(targets)} hosts with {args.host_threads} concurrent threads")
        
        with ThreadPoolExecutor(max_workers=args.host_threads) as executor:
            futures = {
                executor.submit(scan_host, target, start_port, end_port, 
                               args.threads, args.timeout, args.banner, args.verbose): target
                for target in targets
            }
            
            completed = 0
            for future in as_completed(futures):
                completed += 1
                target = futures[future]
                open_ports = future.result()
                
                if open_ports:
                    all_results.append({'target': target, 'open_ports': open_ports})
                
                print(f"[*] Overall progress: {completed}/{len(targets)} hosts")
    else:
        # Sequential scanning
        for target in targets:
            open_ports = scan_host(target, start_port, end_port, 
                                  args.threads, args.timeout, args.banner, args.verbose)
            if open_ports:
                all_results.append({'target': target, 'open_ports': open_ports})
    
    # Display summary
    print(f"\n{'=' * 60}")
    print("[+] Scan Complete!")
    if len(targets) > 1:
        print(f"[+] Scanned: {len(targets)} hosts")
        print(f"[+] Found: {len(all_results)} hosts with open ports")
    print("=" * 60)
    
    # Display results
    for result in all_results:
        if len(targets) > 1:
            print(f"\n[*] Host: {result['target']}")
        
        print(f"\n{'PORT':<10} {'SERVICE':<15} {'BANNER'}")
        print("-" * 60)
        for port_info in result['open_ports']:
            banner = port_info['banner'][:40] + '...' if len(port_info['banner']) > 40 else port_info['banner']
            print(f"{port_info['port']:<10} {port_info['service']:<15} {banner}")
    
    # Save to JSON
    if args.output:
        output_data = {
            'target': args.target,
            'scan_date': datetime.now().isoformat(),
            'port_range': f"{start_port}-{end_port}",
            'results': all_results
        }
        with open(args.output, 'w') as f:
            json.dump(output_data, f, indent=2)
        print(f"\n[+] Results saved to {args.output}")


if __name__ == "__main__":
    main()
