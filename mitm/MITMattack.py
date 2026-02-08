from scapy.all import sniff, TCP, IP, Raw
from datetime import datetime
import sys

# Open log file
log_file = open("mysql_traffic.log", "a")

def log_and_print(message):
    """Print to console AND write to log file"""
    print(message)
    log_file.write(message + "\n")
    log_file.flush()  

def packet_handler(packet):
    if packet.haslayer(TCP) and (packet[TCP].dport == 3306 or packet[TCP].sport == 3306):
        # Get IP layer info
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        
        log_and_print(f"\n{'='*60}")
        log_and_print(f"MySQL Traffic Detected:")
        log_and_print(f"From: {src_ip}:{src_port} -> To: {dst_ip}:{dst_port}")
        
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            log_and_print(f"Payload length: {len(payload)} bytes")
            
            # Display
            try:
                readable = payload.decode('utf-8', errors='ignore')
                readable = ''.join(char if char.isprintable() or char in '\n\r\t' else '.' for char in readable)
                
                if len(readable.strip()) > 0:
                    log_and_print(f"Data:\n{readable[:5000]}")  # Show up to 5000 chars
                else:
                    log_and_print(f"Data (hex): {payload.hex()[:1000]}")
            except:
                log_and_print(f"Data (hex): {payload.hex()[:1000]}")
        else:
            log_and_print("No payload")

log_and_print(f"\n{'='*60}")
log_and_print(f"MySQL Packet Capture Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
log_and_print(f"{'='*60}\n")

try:
    # Sniff on the Docker bridge interface
    sniff(iface="br-bbf4b17196a4", filter="tcp port 3306", prn=packet_handler, store=False)
except KeyboardInterrupt:
    log_and_print(f"\n{'='*60}")
    log_and_print(f"Packet Capture Stopped: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log_and_print(f"{'='*60}")
    log_file.close()
    print("\nLog saved to mysql_traffic.log")