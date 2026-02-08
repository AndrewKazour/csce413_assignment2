#!/usr/bin/env python3
"""Starter template for the port knocking server."""

import argparse
import logging
import socket
import time
import subprocess
from threading import Thread
from collections import defaultdict

DEFAULT_KNOCK_SEQUENCE = [3474, 5678, 9012]
DEFAULT_PROTECTED_PORT = 2222
DEFAULT_SEQUENCE_WINDOW = 10.0


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler()],
    )


def open_protected_port(protected_port, source_ip):
    """Open the protected port using firewall rules."""
    try:
        cmd = [
            "iptables",
            "-I", "INPUT",
            "-p", "tcp",
            "-s", source_ip,
            "--dport", str(protected_port),
            "-j", "ACCEPT"
        ]
        subprocess.run(cmd, check=True, capture_output=True)
        logging.info(f"✓ Opened port {protected_port} for {source_ip}")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to open port: {e.stderr.decode()}")
        return False
    except FileNotFoundError:
        logging.warning("iptables not found - running in demo mode (no firewall changes)")
        logging.info(f"[DEMO] Would open port {protected_port} for {source_ip}")
        return True


def close_protected_port(protected_port, source_ip):
    """Close the protected port using firewall rules."""
    try:
        cmd = [
            "iptables",
            "-D", "INPUT",
            "-p", "tcp",
            "-s", source_ip,
            "--dport", str(protected_port),
            "-j", "ACCEPT"
        ]
        subprocess.run(cmd, check=True, capture_output=True)
        logging.info(f"✗ Closed port {protected_port} for {source_ip}")
        return True
    except subprocess.CalledProcessError:
        # Rule might not exist
        return False
    except FileNotFoundError:
        logging.info(f"[DEMO] Would close port {protected_port} for {source_ip}")
        return True

def create_listener(port, tracker):
    """Create a UDP listener for a specific knock port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', port))
    
    logger = logging.getLogger(f"Listener-{port}")
    logger.info(f"Listening on UDP port {port}")
    
    while True:
        try:
            data, addr = sock.recvfrom(1024)
            source_ip = addr[0]
            logger.debug(f"Received knock from {source_ip}")
            tracker.handle_knock(source_ip, port)
        except Exception as e:
            logger.error(f"Error on port {port}: {e}")

def listen_for_knocks(sequence, window_seconds, protected_port):
    """Listen for knock sequence and open the protected port."""
    class KnockTracker:
        """Track knock sequences for each source IP."""
        
        def __init__(self, correct_sequence, window_seconds, protected_port):
            self.correct_sequence = correct_sequence
            self.window_seconds = window_seconds
            self.protected_port = protected_port
            self.progress = defaultdict(lambda: {"index": 0, "start_time": None, "knocks": []})
            self.authorized_ips = set()
        
        def handle_knock(self, source_ip, port):
            """Process a knock from a source IP on a specific port."""
            current_time = time.time()
            state = self.progress[source_ip]
            
            # Check new sequence 
            if state["start_time"] is None:
                state["start_time"] = current_time
                state["index"] = 0
                state["knocks"] = []
            
            # Check if sequence has timed out
            elapsed = current_time - state["start_time"]
            if elapsed > self.window_seconds:
                logging.warning(f"⏱ Timeout for {source_ip} (elapsed: {elapsed:.2f}s)")
                self.reset_progress(source_ip)
                state["start_time"] = current_time
                state["index"] = 0
                state["knocks"] = []
            
            # Check if this is the expected next knock
            expected_port = self.correct_sequence[state["index"]]
            
            if port == expected_port:
                state["knocks"].append(port)
                state["index"] += 1
                logging.info(f"✓ Valid knock {state['index']}/{len(self.correct_sequence)} from {source_ip} on port {port}")
                
                # Check if sequence is complete
                if state["index"] == len(self.correct_sequence):
                    logging.info(f"🎉 CORRECT SEQUENCE from {source_ip}!")
                    open_protected_port(self.protected_port, source_ip)
                    self.authorized_ips.add(source_ip)
                    self.reset_progress(source_ip)
                    
                    Thread(target=self.auto_close, args=(source_ip,), daemon=True).start()
            else:
                # Wrong port - reset 
                logging.warning(f"✗ Invalid knock from {source_ip}: got {port}, expected {expected_port}")
                logging.info(f"  Progress was: {state['knocks']} -> {port}")
                self.reset_progress(source_ip)
        
        def reset_progress(self, source_ip):
            """Reset knock progress for an IP."""
            self.progress[source_ip] = {"index": 0, "start_time": None, "knocks": []}
        
        def auto_close(self, source_ip, delay=60):
            """Automatically close the port after a delay."""
            time.sleep(delay)
            if source_ip in self.authorized_ips:
                close_protected_port(self.protected_port, source_ip)
                self.authorized_ips.remove(source_ip)
                logging.info(f"⏰ Auto-closed port {self.protected_port} for {source_ip} after {delay}s")
    
#main
    logger = logging.getLogger("KnockServer")
    logger.info("="*60)
    logger.info("Port Knocking Server Started")
    logger.info("="*60)
    logger.info(f"Knock sequence: {sequence}")
    logger.info(f"Protected port: {protected_port}")
    logger.info(f"Sequence window: {window_seconds} seconds")
    logger.info("="*60)
    
    # Create tracker
    tracker = KnockTracker(sequence, window_seconds, protected_port)
    
    # Create a UDP listener thread for each knock port
    threads = []
    for port in sequence:
        thread = Thread(target=create_listener, args=(port, tracker), daemon=True)
        thread.start()
        threads.append(thread)
    
    logger.info(f"Listening for knocks on ports: {sequence}")
    logger.info("Waiting for knock sequences...")
    
    # main thread
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("\nShutting down server...")


def parse_args():
    parser = argparse.ArgumentParser(description="Port knocking server starter")
    parser.add_argument(
        "--sequence",
        default=",".join(str(port) for port in DEFAULT_KNOCK_SEQUENCE),
        help="Comma-separated knock ports",
    )
    parser.add_argument(
        "--protected-port",
        type=int,
        default=DEFAULT_PROTECTED_PORT,
        help="Protected service port",
    )
    parser.add_argument(
        "--window",
        type=float,
        default=DEFAULT_SEQUENCE_WINDOW,
        help="Seconds allowed to complete the sequence",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    setup_logging()

    try:
        sequence = [int(port) for port in args.sequence.split(",")]
    except ValueError:
        raise SystemExit("Invalid sequence. Use comma-separated integers.")

    listen_for_knocks(sequence, args.window, args.protected_port)


if __name__ == "__main__":
    main()
