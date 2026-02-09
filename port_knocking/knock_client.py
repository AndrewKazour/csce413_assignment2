#!/usr/bin/env python3
"""Starter template for the port knocking client."""

import argparse
import socket
import time
import logging

DEFAULT_KNOCK_SEQUENCE = [3474, 5678, 9012]
DEFAULT_PROTECTED_PORT = 2222
DEFAULT_DELAY = 0.3

def setup_logging(verbose=False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler()],
    )



def send_knock(target, port, delay):
    """Send a single knock to the target port."""
    logger = logging.getLogger("KnockClient")
    
    try:
        #UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        
        # Send a simple knock message
        message = b"KNOCK"
        sock.sendto(message, (target, port))
        
        logger.info(f"→ Knocked on port {port}")
        
        sock.close()
        time.sleep(delay)
        return True
        
    except socket.error as e:
        logger.error(f"Failed to knock on port {port}: {e}")
        return False


def perform_knock_sequence(target, sequence, delay):
    """Send the full knock sequence."""
    logger = logging.getLogger("KnockClient")
    
    logger.info("="*60)
    logger.info("Port Knocking Client")
    logger.info("="*60)
    logger.info(f"Target: {target}")
    logger.info(f"Sequence: {sequence}")
    logger.info(f"Knock delay: {delay}s")
    logger.info("="*60)
    logger.info("Sending knock sequence...")
    
    success = True
    for i, port in enumerate(sequence, 1):
        logger.info(f"Knock {i}/{len(sequence)}: Port {port}")
        if not send_knock(target, port, delay):
            success = False
            break
    
    if success:
        logger.info("="*60)
        logger.info("✓ Knock sequence completed successfully!")
        logger.info("="*60)
    else:
        logger.error("✗ Failed to complete knock sequence")
    
    return success


def check_protected_port(target, protected_port):
    """Try connecting to the protected port after knocking."""
    logger = logging.getLogger("KnockClient")
    
    logger.info(f"\nTesting protected port {protected_port}...")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        
        result = sock.connect_ex((target, protected_port))
        sock.close()

            
    except socket.error as e:
        logger.error(f"Error testing port: {e}")
        return False

def parse_args():
    parser = argparse.ArgumentParser(description="Port knocking client starter")
    parser.add_argument("--target", required=True, help="Target host or IP")
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
        "--delay",
        type=float,
        default=DEFAULT_DELAY,
        help="Delay between knocks in seconds",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Attempt connection to protected port after knocking",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    setup_logging()  
    
    try:
        sequence = [int(port) for port in args.sequence.split(",")]
    except ValueError:
        raise SystemExit("Invalid sequence. Use comma-separated integers.")

    perform_knock_sequence(args.target, sequence, args.delay)

    if args.check:
        time.sleep(1) 
        check_protected_port(args.target, args.protected_port)


if __name__ == "__main__":
    main()
