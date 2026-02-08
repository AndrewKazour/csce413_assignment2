#!/usr/bin/env python3
"""HTTP Honeypot - Simulates a vulnerable web application."""

import logging
import os
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime
import json
from urllib.parse import urlparse, parse_qs
import threading
from logger import create_logger, parse_auth_from_data

LOG_PATH = "/app/logs/honeypot.log"
ATTACK_LOG_PATH = "/app/logs/attacks.json"

# Create connection logger instance
connection_logger = create_logger("/app/logs/connections.jsonl")


def setup_logging():
    os.makedirs("/app/logs", exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.FileHandler(LOG_PATH), logging.StreamHandler()],
    )


class HoneypotHTTPHandler(BaseHTTPRequestHandler):
    """HTTP request handler that logs all access attempts."""
    
    # Common vulnerable paths that attackers look for
    VULNERABLE_PATHS = [
        '/admin', '/login', '/phpmyadmin', '/wp-admin', 
        '/administrator', '/.env', '/config.php', '/backup',
        '/shell.php', '/cmd.php', '/.git/config'
    ]
    
    def log_attack(self, attack_data):
        """Log attack details to JSON file."""
        try:
            # Load existing attacks
            if os.path.exists(ATTACK_LOG_PATH):
                with open(ATTACK_LOG_PATH, 'r') as f:
                    attacks = json.load(f)
            else:
                attacks = []
            
            # Add new attack
            attacks.append(attack_data)
            
            # Save back
            with open(ATTACK_LOG_PATH, 'w') as f:
                json.dump(attacks, indent=2, fp=f)
        except Exception as e:
            logging.error(f"Failed to log attack to JSON: {e}")
    
    def analyze_request(self, method, path, headers, body=None):
        """Analyze if request looks like an attack."""
        suspicious = False
        attack_type = "normal"
        
        # Check for SQL injection
        sql_keywords = ['SELECT', 'UNION', 'DROP', 'INSERT', '--', 'OR 1=1', "' OR '"]
        if any(keyword.lower() in path.lower() for keyword in sql_keywords):
            suspicious = True
            attack_type = "SQL Injection"
        
        # Check for path traversal
        if '../' in path or '..\\' in path:
            suspicious = True
            attack_type = "Path Traversal"
        
        # Check for XSS
        xss_patterns = ['<script>', 'javascript:', 'onerror=', 'onload=']
        if any(pattern.lower() in path.lower() for pattern in xss_patterns):
            suspicious = True
            attack_type = "XSS Attempt"
        
        # Check for known vulnerable paths
        if any(vuln_path in path for vuln_path in self.VULNERABLE_PATHS):
            suspicious = True
            attack_type = "Scanning for vulnerabilities"
        
        # Check for credential stuffing
        if body and ('password' in body.lower() or 'username' in body.lower()):
            suspicious = True
            attack_type = "Credential attempt"
        
        return suspicious, attack_type
    
    def do_GET(self):
        """Handle GET requests."""
        self.handle_request('GET')
    
    def do_POST(self):
        """Handle POST requests."""
        # Read POST data
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8', errors='ignore') if content_length > 0 else None
        self.handle_request('POST', body)
    
    def do_HEAD(self):
        """Handle HEAD requests."""
        self.handle_request('HEAD')
    
    def handle_request(self, method, body=None):
        """Main request handler - logs and responds."""
        logger = logging.getLogger("Honeypot")
        
        # Extract request details
        client_ip = self.client_address[0]
        client_port = self.client_address[1]
        path = self.path
        headers = dict(self.headers)
        timestamp = datetime.now().isoformat()
        
        # Create unique connection ID
        connection_id = f"{client_ip}:{client_port}:{timestamp}"
        
        # Start connection logging
        connection_logger.start_connection(connection_id, client_ip, client_port)
        
        # Parse query parameters
        parsed_url = urlparse(path)
        query_params = parse_qs(parsed_url.query)
        
        # Analyze for attacks
        suspicious, attack_type = self.analyze_request(method, path, headers, body)
        
        # Log the command/request
        connection_logger.log_command(connection_id, f"{method} {path}")
        
        # Log request data if present
        if body:
            connection_logger.log_data(connection_id, body, "POST body")
            
            # Check for authentication attempts
            username, password = parse_auth_from_data(body)
            if username or password:
                connection_logger.log_auth_attempt(
                    connection_id, 
                    username=username, 
                    password=password,
                    auth_type="form"
                )
        
        # Log query parameters as data
        if query_params:
            connection_logger.log_data(connection_id, str(query_params), "query_params")
        
        # Log the attempt
        log_msg = f"{method} {path} from {client_ip}:{client_port}"
        if suspicious:
            logger.warning(f"SUSPICIOUS: {log_msg} - Type: {attack_type}")
        else:
            logger.info(f"{log_msg}")
        
        # Log data sent by user
        if body:
            logger.info(f"  📤 POST Data: {body}")
            # Log credentials if present
            username, password = parse_auth_from_data(body)
            if username or password:
                logger.warning(f"Credentials: username='{username}' password='{password}'")
        
        if query_params:
            logger.info(f"Query Params: {dict(query_params)}")
        
        # Create detailed attack record
        attack_data = {
            "timestamp": timestamp,
            "source_ip": client_ip,
            "source_port": client_port,
            "method": method,
            "path": path,
            "query_params": query_params,
            "headers": headers,
            "body": body,
            "user_agent": headers.get('User-Agent', 'Unknown'),
            "suspicious": suspicious,
            "attack_type": attack_type
        }
        
        # Log to JSON file
        self.log_attack(attack_data)
        
        # Send realistic response based on path
        self.send_response_based_on_path(path)
        
        # End connection logging with additional context
        connection_logger.end_connection(connection_id, {
            "method": method,
            "path": path,
            "user_agent": headers.get('User-Agent', 'Unknown'),
            "suspicious": suspicious,
            "attack_type": attack_type,
            "headers": headers
        })
    
    def send_response_based_on_path(self, path):
        """Send convincing responses based on requested path."""
        
        if path == '/' or path == '/index.html':
            # Simulate a login page
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            response = """
            <!DOCTYPE html>
            <html>
            <head><title>Admin Login</title></head>
            <body>
                <h1>Corporate Admin Panel</h1>
                <form action="/login" method="POST">
                    <input type="text" name="username" placeholder="Username"><br>
                    <input type="password" name="password" placeholder="Password"><br>
                    <button type="submit">Login</button>
                </form>
            </body>
            </html>
            """
            self.wfile.write(response.encode())
        
        elif path == '/login':
            # Simulate failed login
            self.send_response(401)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            response = "<html><body><h1>401 Unauthorized</h1><p>Invalid credentials</p></body></html>"
            self.wfile.write(response.encode())
        
        elif path in ['/admin', '/phpmyadmin', '/wp-admin']:
            # Simulate admin panel that exists but requires auth
            self.send_response(403)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            response = "<html><body><h1>403 Forbidden</h1><p>Access denied</p></body></html>"
            self.wfile.write(response.encode())
        
        elif '/.env' in path or '/config' in path:
            # Simulate config file (but actually empty/fake)
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            response = "# Configuration file\nDB_HOST=localhost\nDB_USER=admin\n"
            self.wfile.write(response.encode())
        
        else:
            # Defa  ult 404
            self.send_response(404)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            response = "<html><body><h1>404 Not Found</h1></body></html>"
            self.wfile.write(response.encode())
    
    def log_message(self, format, *args):
        """Override to prevent default HTTP server logging."""
        # We handle our own logging
        pass


def run_honeypot():
    logger = logging.getLogger("Honeypot")
    
    # Server configuration
    PORT = 8080
    
    logger.info("="*60)
    logger.info("HTTP Honeypot Starting")
    logger.info("="*60)
    logger.info(f"Listening on port {PORT}")
    logger.info(f"Logs: {LOG_PATH}")
    logger.info(f"Attack data: {ATTACK_LOG_PATH}")
    logger.info("="*60)
    
    # Create HTTP server
    server = HTTPServer(('0.0.0.0', PORT), HoneypotHTTPHandler)
    
    logger.info("Honeypot is running. Waiting for attacks...")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("\nShutting down honeypot...")
        server.shutdown()


if __name__ == "__main__":
    setup_logging()
    run_honeypot()