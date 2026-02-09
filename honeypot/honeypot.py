#!/usr/bin/env python3
"""HTTP Honeypot - Simulates a vulnerable web application."""

import logging
import os
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime
import json
from urllib.parse import urlparse, parse_qs, unquote_plus
import threading
from logger import create_logger, parse_auth_from_data

# Determine log directory 
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def is_running_in_docker():
    """Check if we're running inside a Docker container."""
    # Check for .dockerenv file (most reliable)
    if os.path.exists('/.dockerenv'):
        return True
    # Check cgroup (fallback)
    try:
        with open('/proc/1/cgroup', 'r') as f:
            return 'docker' in f.read()
    except:
        return False

if is_running_in_docker():
    LOG_DIR = "/app/logs"
else:
    LOG_DIR = os.path.join(SCRIPT_DIR, "logs")

os.makedirs(LOG_DIR, exist_ok=True)

LOG_PATH = os.path.join(LOG_DIR, "honeypot.log")
ATTACK_LOG_PATH = os.path.join(LOG_DIR, "attacks.json")

connection_logger = create_logger(os.path.join(LOG_DIR, "connections.jsonl"))


def setup_logging():
    os.makedirs(LOG_DIR, exist_ok=True)
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
            
        
            with open(ATTACK_LOG_PATH, 'w') as f:
                json.dump(attacks, indent=2, fp=f)
        except Exception as e:
            logging.error(f"Failed to log attack to JSON: {e}")
    
    def analyze_request(self, method, path, headers, body=None, query_params=None):
        """Analyze if request looks like an attack."""
        suspicious = False
        attack_types = []

        decoded_path = unquote_plus(path or "")
        decoded_body = unquote_plus(body or "")
        decoded_query = ""
        if query_params:
            decoded_query = unquote_plus(json.dumps(query_params))

        combined_payload = " ".join([decoded_path, decoded_body, decoded_query])
        combined_lower = combined_payload.lower()

        # Check for SQL injection
        sql_keywords = ['select', 'union', 'drop', 'insert', '--', 'or 1=1', "' or '"]
        if any(keyword in combined_lower for keyword in sql_keywords):
            suspicious = True
            attack_types.append("SQL Injection")

        # Check for path traversal
        if '../' in combined_lower or '..\\' in combined_lower:
            suspicious = True
            attack_types.append("Path Traversal")

        # Check for XSS
        xss_patterns = ['<script>', 'javascript:', 'onerror=', 'onload=']
        if any(pattern in combined_lower for pattern in xss_patterns):
            suspicious = True
            attack_types.append("XSS Attempt")

        # Check for known vulnerable paths
        if any(vuln_path in decoded_path for vuln_path in self.VULNERABLE_PATHS):
            suspicious = True
            attack_types.append("Scanning for vulnerabilities")

        # Check for credential stuffing
        if 'password' in combined_lower or 'username' in combined_lower:
            suspicious = True
            attack_types.append("Credential attempt")

        if not attack_types:
            return False, "normal"

        return suspicious, "; ".join(attack_types)
    
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
        
        connection_id = f"{client_ip}:{client_port}:{timestamp}"
        
        connection_logger.start_connection(connection_id, client_ip, client_port)
    
        parsed_url = urlparse(path)
        query_params = parse_qs(parsed_url.query)

        suspicious, attack_type = self.analyze_request(method, path, headers, body, query_params)
        

        connection_logger.log_command(connection_id, f"{method} {path}")
       
        if body:
            connection_logger.log_data(connection_id, body, "POST body")
            
            # Authentication attempts
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
            # Simulate a fictional bank login page
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            response = """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Cedar Valley Bank | Secure Sign On</title>
                <style>
                    :root {
                        --ink: #1b1b1d;
                        --paper: #f7f2ea;
                        --clay: #c55a3a;
                        --bronze: #8e5d3b;
                        --pine: #500000;
                        --mist: #e7e1d7;
                    }
                    * { box-sizing: border-box; }
                    body {
                        margin: 0;
                        font-family: "Garamond", "Palatino Linotype", "Book Antiqua", serif;
                        color: var(--ink);
                        background: radial-gradient(1200px 600px at 10% -10%, #500000 0%, var(--paper) 40%, #efe7dd 100%);
                        min-height: 100vh;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        padding: 32px 16px;
                    }
                    .frame {
                        width: min(960px, 96vw);
                        display: grid;
                        grid-template-columns: 1.2fr 0.8fr;
                        gap: 24px;
                        background: #fff;
                        border: 1px solid var(--mist);
                        border-radius: 18px;
                        box-shadow: 0 18px 40px rgba(0, 0, 0, 0.12);
                        overflow: hidden;
                        animation: float-in 700ms ease-out;
                    }
                    .brand {
                        background: linear-gradient(135deg, var(--pine), #3d5f52 55%, #4b6a5a 100%);
                        color: #f4efe8;
                        padding: 36px 32px;
                        position: relative;
                    }
                    .brand:before {
                        content: "";
                        position: absolute;
                        right: -40px;
                        top: 30px;
                        width: 160px;
                        height: 160px;
                        border-radius: 50%;
                        background: rgba(255, 255, 255, 0.08);
                    }
                    .brand h1 {
                        margin: 0 0 8px 0;
                        font-size: 32px;
                        letter-spacing: 0.5px;
                    }
                    .brand p {
                        margin: 0 0 16px 0;
                        font-size: 16px;
                        line-height: 1.5;
                        color: #e8e1d7;
                    }
                    .brand .badge {
                        display: inline-block;
                        padding: 6px 10px;
                        border: 1px solid rgba(255, 255, 255, 0.3);
                        border-radius: 999px;
                        font-size: 12px;
                        text-transform: uppercase;
                        letter-spacing: 1px;
                    }
                    .panel {
                        padding: 32px 32px 36px;
                    }
                    .panel h2 {
                        margin: 0 0 6px 0;
                        font-size: 24px;
                    }
                    .panel small {
                        color: #6b6256;
                    }
                    form {
                        margin-top: 18px;
                        display: grid;
                        gap: 14px;
                    }
                    label {
                        font-size: 13px;
                        letter-spacing: 0.4px;
                        text-transform: uppercase;
                        color: #6a5a4d;
                    }
                    input {
                        width: 100%;
                        padding: 12px 14px;
                        border: 1px solid var(--mist);
                        border-radius: 10px;
                        font-size: 16px;
                        background: #fffdf9;
                    }
                    button {
                        margin-top: 8px;
                        padding: 12px 14px;
                        border: none;
                        border-radius: 12px;
                        background: linear-gradient(135deg, var(--clay), var(--bronze));
                        color: #fff7ef;
                        font-size: 16px;
                        letter-spacing: 0.6px;
                        cursor: pointer;
                    }
                    .assist {
                        margin-top: 16px;
                        font-size: 14px;
                        color: #6b6256;
                        display: flex;
                        justify-content: space-between;
                        flex-wrap: wrap;
                        gap: 8px;
                    }
                    .assist span { text-decoration: underline; }
                    @keyframes float-in {
                        from { opacity: 0; transform: translateY(16px); }
                        to { opacity: 1; transform: translateY(0); }
                    }
                    @media (max-width: 820px) {
                        .frame { grid-template-columns: 1fr; }
                    }
                </style>
            </head>
            <body>
                <div class="frame">
                    <section class="brand">
                        <span class="badge">Demo Bank</span>
                        <h1>A&M Bank</h1>
                        <p>Secure sign-on for personal and small business banking. Monitor accounts, pay bills, and manage alerts from one place.</p>
                        <p>Need help? Call 1-800-555-0199.</p>
                    </section>
                    <section class="panel">
                        <h2>Sign on</h2>
                        <small>Enter your online ID and password to continue.</small>
                        <form action="/login" method="POST">
                            <div>
                                <label for="username">Online ID</label>
                                <input id="username" type="text" name="username" placeholder="Your online ID" autocomplete="username">
                            </div>
                            <div>
                                <label for="password">Password</label>
                                <input id="password" type="password" name="password" placeholder="Your password" autocomplete="current-password">
                            </div>
                            <button type="submit">Sign on securely</button>
                        </form>
                        <div class="assist">
                            <span>Forgot Online ID?</span>
                            <span>Enroll</span>
                            <span>Privacy & Security</span>
                        </div>
                    </section>
                </div>
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
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            response = "# Configuration file\nDB_HOST=localhost\nDB_USER=admin\n"
            self.wfile.write(response.encode())
        
        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            response = "<html><body><h1>404 Not Found</h1></body></html>"
            self.wfile.write(response.encode())
    
    def log_message(self, format, *args):
        """Override to prevent default HTTP server logging."""
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