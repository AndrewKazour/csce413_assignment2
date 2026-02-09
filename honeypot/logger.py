"""Logging helpers for the honeypot."""

import json
import logging
import os
from datetime import datetime
from typing import Optional, Dict, Any


class ConnectionLogger:
    """Logger for tracking honeypot connection attempts."""
    
    def __init__(self, log_file: str = "/app/logs/connections.jsonl"):
        """Initialize the connection logger.
        
        Args:
            log_file: Path to the JSONL log file
        """
        self.log_file = log_file
        self.connections = {}  # Track active connections by ID
        
        # Ensure log directory exists
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
    def start_connection(self, connection_id: str, source_ip: str, source_port: int) -> Dict[str, Any]:
        """Start tracking a new connection.
        
        Args:
            connection_id: Unique identifier for this connection
            source_ip: IP address of the connecting client
            source_port: Port number of the connecting client
            
        Returns:
            Connection data dictionary
        """
        connection_data = {
            "connection_id": connection_id,
            "source_ip": source_ip,
            "source_port": source_port,
            "timestamp_start": datetime.now().isoformat(),
            "timestamp_end": None,
            "duration_seconds": None,
            "commands": [],
            "data_sent": [],
            "auth_attempts": []
        }
        
        self.connections[connection_id] = connection_data
        return connection_data
    
    def log_command(self, connection_id: str, command: str, data: Optional[str] = None):
        """Log a command or request from the attacker.
        
        Args:
            connection_id: Connection identifier
            command: The command/request made
            data: Optional additional data
        """
        if connection_id in self.connections:
            command_entry = {
                "timestamp": datetime.now().isoformat(),
                "command": command,
                "data": data
            }
            self.connections[connection_id]["commands"].append(command_entry)
    
    def log_data(self, connection_id: str, data: str, data_type: str = "request"):
        """Log data sent by the attacker.
        
        Args:
            connection_id: Connection identifier
            data: The data sent
            data_type: Type of data (request, payload, etc.)
        """
        if connection_id in self.connections:
            data_entry = {
                "timestamp": datetime.now().isoformat(),
                "type": data_type,
                "data": data
            }
            self.connections[connection_id]["data_sent"].append(data_entry)
    
    def log_auth_attempt(self, connection_id: str, username: Optional[str] = None, 
                        password: Optional[str] = None, auth_type: str = "basic"):
        """Log an authentication attempt.
        
        Args:
            connection_id: Connection identifier
            username: Username attempted (if any)
            password: Password attempted (if any)
            auth_type: Type of authentication (basic, form, token, etc.)
        """
        if connection_id in self.connections:
            auth_entry = {
                "timestamp": datetime.now().isoformat(),
                "auth_type": auth_type,
                "username": username,
                "password": password
            }
            self.connections[connection_id]["auth_attempts"].append(auth_entry)
    
    def end_connection(self, connection_id: str, additional_data: Optional[Dict[str, Any]] = None):
        """End tracking for a connection and write to log file.
        
        Args:
            connection_id: Connection identifier
            additional_data: Optional additional data to include in the log
        """
        if connection_id in self.connections:
            connection_data = self.connections[connection_id]
            
            # Calculate duration
            timestamp_end = datetime.now()
            connection_data["timestamp_end"] = timestamp_end.isoformat()
            
            timestamp_start = datetime.fromisoformat(connection_data["timestamp_start"])
            duration = (timestamp_end - timestamp_start).total_seconds()
            connection_data["duration_seconds"] = round(duration, 3)
            
            # Add any additional data
            if additional_data:
                connection_data.update(additional_data)
            
            # Write to JSONL file (one JSON object per line)
            self._write_to_log(connection_data)
            
            # Remove from active connections
            del self.connections[connection_id]
    
    def _write_to_log(self, data: Dict[str, Any]):
        """Write a log entry to the JSONL file.
        
        Args:
            data: Dictionary to write as JSON
        """
        try:
            with open(self.log_file, 'a') as f:
                json.dump(data, f)
                f.write('\n')
        except Exception as e:
            logging.error(f"Failed to write to log file: {e}")
    
    def log_connection(self, source_ip: str, source_port: int, 
                      commands: list = None, data_sent: list = None,
                      auth_attempts: list = None, additional_data: Dict[str, Any] = None):
        """Log a complete connection in one call (for simple cases).
        
        Args:
            source_ip: IP address of the client
            source_port: Port number of the client
            commands: List of commands/requests made
            data_sent: List of data sent
            auth_attempts: List of authentication attempts
            additional_data: Any additional data to log
        """
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "source_ip": source_ip,
            "source_port": source_port,
            "commands": commands or [],
            "data_sent": data_sent or [],
            "auth_attempts": auth_attempts or []
        }
        
        if additional_data:
            log_entry.update(additional_data)
        
        self._write_to_log(log_entry)


def create_logger(log_file: str = "/app/logs/connections.jsonl") -> ConnectionLogger:
    """Create and return a ConnectionLogger instance.
    
    Args:
        log_file: Path to the JSONL log file
        
    Returns:
        ConnectionLogger instance
    """
    return ConnectionLogger(log_file)


def parse_auth_from_data(data: str) -> tuple[Optional[str], Optional[str]]:
    """Extract username and password from request data.
    
    Args:
        data: Request body or query string
        
    Returns:
        Tuple of (username, password)
    """
    username = None
    password = None
    
    if not data:
        return username, password
    
    # Try to parse as query string format 
    try:
        parts = data.split('&')
        for part in parts:
            if '=' in part:
                key, value = part.split('=', 1)
                if key.lower() in ['username', 'user', 'login', 'email']:
                    username = value
                elif key.lower() in ['password', 'pass', 'pwd']:
                    password = value
    except Exception:
        pass
    
    # Try to parse as JSON
    try:
        json_data = json.loads(data)
        if isinstance(json_data, dict):
            username = json_data.get('username') or json_data.get('user') or json_data.get('email')
            password = json_data.get('password') or json_data.get('pass')
    except Exception:
        pass
    
    return username, password
