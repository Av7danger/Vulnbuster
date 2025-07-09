import socket
import threading
import logging
import time
import json
import urllib.parse
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

class OOBHTTPRequestHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.queries = []
        super().__init__(*args, **kwargs)

    def do_GET(self):
        """Handle GET requests"""
        try:
            # Parse request
            parsed_url = urllib.parse.urlparse(self.path)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            # Log request
            timestamp = datetime.now().isoformat()
            request_info = {
                'timestamp': timestamp,
                'method': 'GET',
                'path': self.path,
                'query_params': query_params,
                'headers': dict(self.headers),
                'client_ip': self.client_address[0],
                'type': 'HTTP'
            }
            
            self.queries.append(request_info)
            logging.info(f"HTTP GET from {self.client_address[0]}: {self.path}")
            
            # Check for OOB payload indicators
            if self.is_oob_payload(self.path, query_params):
                logging.warning(f"OOB payload detected in HTTP request: {self.path}")
            
            # Send response
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"OK")
            
        except Exception as e:
            logging.error(f"Error handling GET request: {e}")
            self.send_error(500)

    def do_POST(self):
        """Handle POST requests"""
        try:
            # Get request body
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8', errors='ignore')
            
            # Parse request
            parsed_url = urllib.parse.urlparse(self.path)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            # Log request
            timestamp = datetime.now().isoformat()
            request_info = {
                'timestamp': timestamp,
                'method': 'POST',
                'path': self.path,
                'query_params': query_params,
                'body': body,
                'headers': dict(self.headers),
                'client_ip': self.client_address[0],
                'type': 'HTTP'
            }
            
            self.queries.append(request_info)
            logging.info(f"HTTP POST from {self.client_address[0]}: {self.path}")
            
            # Check for OOB payload indicators
            if self.is_oob_payload(self.path, query_params, body):
                logging.warning(f"OOB payload detected in HTTP POST: {self.path}")
            
            # Send response
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"OK")
            
        except Exception as e:
            logging.error(f"Error handling POST request: {e}")
            self.send_error(500)

    def is_oob_payload(self, path, query_params, body=''):
        """Check if request contains OOB payload indicators"""
        oob_indicators = [
            'oob',
            'webhook',
            'callback',
            'exfil',
            'leak',
            'test',
            'payload',
            'injection',
            'sqli',
            'xss',
            'lfi',
            'rfi',
            'blind',
            'time-based',
            'error-based'
        ]
        
        # Check path
        path_lower = path.lower()
        if any(indicator in path_lower for indicator in oob_indicators):
            return True
        
        # Check query parameters
        for param_name, param_values in query_params.items():
            param_name_lower = param_name.lower()
            if any(indicator in param_name_lower for indicator in oob_indicators):
                return True
            
            for param_value in param_values:
                param_value_lower = param_value.lower()
                if any(indicator in param_value_lower for indicator in oob_indicators):
                    return True
        
        # Check body
        body_lower = body.lower()
        if any(indicator in body_lower for indicator in oob_indicators):
            return True
        
        return False

    def log_message(self, format, *args):
        """Override to use our logging"""
        logging.info(f"HTTP Server: {format % args}")

class HTTPListener:
    def __init__(self, host='0.0.0.0', port=8080):
        self.host = host
        self.port = port
        self.server = None
        self.running = False
        self.queries = []

    def start(self):
        """Start HTTP listener server"""
        try:
            # Create custom request handler with queries list
            class CustomHandler(OOBHTTPRequestHandler):
                def __init__(self, *args, **kwargs):
                    self.queries = self.queries if hasattr(self, 'queries') else []
                    super().__init__(*args, **kwargs)
            
            # Set up server
            self.server = HTTPServer((self.host, self.port), CustomHandler)
            self.running = True
            
            logging.info(f"HTTP listener started on {self.host}:{self.port}")
            
            # Start server in a separate thread
            server_thread = threading.Thread(target=self.server.serve_forever)
            server_thread.daemon = True
            server_thread.start()
            
        except Exception as e:
            logging.error(f"Failed to start HTTP listener: {e}")

    def stop(self):
        """Stop HTTP listener"""
        self.running = False
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        logging.info("HTTP listener stopped")

    def get_queries(self):
        """Get all recorded queries"""
        return self.queries

    def save_queries(self, filename='http_queries.json'):
        """Save queries to JSON file"""
        try:
            with open(filename, 'w') as f:
                json.dump(self.queries, f, indent=2)
            logging.info(f"HTTP queries saved to {filename}")
        except Exception as e:
            logging.error(f"Failed to save HTTP queries: {e}")

    def clear_queries(self):
        """Clear recorded queries"""
        self.queries = []
        logging.info("HTTP queries cleared") 