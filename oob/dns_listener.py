import socket
import threading
import logging
import time
import json
from datetime import datetime

class DNSListener:
    def __init__(self, domain='oob.webblood.local', port=53):
        self.domain = domain
        self.port = port
        self.running = False
        self.queries = []
        self.server_socket = None

    def start(self):
        """Start DNS listener server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.server_socket.bind(('0.0.0.0', self.port))
            self.running = True
            
            logging.info(f"DNS listener started on port {self.port} for domain {self.domain}")
            
            while self.running:
                try:
                    data, addr = self.server_socket.recvfrom(1024)
                    self.handle_dns_query(data, addr)
                except Exception as e:
                    if self.running:
                        logging.error(f"DNS listener error: {e}")
                        
        except Exception as e:
            logging.error(f"Failed to start DNS listener: {e}")
        finally:
            if self.server_socket:
                self.server_socket.close()

    def handle_dns_query(self, data, addr):
        """Handle incoming DNS query"""
        try:
            # Parse DNS query (simplified)
            query = self.parse_dns_query(data)
            if query:
                timestamp = datetime.now().isoformat()
                query_info = {
                    'timestamp': timestamp,
                    'source_ip': addr[0],
                    'source_port': addr[1],
                    'query': query,
                    'type': 'DNS'
                }
                
                self.queries.append(query_info)
                logging.info(f"DNS query from {addr[0]}: {query}")
                
                # Check if query contains OOB payload indicators
                if self.is_oob_payload(query):
                    logging.warning(f"OOB payload detected in DNS query: {query}")
                
        except Exception as e:
            logging.error(f"Error handling DNS query: {e}")

    def parse_dns_query(self, data):
        """Parse DNS query data (simplified implementation)"""
        try:
            # This is a simplified DNS parser
            # In a real implementation, you'd use a proper DNS library
            if len(data) > 12:
                # Extract query name (simplified)
                query_part = data[12:]
                query_name = ""
                i = 0
                while i < len(query_part) and query_part[i] != 0:
                    length = query_part[i]
                    if i + 1 + length <= len(query_part):
                        query_name += query_part[i+1:i+1+length].decode('utf-8', errors='ignore') + "."
                    i += length + 1
                return query_name.rstrip('.')
        except Exception:
            pass
        return None

    def is_oob_payload(self, query):
        """Check if DNS query contains OOB payload indicators"""
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
            'rfi'
        ]
        
        query_lower = query.lower()
        return any(indicator in query_lower for indicator in oob_indicators)

    def stop(self):
        """Stop DNS listener"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        logging.info("DNS listener stopped")

    def get_queries(self):
        """Get all recorded queries"""
        return self.queries

    def save_queries(self, filename='dns_queries.json'):
        """Save queries to JSON file"""
        try:
            with open(filename, 'w') as f:
                json.dump(self.queries, f, indent=2)
            logging.info(f"DNS queries saved to {filename}")
        except Exception as e:
            logging.error(f"Failed to save DNS queries: {e}")

    def clear_queries(self):
        """Clear recorded queries"""
        self.queries = []
        logging.info("DNS queries cleared") 