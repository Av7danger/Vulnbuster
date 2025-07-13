#!/usr/bin/env python3
"""
VulnBuster - Main Entry Point

This module provides the command-line interface for the VulnBuster application.
"""

import asyncio
import argparse
import logging
import sys
from pathlib import Path

from vulnbuster.core import VulnBusterApp
from vulnbuster.config import load_config, Config

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="VulnBuster - Offensive Security Automation Platform")
    
    # Core arguments
    parser.add_argument("target", help="Target URL, hostname, or IP address to scan")
    parser.add_argument("-c", "--config", help="Path to configuration file")
    parser.add_argument("-o", "--output", help="Output file for scan results")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    
    # Scan options
    scan_group = parser.add_argument_group("Scan Options")
    scan_group.add_argument("--mode", choices=["web", "network", "mobile", "cloud"], 
                          default="web", help="Scan mode (default: web)")
    scan_group.add_argument("--threads", type=int, default=10, 
                           help="Number of concurrent threads (default: 10)")
    scan_group.add_argument("--timeout", type=int, default=30, 
                           help="Request timeout in seconds (default: 30)")
    
    # Authentication
    auth_group = parser.add_argument_group("Authentication")
    auth_group.add_argument("-u", "--username", help="Username for authentication")
    auth_group.add_argument("-p", "--password", help="Password for authentication")
    auth_group.add_argument("--token", help="API token for authentication")
    
    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument("--format", choices=["json", "html", "text"], 
                             default="json", help="Output format (default: json)")
    output_group.add_argument("--no-color", action="store_true", 
                            help="Disable colored output")
    
    return parser.parse_args()

async def main():
    """Main entry point."""
    args = parse_arguments()
    
    # Set up logging
    log_level = logging.DEBUG if args.verbose or args.debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    try:
        # Load configuration
        config = {}
        if args.config:
            config = load_config(args.config)
        
        # Override with command line arguments
        config.update({
            "target": args.target,
            "mode": args.mode,
            "debug": args.debug,
            "scanner": {
                "threads": args.threads,
                "timeout": args.timeout
            },
            "auth": {
                "username": args.username,
                "password": args.password,
                "token": args.token
            },
            "output": {
                "format": args.format,
                "file": args.output,
                "color": not args.no_color
            }
        })
        
        # Create and initialize the application
        app = VulnBusterApp(config=Config(**config))
        await app.initialize()
        
        # Run the scan
        results = await app.run_scan(args.target)
        
        # Output results
        if args.output:
            with open(args.output, 'w') as f:
                f.write(str(results))
        else:
            print(results)
            
    except Exception as e:
        logging.error(f"Error: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        print("\nScan cancelled by user")
        sys.exit(130)
