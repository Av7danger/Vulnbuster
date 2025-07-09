#!/usr/bin/env python3
"""
CI/CD Runner for VulnBuster
Optimized for GitHub Actions, GitLab CI, and other CI/CD pipelines
"""

import asyncio
import json
import sys
import os
from pathlib import Path
from typing import Dict, Any, List

# Add VulnBuster to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from main import VulnBuster, build_config_from_args
import argparse

class CICDRunner:
    def __init__(self):
        self.results = []
        self.exit_code = 0
    
    async def run_scan(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Run VulnBuster scan with CI/CD optimizations"""
        try:
            # Force CI/CD mode settings
            config['ci_cd'] = True
            config['format'] = ['json']
            config['verbose'] = False
            config['debug'] = False
            
            # Create VulnBuster instance
            vulnbuster = VulnBuster(config)
            
            # Run scan
            results = await vulnbuster.run_scan()
            
            return {
                'status': 'success',
                'results': results,
                'summary': self._generate_summary(results)
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'results': []
            }
    
    def _generate_summary(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate CI/CD friendly summary"""
        vuln_types = {}
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        
        for result in results:
            vuln_type = result.get('type', 'unknown')
            severity = result.get('severity', 'medium')
            
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
            
            if severity == 'critical':
                critical_count += 1
            elif severity == 'high':
                high_count += 1
            elif severity == 'medium':
                medium_count += 1
            elif severity == 'low':
                low_count += 1
        
        return {
            'total_vulnerabilities': len(results),
            'critical': critical_count,
            'high': high_count,
            'medium': medium_count,
            'low': low_count,
            'vulnerability_types': vuln_types,
            'risk_score': self._calculate_risk_score(critical_count, high_count, medium_count, low_count)
        }
    
    def _calculate_risk_score(self, critical: int, high: int, medium: int, low: int) -> float:
        """Calculate overall risk score (0-10)"""
        return (critical * 10 + high * 7 + medium * 4 + low * 1) / max(1, critical + high + medium + low)
    
    def output_json(self, data: Dict[str, Any]):
        """Output clean JSON to stdout for CI/CD pipelines"""
        json.dump(data, sys.stdout, indent=2)
        sys.stdout.write('\n')
    
    def set_exit_code(self, summary: Dict[str, Any]):
        """Set exit code based on vulnerability severity"""
        if summary.get('critical', 0) > 0:
            self.exit_code = 1  # Critical vulns = failure
        elif summary.get('high', 0) > 0:
            self.exit_code = 2  # High vulns = warning
        else:
            self.exit_code = 0  # No critical/high vulns = success

async def main():
    """Main CI/CD entry point"""
    parser = argparse.ArgumentParser(description='VulnBuster CI/CD Runner')
    parser.add_argument('--target', required=True, help='Target URL/IP')
    parser.add_argument('--mode', default='web', help='Scan mode')
    parser.add_argument('--modules', help='Comma-separated vulnerability modules')
    parser.add_argument('--profile', help='Scan profile')
    parser.add_argument('--offline', action='store_true', help='Offline mode')
    parser.add_argument('--timeout', type=int, default=3600, help='Scan timeout in seconds')
    
    args = parser.parse_args()
    
    # Build config
    config = {
        'target': args.target,
        'mode': args.mode,
        'modules': args.modules.split(',') if args.modules else [],
        'profile': args.profile,
        'offline': args.offline,
        'timeout': args.timeout
    }
    
    # Run scan
    runner = CICDRunner()
    result = await runner.run_scan(config)
    
    # Output results
    runner.output_json(result)
    
    # Set exit code
    if result['status'] == 'success':
        runner.set_exit_code(result['summary'])
    else:
        runner.exit_code = 1
    
    sys.exit(runner.exit_code)

if __name__ == '__main__':
    asyncio.run(main()) 