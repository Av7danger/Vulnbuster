"""
Bug Bounty Toolkit for Mobile Application Security Testing.

This module provides advanced security testing capabilities specifically designed
for bug bounty hunters targeting mobile applications (Android/iOS).
"""
import asyncio
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any, Callable, Awaitable

import aiohttp
import frida
from androguard.core.bytecodes.apk import APK
from frida.core import Device as FridaDevice

from ..models import Finding, Severity, Platform
from .scanner import MobileScanner
from .advanced_analysis import AdvancedMobileAnalyzer

logger = logging.getLogger(__name__)

class BountyTargetType(Enum):
    ANDROID_APP = "android_app"
    IOS_APP = "ios_app"
    API_ENDPOINT = "api_endpoint"
    WEBSOCKET = "websocket"

@dataclass
class BountyTarget:
    """Represents a target for bug bounty hunting."""
    target_type: BountyTargetType
    identifier: str  # package name, bundle ID, or URL
    platform: Platform
    endpoints: List[str] = field(default_factory=list)
    custom_headers: Dict[str, str] = field(default_factory=dict)
    authentication: Optional[Dict[str, Any]] = None

class BugBountyAgent:
    """Advanced agent for mobile application bug bounty hunting."""
    
    def __init__(self, target: BountyTarget):
        """Initialize the bug bounty agent.
        
        Args:
            target: The target to test against
        """
        self.target = target
        self.temp_dir = Path(tempfile.mkdtemp(prefix="vulnbuster_bounty_"))
        self.session = None
        self.frida_device: Optional[FridaDevice] = None
        self.frida_session = None
        self.scripts = {}
        self.findings: List[Finding] = []
        self.http_session = None
        self._setup_directories()
    
    async def __aenter__(self):
        """Async context manager entry."""
        self.http_session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.http_session:
            await self.http_session.close()
        self._cleanup()
    
    def _setup_directories(self):
        """Set up working directories."""
        self.reports_dir = self.temp_dir / "reports"
        self.tools_dir = self.temp_dir / "tools"
        self.data_dir = self.temp_dir / "data"
        
        for d in [self.reports_dir, self.tools_dir, self.data_dir]:
            d.mkdir(exist_ok=True, parents=True)
    
    def _cleanup(self):
        """Clean up temporary files and resources."""
        try:
            if self.temp_dir.exists():
                shutil.rmtree(self.temp_dir)
        except Exception as e:
            logger.warning(f"Failed to clean up temporary directory: {e}")
    
    async def run_full_assessment(self) -> List[Finding]:
        """Run a comprehensive security assessment of the target."""
        try:
            logger.info(f"Starting comprehensive security assessment for {self.target.identifier}")
            
            # Initial reconnaissance
            await self._gather_intel()
            
            # Run platform-specific assessments
            if self.target.platform == Platform.ANDROID:
                await self._android_assessment()
            elif self.target.platform == Platform.IOS:
                await self._ios_assessment()
            
            # Run common mobile tests
            await self._test_common_vulnerabilities()
            
            # Test API endpoints if any
            if self.target.endpoints:
                await self._test_api_endpoints()
            
            # Generate comprehensive report
            report = self._generate_report()
            
            logger.info(f"Assessment completed. Found {len(self.findings)} security issues.")
            return self.findings
            
        except Exception as e:
            logger.error(f"Error during assessment: {str(e)}", exc_info=True)
            raise
    
    async def _gather_intel(self):
        """Gather intelligence about the target."""
        logger.info("Gathering intelligence about the target...")
        
        tasks = [
            self._check_third_party_services(),
            self._check_dns_records(),
            self._check_technologies(),
            self._search_exploits()
        ]
        
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _android_assessment(self):
        """Run Android-specific security tests."""
        logger.info("Starting Android-specific security assessment...")
        
        # Static analysis
        static_analyzer = AdvancedMobileAnalyzer(self.target.identifier, 'android')
        static_findings = await static_analyzer.analyze()
        self.findings.extend(static_findings)
        
        # Dynamic analysis with Frida
        await self._setup_frida()
        await self._run_frida_scripts('android')
        
        # Test for common Android vulnerabilities
        await self._test_android_vulnerabilities()
    
    async def _ios_assessment(self):
        """Run iOS-specific security tests."""
        logger.info("Starting iOS-specific security assessment...")
        
        # Static analysis
        static_analyzer = AdvancedMobileAnalyzer(self.target.identifier, 'ios')
        static_findings = await static_analyzer.analyze()
        self.findings.extend(static_findings)
        
        # Dynamic analysis with Frida
        await self._setup_frida()
        await self._run_frida_scripts('ios')
        
        # Test for common iOS vulnerabilities
        await self._test_ios_vulnerabilities()
    
    async def _setup_frida(self):
        """Set up Frida for dynamic instrumentation."""
        try:
            self.frida_device = frida.get_usb_device()
            logger.info(f"Connected to Frida device: {self.frida_device}")
        except Exception as e:
            logger.error(f"Failed to connect to Frida device: {str(e)}")
            raise
    
    async def _run_frida_scripts(self, platform: str):
        """Run Frida scripts for dynamic analysis."""
        try:
            script_dir = Path(__file__).parent / "frida_scripts"
            if not script_dir.exists():
                logger.warning(f"Frida scripts directory not found: {script_dir}")
                return
            
            # Load and run platform-specific scripts
            for script_file in script_dir.glob(f"{platform}_*.js"):
                try:
                    with open(script_file, 'r') as f:
                        script_code = f.read()
                    
                    logger.info(f"Running Frida script: {script_file.name}")
                    session = await self.frida_device.attach(self.target.identifier)
                    script = await session.create_script(script_code)
                    
                    # Handle messages from the script
                    def on_message(message, data):
                        self._handle_frida_message(message, data, script_file.name)
                    
                    script.on('message', on_message)
                    await script.load()
                    self.scripts[script_file.stem] = script
                    
                except Exception as e:
                    logger.error(f"Error running Frida script {script_file}: {str(e)}")
        
        except Exception as e:
            logger.error(f"Error in Frida script execution: {str(e)}")
    
    def _handle_frida_message(self, message, data, script_name):
        """Handle messages from Frida scripts."""
        try:
            if message['type'] == 'send':
                payload = message.get('payload', {})
                if isinstance(payload, dict):
                    self._process_frida_finding(payload, script_name)
                else:
                    logger.debug(f"Received message from {script_name}: {payload}")
            elif message['type'] == 'error':
                logger.error(f"Error from Frida script {script_name}: {message}")
        except Exception as e:
            logger.error(f"Error handling Frida message: {str(e)}")
    
    def _process_frida_finding(self, finding: Dict[str, Any], source: str):
        """Process a security finding from Frida."""
        try:
            self.findings.append(
                Finding(
                    title=finding.get('title', 'Security Issue Detected'),
                    description=finding.get('description', ''),
                    severity=Severity.from_string(finding.get('severity', 'medium')),
                    context={
                        'source': f"frida:{source}",
                        'details': finding.get('details', {}),
                        'remediation': finding.get('remediation', '')
                    }
                )
            )
        except Exception as e:
            logger.error(f"Error processing Frida finding: {str(e)}")
    
    async def _test_common_vulnerabilities(self):
        """Test for common mobile vulnerabilities."""
        logger.info("Testing for common mobile vulnerabilities...")
        
        tests = [
            self._test_insecure_data_storage(),
            self._test_insecure_communication(),
            self._test_insecure_authentication(),
            self._test_insecure_cryptography(),
            self._test_code_tampering(),
            self._test_reverse_engineering(),
            self._test_extraneous_functionality()
        ]
        
        await asyncio.gather(*tests, return_exceptions=True)
    
    async def _test_android_vulnerabilities(self):
        """Test for Android-specific vulnerabilities."""
        logger.info("Testing for Android-specific vulnerabilities...")
        
        tests = [
            self._test_debuggable_apps(),
            self._test_backup_enabled(),
            self._test_exported_components(),
            self._test_webview_vulnerabilities(),
            self._test_intent_scheme_urls(),
            self._test_deep_links()
        ]
        
        await asyncio.gather(*tests, return_exceptions=True)
    
    async def _test_ios_vulnerabilities(self):
        """Test for iOS-specific vulnerabilities."""
        logger.info("Testing for iOS-specific vulnerabilities...")
        
        tests = [
            self._test_jailbreak_detection_bypass(),
            self._test_pasteboard_leakage(),
            self._test_keychain_vulnerabilities(),
            self._test_url_scheme_abuse(),
            self._test_biometric_bypass()
        ]
        
        await asyncio.gather(*tests, return_exceptions=True)
    
    async def _test_insecure_data_storage(self):
        """Test for insecure data storage issues."""
        # Implementation for testing insecure data storage
        pass
    
    async def _test_insecure_communication(self):
        """Test for insecure communication issues."""
        # Implementation for testing insecure communication
        pass
    
    async def _test_api_endpoints(self):
        """Test API endpoints for common vulnerabilities."""
        if not self.target.endpoints:
            return
        
        logger.info("Testing API endpoints for vulnerabilities...")
        
        for endpoint in self.target.endpoints:
            try:
                # Test for common API vulnerabilities
                tests = [
                    self._test_sql_injection(endpoint),
                    self._test_xss(endpoint),
                    self._test_ssrf(endpoint),
                    self._test_idor(endpoint),
                    self._test_jwt_issues(endpoint),
                    self._test_rate_limiting(endpoint)
                ]
                
                await asyncio.gather(*tests, return_exceptions=True)
                
            except Exception as e:
                logger.error(f"Error testing endpoint {endpoint}: {str(e)}")
    
    async def _test_sql_injection(self, endpoint: str):
        """Test for SQL injection vulnerabilities."""
        # Implementation for SQL injection testing
        pass
    
    async def _test_xss(self, endpoint: str):
        """Test for XSS vulnerabilities."""
        # Implementation for XSS testing
        pass
    
    async def _test_ssrf(self, endpoint: str):
        """Test for SSRF vulnerabilities."""
        # Implementation for SSRF testing
        pass
    
    async def _test_idor(self, endpoint: str):
        """Test for IDOR vulnerabilities."""
        # Implementation for IDOR testing
        pass
    
    async def _test_jwt_issues(self, endpoint: str):
        """Test for JWT implementation issues."""
        # Implementation for JWT testing
        pass
    
    async def _test_rate_limiting(self, endpoint: str):
        """Test for rate limiting issues."""
        # Implementation for rate limiting testing
        pass
    
    async def _check_third_party_services(self):
        """Check for third-party services used by the app."""
        # Implementation for checking third-party services
        pass
    
    async def _check_dns_records(self):
        """Check DNS records for subdomains and other information."""
        # Implementation for DNS enumeration
        pass
    
    async def _check_technologies(self):
        """Check for technologies used by the app."""
        # Implementation for technology detection
        pass
    
    async def _search_exploits(self):
        """Search for known exploits for the target."""
        # Implementation for exploit database searching
        pass
    
    def _generate_report(self) -> Dict[str, Any]:
        """Generate a comprehensive security report."""
        report = {
            'target': {
                'identifier': self.target.identifier,
                'type': self.target.target_type.value,
                'platform': self.target.platform.value,
                'endpoints': self.target.endpoints
            },
            'findings': [
                {
                    'title': f.title,
                    'description': f.description,
                    'severity': f.severity.value,
                    'context': f.context
                }
                for f in self.findings
            ],
            'summary': self._generate_summary(),
            'timestamp': datetime.utcnow().isoformat(),
            'metadata': {
                'tool': 'VulnBuster Bug Bounty Agent',
                'version': '1.0.0'
            }
        }
        
        # Save the report to a file
        report_path = self.reports_dir / f"{self.target.identifier}_report.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Report generated: {report_path}")
        return report
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate a summary of the findings."""
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for finding in self.findings:
            severity = finding.severity.value.lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return {
            'total_findings': len(self.findings),
            'severity_counts': severity_counts,
            'risk_score': self._calculate_risk_score(severity_counts)
        }
    
    def _calculate_risk_score(self, severity_counts: Dict[str, int]) -> float:
        """Calculate an overall risk score."""
        weights = {
            'critical': 10,
            'high': 7,
            'medium': 4,
            'low': 1,
            'info': 0.1
        }
        
        total_weight = 0
        total_count = 0
        
        for severity, count in severity_counts.items():
            total_weight += weights.get(severity, 0) * count
            total_count += count
        
        if total_count == 0:
            return 0.0
            
        # Normalize to 0-10 scale
        score = (total_weight / total_count) * 10
        return min(score, 10.0)

# Example usage
async def main():
    """Example usage of the BugBountyAgent."""
    target = BountyTarget(
        target_type=BountyTargetType.ANDROID_APP,
        identifier="com.example.vulnerableapp",
        platform=Platform.ANDROID,
        endpoints=["https://api.example.com/v1"]
    )
    
    async with BugBountyAgent(target) as agent:
        findings = await agent.run_full_assessment()
        
        # Print findings
        for finding in findings:
            print(f"[{finding.severity.value.upper()}] {finding.title}")

if __name__ == "__main__":
    asyncio.run(main())
