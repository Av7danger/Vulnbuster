"""
Bug Bounty Agent for Mobile Application Security Testing.

This module provides advanced security testing capabilities specifically designed
for bug bounty hunters targeting mobile applications (Android/iOS).
"""
import asyncio
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any, Callable, Awaitable

import aiohttp
import frida
import numpy as np
from frida.core import Device as FridaDevice

from ..models import Finding, Severity, Platform
from .scanner import MobileScanner
from .analyzer import AdvancedMobileAnalyzer
from .dynamic_analyzer import DynamicAnalyzer, HookConfig, HookType
from .ai_model_trainer import AIModelTrainer
from .platform_checks import get_platform_checks, CheckType

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
    
    def __init__(self, target: BountyTarget, ai_model_dir: Optional[str] = None):
        """Initialize the bug bounty agent.
        
        Args:
            target: The target to test against
            ai_model_dir: Directory containing pre-trained AI models
        """
        self.target = target
        self.scanner = MobileScanner(platform=target.platform)
        self.analyzer = AdvancedMobileAnalyzer()
        self.dynamic_analyzer = None
        self.session = None
        self.device = None
        self.scripts = {}
        self.findings: List[Finding] = []
        self.script_dir = Path(__file__).parent / "scripts"
        self.script_dir.mkdir(exist_ok=True)
        self.ai_model = None
        self._setup_dynamic_analyzer()
        self._load_ai_models(ai_model_dir)
        self.platform_checks = get_platform_checks(target.platform)
        
    def _setup_dynamic_analyzer(self) -> None:
        """Initialize the dynamic analyzer with appropriate configuration."""
        # Common hooks for both platforms
        common_hooks = [
            HookConfig(
                name="http_request",
                type=HookType.API_CALL,
                target="http.*Request",
                on_enter="""
                var url = this.getURL().toString();
                var method = this.getMethod();
                var headers = this.getHeaders();
                var body = this.getBody();
                
                send({
                    type: 'http_request',
                    payload: {
                        url: url,
                        method: method,
                        headers: JSON.parse(JSON.stringify(headers, Object.getOwnPropertyNames(headers))),
                        body: body ? body.toString() : null
                    }
                });
                """
            )
        ]
        
        platform_specific_hooks = []
        if self.target.platform == Platform.ANDROID:
            platform_specific_hooks.extend([
                HookConfig(
                    name="shared_preferences",
                    type=HookType.JAVA_METHOD,
                    target="android.content.SharedPreferences$Editor.putString",
                    on_enter="""
                    var key = args[1];
                    var value = args[2];
                    
                    // Check for sensitive data
                    var sensitivePatterns = [
                        /password/i, /passwd/i, /secret/i, /api[_-]?key/i,
                        /token/i, /auth/i, /credential/i, /cert/i, /private[_-]?key/i
                    ];
                    
                    var isSensitive = sensitivePatterns.some(function(pattern) {
                        return pattern.test(key) || pattern.test(value);
                    });
                    
                    if (isSensitive) {
                        send({
                            type: 'sensitive_data_storage',
                            payload: {
                                storage_type: 'SharedPreferences',
                                key: key,
                                value: value,
                                stack: Thread.backtrace(this.context, Backtracer.ACCURATE)
                            }
                        });
                    }
                    """
                )
            ])
        elif self.target.platform == Platform.IOS:
            platform_specific_hooks.extend([
                HookConfig(
                    name="nsuserdefaults",
                    type=HookType.OBJC_METHOD,
                    target="-[NSUserDefaults setObject:forKey:]",
                    on_enter="""
                    var key = new ObjC.Object(args[2]);
                    var value = new ObjC.Object(args[3]);
                    
                    // Check for sensitive data (similar to Android)
                    var sensitivePatterns = [
                        /password/i, /passwd/i, /secret/i, /api[_-]?key/i,
                        /token/i, /auth/i, /credential/i, /cert/i, /private[_-]?key/i
                    ];
                    
                    var keyStr = key.toString();
                    var valueStr = value ? value.toString() : '';
                    
                    var isSensitive = sensitivePatterns.some(function(pattern) {
                        return pattern.test(keyStr) || pattern.test(valueStr);
                    });
                    
                    if (isSensitive) {
                        send({
                            type: 'sensitive_data_storage',
                            payload: {
                                storage_type: 'NSUserDefaults',
                                key: keyStr,
                                value: valueStr,
                                stack: Thread.backtrace(this.context, Backtracer.ACCURATE)
                            }
                        });
                    }
                    """
                )
            ])
        
        all_hooks = common_hooks + platform_specific_hooks
        self.dynamic_analyzer = DynamicAnalyzer(
            platform=self.target.platform,
            package_name=self.target.identifier,
            hooks=all_hooks
        )
        
    async def __aenter__(self):
        """Async context manager entry."""
        self.http_session = aiohttp.ClientSession()
        if self.dynamic_analyzer:
            await self.dynamic_analyzer.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.dynamic_analyzer:
            await self.dynamic_analyzer.stop()
        if self.http_session:
            await self.http_session.close()
        if self.session:
            await self.session.close()
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
        """Run a full assessment of the target."""
        try:
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
        
        # Run static analysis
        static_analyzer = AdvancedMobileAnalyzer(self.target.identifier, 'android')
        static_findings = await static_analyzer.analyze()
        self.findings.extend(static_findings)
        
        # Run platform-specific static checks
        static_checks = await self._run_platform_checks(CheckType.STATIC)
        self.findings.extend(static_checks)
        
        # Run dynamic analysis with Frida
        await self._setup_frida()
        await self._run_frida_scripts('android')
        
        # Run platform-specific runtime checks
        runtime_checks = await self._run_platform_checks(CheckType.RUNTIME)
        self.findings.extend(runtime_checks)
        
        # Run configuration checks
        config_checks = await self._run_platform_checks(CheckType.CONFIGURATION)
        self.findings.extend(config_checks)
        
        # Test for common Android vulnerabilities
        await self._test_android_vulnerabilities()
    
    async def _ios_assessment(self):
        """Run iOS-specific security tests."""
        logger.info("Starting iOS-specific security assessment...")
        
        # Run static analysis
        static_analyzer = AdvancedMobileAnalyzer(self.target.identifier, 'ios')
        static_findings = await static_analyzer.analyze()
        self.findings.extend(static_findings)
        
        # Run platform-specific static checks
        static_checks = await self._run_platform_checks(CheckType.STATIC)
        self.findings.extend(static_checks)
        
        # Run dynamic analysis with Frida
        await self._setup_frida()
        await self._run_frida_scripts('ios')
        
        # Run platform-specific runtime checks
        runtime_checks = await self._run_platform_checks(CheckType.RUNTIME)
        self.findings.extend(runtime_checks)
        
        # Run configuration checks
        config_checks = await self._run_platform_checks(CheckType.CONFIGURATION)
        self.findings.extend(config_checks)
        
        # Test for common iOS vulnerabilities
        await self._test_ios_vulnerabilities()
    
    async def _get_dynamic_analysis_data(self) -> Dict[str, Any]:
        """Get dynamic analysis data for AI processing."""
        if not self.dynamic_analyzer:
            return {}
            
        # Gather data for platform checks
        context = {
            'manifest': await self._get_manifest_data(),
            'webview': await self._get_webview_data(),
            'storage_ops': await self._get_storage_operations(),
            'crypto_usage': await self._get_crypto_usage(),
            'source_files': await self._get_source_files()
        }
        
        # Add platform-specific context
        if self.target.platform == Platform.ANDROID:
            context.update({
                'activities': await self._get_activities(),
                'services': await self._get_services(),
                'receivers': await self._get_receivers()
            })
        elif self.target.platform == Platform.IOS:
            context.update({
                'info_plist': await self._get_info_plist(),
                'keychain': await self._get_keychain_data(),
                'jailbreak': await self._get_jailbreak_data()
            })
        
        return context
    
    async def _run_platform_checks(self, check_type: CheckType) -> List[Finding]:
        """Run platform-specific security checks."""
        if not hasattr(self, 'platform_checks'):
            return []
            
        try:
            # Get the appropriate context for the checks
            context = {}
            
            if check_type == CheckType.STATIC:
                context = {
                    'manifest': await self._get_manifest_data(),
                    'source_files': await self._get_source_files()
                }
            elif check_type == CheckType.RUNTIME:
                context = {
                    'webview': await self._get_webview_data(),
                    'storage_ops': await self._get_storage_operations()
                }
                
                if self.target.platform == Platform.ANDROID:
                    context.update({
                        'activities': await self._get_activities(),
                        'services': await self._get_services(),
                        'receivers': await self._get_receivers()
                    })
                elif self.target.platform == Platform.IOS:
                    context.update({
                        'info_plist': await self._get_info_plist(),
                        'keychain': await self._get_keychain_data(),
                        'jailbreak': await self._get_jailbreak_data()
                    })
            elif check_type == CheckType.CONFIGURATION:
                context = {
                    'manifest': await self._get_manifest_data()
                }
                
                if self.target.platform == Platform.IOS:
                    context['info_plist'] = await self._get_info_plist()
            
            # Run the checks
            return self.platform_checks.run_checks(check_type, context)
            
        except Exception as e:
            logger.error(f"Error running platform checks: {str(e)}", exc_info=True)
            return [
                Finding(
                    title="Platform Check Error",
                    description=f"Error running {check_type.value} checks: {str(e)}",
                    severity=Severity.MEDIUM,
                    category="Analysis Error"
                )
            ]
    
    # Helper methods to gather platform-specific data
    async def _get_manifest_data(self) -> Dict[str, Any]:
        """Get Android manifest data."""
        if not hasattr(self, '_manifest_data'):
            if self.target.platform == Platform.ANDROID and hasattr(self, 'scanner'):
                self._manifest_data = await self.scanner.get_manifest() or {}
            else:
                self._manifest_data = {}
        return self._manifest_data
    
    async def _get_webview_data(self) -> Dict[str, Any]:
        """Get WebView configuration data."""
        if not hasattr(self, '_webview_data'):
            if hasattr(self, 'dynamic_analyzer'):
                self._webview_data = await self.dynamic_analyzer.get_webview_data() or {}
            else:
                self._webview_data = {}
        return self._webview_data
    
    async def _get_storage_operations(self) -> List[Dict[str, Any]]:
        """Get storage operation data."""
        if not hasattr(self, '_storage_ops'):
            if hasattr(self, 'dynamic_analyzer'):
                self._storage_ops = await self.dynamic_analyzer.get_storage_operations() or []
            else:
                self._storage_ops = []
        return self._storage_ops
    
    async def _get_crypto_usage(self) -> List[Dict[str, Any]]:
        """Get cryptography usage data."""
        if not hasattr(self, '_crypto_usage'):
            if hasattr(self, 'scanner'):
                self._crypto_usage = await self.scanner.get_crypto_usage() or []
            else:
                self._crypto_usage = []
        return self._crypto_usage
    
    async def _get_source_files(self) -> List[Path]:
        """Get source code files for analysis."""
        if not hasattr(self, '_source_files'):
            if hasattr(self, 'scanner'):
                self._source_files = await self.scanner.get_source_files() or []
            else:
                self._source_files = []
        return self._source_files
    
    async def _get_activities(self) -> List[Dict[str, Any]]:
        """Get Android activities."""
        manifest = await self._get_manifest_data()
        return manifest.get('activities', [])
    
    async def _get_services(self) -> List[Dict[str, Any]]:
        """Get Android services."""
        manifest = await self._get_manifest_data()
        return manifest.get('services', [])
    
    async def _get_receivers(self) -> List[Dict[str, Any]]:
        """Get Android broadcast receivers."""
        manifest = await self._get_manifest_data()
        return manifest.get('receivers', [])
    
    async def _get_info_plist(self) -> Dict[str, Any]:
        """Get iOS Info.plist data."""
        if not hasattr(self, '_info_plist'):
            if self.target.platform == Platform.IOS and hasattr(self, 'scanner'):
                self._info_plist = await self.scanner.get_info_plist() or {}
            else:
                self._info_plist = {}
        return self._info_plist
    
    async def _get_keychain_data(self) -> Dict[str, Any]:
        """Get iOS keychain data."""
        if not hasattr(self, '_keychain_data'):
            if hasattr(self, 'dynamic_analyzer'):
                self._keychain_data = await self.dynamic_analyzer.get_keychain_data() or {}
            else:
                self._keychain_data = {}
        return self._keychain_data
    
    async def _get_jailbreak_data(self) -> Dict[str, Any]:
        """Get jailbreak detection data."""
        if not hasattr(self, '_jailbreak_data'):
            if hasattr(self, 'dynamic_analyzer'):
                self._jailbreak_data = await self.dynamic_analyzer.get_jailbreak_data() or {}
            else:
                self._jailbreak_data = {}
        return self._jailbreak_data
    
    async def _test_common_vulnerabilities(self):
        """Test for common mobile vulnerabilities."""
        logger.info("Testing for common mobile vulnerabilities...")
        
        tests = [
            self._test_insecure_data_storage,
            self._test_insecure_communication,
            self._test_insecure_authentication,
            self._test_insecure_cryptography,
            self._test_code_tampering,
            self._test_reverse_engineering,
            self._test_extraneous_functionality
        ]
        
        await asyncio.gather(*[test() for test in tests], return_exceptions=True)
    
    async def _test_android_vulnerabilities(self):
        """Test for Android-specific vulnerabilities."""
        logger.info("Testing for Android-specific vulnerabilities...")
        
        tests = [
            self._test_debuggable_apps,
            self._test_backup_enabled,
            self._test_exported_components,
            self._test_webview_vulnerabilities,
            self._test_intent_scheme_urls,
            self._test_deep_links
        ]
        
        await asyncio.gather(*[test() for test in tests], return_exceptions=True)
    
    async def _test_ios_vulnerabilities(self):
        """Test for iOS-specific vulnerabilities."""
        logger.info("Testing for iOS-specific vulnerabilities...")
        
        tests = [
            self._test_jailbreak_detection_bypass,
            self._test_pasteboard_leakage,
            self._test_keychain_vulnerabilities,
            self._test_url_scheme_abuse,
            self._test_biometric_bypass
        ]
        
        await asyncio.gather(*[test() for test in tests], return_exceptions=True)
    
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
