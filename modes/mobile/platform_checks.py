"""
Platform-specific security checks for Android and iOS.

This module contains platform-specific security checks for Android and iOS applications,
including checks for common vulnerabilities and misconfigurations.
"""
import logging
import re
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple

from ..models import Finding, Severity, Platform

logger = logging.getLogger(__name__)

class CheckType(Enum):
    """Types of security checks."""
    STATIC = "static"
    DYNAMIC = "dynamic"
    CONFIGURATION = "configuration"
    RUNTIME = "runtime"

class PlatformCheck:
    """Base class for platform-specific security checks."""
    
    def __init__(self, platform: Platform):
        self.platform = platform
        self.checks = self._initialize_checks()
    
    def _initialize_checks(self) -> Dict[str, Dict[str, Any]]:
        raise NotImplementedError("Subclasses must implement _initialize_checks")
    
    def get_checks(self, check_type: Optional[CheckType] = None) -> List[Dict[str, Any]]:
        if check_type is None:
            return list(self.checks.values())
        return [check for check in self.checks.values() if check['type'] == check_type]
    
    def run_check(self, check_id: str, context: Dict[str, Any]) -> List[Finding]:
        if check_id not in self.checks:
            logger.warning(f"Unknown check ID: {check_id}")
            return []
        
        try:
            return self.checks[check_id]['function'](context)
        except Exception as e:
            logger.error(f"Error running check {check_id}: {str(e)}", exc_info=True)
            return [
                Finding(
                    title=f"Check Execution Error: {check_id}",
                    description=f"An error occurred: {str(e)}",
                    severity=Severity.MEDIUM,
                    category="Check Error"
                )
            ]
    
    def run_checks(self, check_type: Optional[CheckType] = None, context: Optional[Dict[str, Any]] = None) -> List[Finding]:
        context = context or {}
        findings = []
        for check_id in self.checks:
            if check_type is None or self.checks[check_id]['type'] == check_type:
                findings.extend(self.run_check(check_id, context))
        return findings

class AndroidSecurityChecks(PlatformCheck):
    """Android-specific security checks."""
    
    def __init__(self):
        super().__init__(Platform.ANDROID)
    
    def _initialize_checks(self) -> Dict[str, Dict[str, Any]]:
        return {
            'debuggable': self._check_config('Debug Mode', 'Application is debuggable', CheckType.CONFIGURATION, Severity.HIGH, self._check_debuggable),
            'backup': self._check_config('Backup Config', 'Insecure backup settings', CheckType.CONFIGURATION, Severity.MEDIUM, self._check_backup),
            'webview_ssl': self._check_config('WebView SSL', 'WebView SSL issues', CheckType.RUNTIME, Severity.HIGH, self._check_webview_ssl),
            'exported': self._check_config('Exported Components', 'Insecure exported components', CheckType.STATIC, Severity.HIGH, self._check_exported_components),
            'secrets': self._check_config('Hardcoded Secrets', 'Hardcoded sensitive data', CheckType.STATIC, Severity.HIGH, self._check_secrets),
            'storage': self._check_config('Insecure Storage', 'Insecure data storage', CheckType.RUNTIME, Severity.HIGH, self._check_storage),
            'crypto': self._check_config('Crypto Issues', 'Insecure cryptography', CheckType.STATIC, Severity.HIGH, self._check_crypto)
        }
    
    def _check_config(self, title: str, desc: str, check_type: CheckType, severity: Severity, func):
        return {
            'title': title,
            'description': desc,
            'type': check_type,
            'severity': severity,
            'function': func
        }
    
    def _check_debuggable(self, context: Dict[str, Any]) -> List[Finding]:
        manifest = context.get('manifest', {})
        if manifest.get('application', {}).get('android:debuggable') == 'true':
            return [
                Finding(
                    title="Debug Mode Enabled",
                    description="App is debuggable in release build",
                    severity=Severity.HIGH,
                    category="Insecure Config"
                )
            ]
        return []
    
    def _check_backup(self, context: Dict[str, Any]) -> List[Finding]:
        manifest = context.get('manifest', {})
        app = manifest.get('application', {})
        if app.get('android:allowBackup') == 'true' and 'android:fullBackupContent' not in app:
            return [
                Finding(
                    title="Insecure Backup Config",
                    description="Backup enabled without proper config",
                    severity=Severity.MEDIUM,
                    category="Insecure Config"
                )
            ]
        return []
    
    def _check_webview_ssl(self, context: Dict[str, Any]) -> List[Finding]:
        webview = context.get('webview', {})
        if webview.get('ignores_ssl_errors'):
            return [
                Finding(
                    title="WebView Ignores SSL Errors",
                    description="WebView configured to ignore SSL errors",
                    severity=Severity.HIGH,
                    category="Insecure Communication"
                )
            ]
        return []
    
    def _check_exported_components(self, context: Dict[str, Any]) -> List[Finding]:
        manifest = context.get('manifest', {})
        findings = []
        
        def check_components(components, ctype):
            for comp in components:
                if comp.get('exported') and not comp.get('permission'):
                    findings.append(
                        Finding(
                            title=f"Insecure Exported {ctype}",
                            description=f"{ctype} exported without permission: {comp.get('name')}",
                            severity=Severity.HIGH,
                            category="Insecure Config"
                        )
                    )
        
        check_components(manifest.get('activities', []), 'Activity')
        check_components(manifest.get('services', []), 'Service')
        check_components(manifest.get('receivers', []), 'BroadcastReceiver')
        
        return findings
    
    def _check_secrets(self, context: Dict[str, Any]) -> List[Finding]:
        findings = []
        for file_path in context.get('source_files', []):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    if re.search(r'(?i)(password|api[_-]?key|secret|token)', content):
                        findings.append(
                            Finding(
                                title="Potential Hardcoded Secret",
                                description=f"Sensitive string found in {file_path.name}",
                                severity=Severity.HIGH,
                                category="Hardcoded Secret"
                            )
                        )
            except Exception as e:
                logger.warning(f"Error checking {file_path}: {str(e)}")
        return findings
    
    def _check_storage(self, context: Dict[str, Any]) -> List[Finding]:
        findings = []
        for storage in context.get('storage_ops', []):
            if storage.get('type') == 'external' and storage.get('sensitive'):
                findings.append(
                    Finding(
                        title="Sensitive Data in External Storage",
                        description=f"Sensitive data written to external storage: {storage.get('path')}",
                        severity=Severity.HIGH,
                        category="Insecure Storage"
                    )
                )
        return findings
    
    def _check_crypto(self, context: Dict[str, Any]) -> List[Finding]:
        findings = []
        for crypto in context.get('crypto_usage', []):
            if crypto.get('algorithm') in ['MD5', 'SHA1']:
                findings.append(
                    Finding(
                        title="Weak Cryptographic Algorithm",
                        description=f"Insecure algorithm used: {crypto.get('algorithm')}",
                        severity=Severity.HIGH,
                        category="Insecure Cryptography"
                    )
                )
        return findings

class IOSSecurityChecks(PlatformCheck):
    """iOS-specific security checks."""
    
    def __init__(self):
        super().__init__(Platform.IOS)
    
    def _initialize_checks(self) -> Dict[str, Dict[str, Any]]:
        return {
            'plist': self._check_config('Plist Security', 'Insecure plist settings', CheckType.CONFIGURATION, Severity.HIGH, self._check_plist),
            'keychain': self._check_config('Keychain', 'Insecure keychain usage', CheckType.RUNTIME, Severity.HIGH, self._check_keychain),
            'webview': self._check_config('WebView', 'WebView security issues', CheckType.RUNTIME, Severity.HIGH, self._check_webview),
            'jailbreak': self._check_config('Jailbreak', 'Jailbreak detection', CheckType.RUNTIME, Severity.MEDIUM, self._check_jailbreak)
        }
    
    def _check_config(self, title: str, desc: str, check_type: CheckType, severity: Severity, func):
        return {
            'title': title,
            'description': desc,
            'type': check_type,
            'severity': severity,
            'function': func
        }
    
    def _check_plist(self, context: Dict[str, Any]) -> List[Finding]:
        plist = context.get('info_plist', {})
        findings = []
        
        # Check ATS exceptions
        ats = plist.get('NSAppTransportSecurity', {})
        if ats.get('NSAllowsArbitraryLoads'):
            findings.append(
                Finding(
                    title="Insecure ATS Configuration",
                    description="ATS allows arbitrary loads",
                    severity=Severity.HIGH,
                    category="Insecure Config"
                )
            )
        
        # Check custom URL schemes
        for url_type in plist.get('CFBundleURLTypes', []):
            for scheme in url_type.get('CFBundleURLSchemes', []):
                if scheme.lower() not in ['http', 'https', 'ftp']:
                    findings.append(
                        Finding(
                            title="Custom URL Scheme",
                            description=f"Custom URL scheme registered: {scheme}",
                            severity=Severity.MEDIUM,
                            category="App Security"
                        )
                    )
        
        return findings
    
    def _check_keychain(self, context: Dict[str, Any]) -> List[Finding]:
        keychain = context.get('keychain', {})
        findings = []
        
        for item in keychain.get('items', []):
            if item.get('accessibility') == 'kSecAttrAccessibleAlways':
                findings.append(
                    Finding(
                        title="Insecure Keychain Item",
                        description=f"Keychain item with insecure accessibility: {item.get('account')}",
                        severity=Severity.HIGH,
                        category="Insecure Storage"
                    )
                )
        
        return findings
    
    def _check_webview(self, context: Dict[str, Any]) -> List[Finding]:
        webview = context.get('webview', {})
        findings = []
        
        if webview.get('javascript_enabled'):
            findings.append(
                Finding(
                    title="JavaScript Enabled in WebView",
                    description="JavaScript is enabled in WebView",
                    severity=Severity.MEDIUM,
                    category="Web Security"
                )
            )
        
        return findings
    
    def _check_jailbreak(self, context: Dict[str, Any]) -> List[Finding]:
        jailbreak = context.get('jailbreak', {})
        if not jailbreak.get('detection_implemented'):
            return [
                Finding(
                    title="Missing Jailbreak Detection",
                    description="No jailbreak detection implemented",
                    severity=Severity.MEDIUM,
                    category="App Security"
                )
            ]
        return []

def get_platform_checks(platform: Platform) -> PlatformCheck:
    """Get the appropriate platform checks for the given platform."""
    if platform == Platform.ANDROID:
        return AndroidSecurityChecks()
    elif platform == Platform.IOS:
        return IOSSecurityChecks()
    else:
        raise ValueError(f"Unsupported platform: {platform}")
