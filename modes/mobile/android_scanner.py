"""
Android Security Scanner for VulnBuster.

This module provides functionality to scan Android applications (APK files)
for security vulnerabilities and misconfigurations.
"""
import asyncio
import logging
import re
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis
from androguard.misc import AnalyzeAPK

from ..models import Finding, Severity, Platform
from .scanner import MobileScanner
from .utils import extract_strings, run_command
from .advanced_analysis import AdvancedMobileAnalyzer

logger = logging.getLogger(__name__)

# Suspicious APIs to detect in DEX opcode analysis
SUSPICIOUS_APIS = [
    'java/lang/reflect',
    'dalvik/system/DexClassLoader',
    'dalvik/system/PathClassLoader',
    'loadClass',
    'getMethod',
    'invoke',
    'exec',
    'Runtime.getRuntime()',
    'getRuntime',
    'loadLibrary',
    'load',
    'getExternalStorage',
    'getExternalFilesDir',
    'getExternalCacheDir',
    'getExternalMediaDirs',
    'getExternalCacheDirs',
    'getExternalMediaDirs',
    'getExternalCacheDirs',
]

class AndroidScanner(MobileScanner):
    """Scanner for Android application security assessment."""
    
    def __init__(self, apk_path: str):
        """Initialize the Android scanner.
        
        Args:
            apk_path: Path to the APK file to scan
        """
        super().__init__(apk_path, Platform.ANDROID)
        self.apk: Optional[APK] = None
        self.dx: Optional[analysis.Analysis] = None
        self.temp_dir: Optional[Path] = None
        self._app_info: Dict[str, Any] = {}
        self.analysis = None
    
    def _extract_manifest_info(self) -> Dict[str, Any]:
        """Extract and parse AndroidManifest.xml."""
        try:
            manifest_data = self.apk.get_android_manifest_axml().get_xml()
            root = ET.fromstring(manifest_data)
            return root
        except Exception as e:
            logger.error(f"Error parsing AndroidManifest.xml: {str(e)}")
            return None

    async def _check_content_providers(self) -> List[Finding]:
        """Check for exported content providers without proper permission protection."""
        findings = []
        try:
            root = self._extract_manifest_info()
            if root is None:
                return findings
                
            ns = {'android': 'http://schemas.android.com/apk/res/android'}
            android_ns = '{' + ns['android'] + '}'
            
            for provider in root.findall('.//provider'):
                exported = provider.get(f"{android_ns}exported")
                name = provider.get(f"{android_ns}name")
                permission = provider.get(f"{android_ns}permission")
                
                if exported == 'true' and not permission:
                    findings.append(
                        Finding(
                            title="Exported Content Provider Without Permission",
                            description=f"Content provider '{name}' is exported but not protected by a permission.",
                            severity=Severity.HIGH,
                            context={
                                'provider': name,
                                'exported': True,
                                'permission': None,
                                'recommendation': "Add android:permission attribute or set android:exported to false if not needed."
                            }
                        )
                    )
        except Exception as e:
            logger.error(f"Error checking content providers: {str(e)}")
            
        return findings

    async def _analyze_dex_opcodes(self) -> List[Finding]:
        """Analyze DEX opcodes for suspicious API usage."""
        findings = []
        try:
            # Get all DEX files from the APK
            dex_files = []
            with zipfile.ZipFile(self.app_path, 'r') as z:
                for f in z.namelist():
                    if f.endswith('.dex'):
                        dex_files.append(f)
            
            # Analyze each DEX file
            for dex_file in dex_files:
                d = dvm.DalvikVMFormat(zipfile.ZipFile(self.app_path, 'r').read(dex_file))
                dx = analysis.Analysis(d)
                
                for method in d.get_methods():
                    code = method.get_code()
                    if code:
                        bytecode = code.get_bc()
                        for ins in bytecode.get_instructions():
                            output = ins.get_output()
                            for api in SUSPICIOUS_APIS:
                                if api in output:
                                    findings.append(
                                        Finding(
                                            title=f"Suspicious API Usage: {api}",
                                            description=f"Method {method.get_class_name()}.{method.get_name()} uses potentially dangerous API: {api}",
                                            severity=Severity.MEDIUM,
                                            context={
                                                'class': method.get_class_name(),
                                                'method': method.get_name(),
                                                'api': api,
                                                'recommendation': f"Review the usage of {api} and ensure it's properly secured."
                                            }
                                        )
                                    )
        except Exception as e:
            logger.error(f"Error analyzing DEX opcodes: {str(e)}")
            
        return findings

    async def _check_insecure_storage(self) -> List[Finding]:
        """Check for insecure data storage practices."""
        findings = []
        try:
            # Look for external storage usage
            strings = extract_strings(self.app_path)
            
            external_storage_indicators = [
                'getExternalStorage',
                'getExternalFilesDir',
                'getExternalCacheDir',
                'getExternalMediaDirs',
                'getExternalCacheDirs',
                '/sdcard/',
                '/mnt/sdcard/'
            ]
            
            for indicator in external_storage_indicators:
                if any(indicator in s for s in strings):
                    findings.append(
                        Finding(
                            title="Potential Insecure Storage Usage",
                            description=f"Found potential external storage usage: {indicator}",
                            severity=Severity.MEDIUM,
                            context={
                                'indicator': indicator,
                                'recommendation': "Avoid storing sensitive data on external storage. Use internal storage or encrypted storage instead."
                            }
                        )
                    )
        except Exception as e:
            logger.error(f"Error checking insecure storage: {str(e)}")
            
        return findings

    async def extract_app_info(self) -> Dict[str, Any]:
        """Extract basic information about the Android application."""
        try:
            self.apk = APK(self.app_path)
            self._app_info = {
                'package_name': self.apk.get_package(),
                'version_name': self.apk.get_androidversion_name(),
                'version_code': self.apk.get_androidversion_code(),
                'min_sdk': self.apk.get_min_sdk_version(),
                'target_sdk': self.apk.get_target_sdk_version(),
                'permissions': self.apk.get_permissions(),
                'activities': self.apk.get_activities(),
                'services': self.apk.get_services(),
                'receivers': self.apk.get_receivers(),
                'providers': self.apk.get_providers(),
                'is_debuggable': self.apk.get_debuggable(),
                'is_backup_allowed': self.apk.get_application_attr_value('allowBackup'),
                'certificates': [cert.sha256_fingerprint for cert in self.apk.get_certificates()],
                'signature_scheme': self.apk.get_signature_scheme_name(0) if self.apk.get_signature_scheme_version(0) > 0 else 'JAR',
                'has_code': self.apk.get_attribute_value('application', 'hasCode'),
                'allow_backup': self.apk.get_application_attr_value('allowBackup'),
                'network_security_config': self.apk.get_network_security_config(),
            }
            
            # Initialize androguard analysis
            self.apk, self.dx, _ = AnalyzeAPK(self.app_path)
            
            return self._app_info
        except Exception as e:
            logger.error(f"Error extracting APK info: {str(e)}")
            raise
    
    async def scan(self) -> List[Finding]:
        """Perform the security scan on the Android application."""
        findings = []
        
        try:
            # Extract basic app info
            app_info = await self.extract_app_info()
            
            # Add app info to findings
            findings.append(
                Finding(
                    title="Application Information",
                    description="Basic information about the Android application.",
                    severity=Severity.INFO,
                    context=app_info
                )
            )
            
            # Run basic security checks in parallel
            basic_checks = [
                self._check_debug_mode(),
                self._check_backup_allowed(),
                self._check_test_only(),
                self._check_exported_components(),
                self._check_network_security(),
                self._check_content_providers(),
                self._analyze_dex_opcodes(),
                self._check_insecure_storage()
            ]
            
            # Run advanced analysis
            advanced_analyzer = AdvancedMobileAnalyzer(str(self.app_path), 'android')
            advanced_findings = await advanced_analyzer.analyze()
            
            # Wait for all basic checks to complete
            basic_results = await asyncio.gather(*basic_checks, return_exceptions=True)
            
            # Process basic check results
            for result in basic_results:
                if isinstance(result, Exception):
                    logger.error(f"Error during security check: {str(result)}")
                    continue
                findings.extend(result)
            
            # Add advanced findings
            findings.extend(advanced_findings)
            
            # Remove duplicates while preserving order
            unique_findings = []
            seen = set()
            for finding in findings:
                # Create a unique key for each finding
                key = (finding.title, finding.description[:100])
                if key not in seen:
                    seen.add(key)
                    unique_findings.append(finding)
            
            return unique_findings
            
        except Exception as e:
            logger.error(f"Error during Android scan: {str(e)}", exc_info=True)
            raise
            
    async def _check_debug_mode(self) -> List[Finding]:
        """Check if the app is debuggable."""
        if self._app_info.get('is_debuggable'):
            return [
                Finding(
                    title="Application is Debuggable",
                    description="The application is marked as debuggable in the manifest.",
                    severity=Severity.HIGH,
                    context={
                        'recommendation': 'Set android:debuggable="false" in the AndroidManifest.xml.'
                    }
                )
            ]
        return []
        
    async def _check_backup_allowed(self) -> List[Finding]:
        """Check if app allows backup."""
        if self._app_info.get('is_backup_allowed'):
            return [
                Finding(
                    title="Application Data Backup Allowed",
                    description="The application allows backup, which could lead to data leakage.",
                    severity=Severity.MEDIUM,
                    context={
                        'recommendation': 'Set android:allowBackup="false" in the AndroidManifest.xml.'
                    }
                )
            ]
        return []
        
    async def _check_test_only(self) -> List[Finding]:
        """Check if app is marked as testOnly."""
        if self.apk.get_attribute_value('application', 'testOnly') == 'true':
            return [
                Finding(
                    title="Test-Only Application",
                    description="The application is marked as testOnly in the manifest.",
                    severity=Severity.HIGH,
                    context={
                        'recommendation': 'Remove android:testOnly="true" from the AndroidManifest.xml.'
                    }
                )
            ]
        return []
        
    async def _check_exported_components(self) -> List[Finding]:
        """Check for exported components."""
        exported_components = []
        for component_type in ['activity', 'service', 'receiver']:
            components = getattr(self.apk, f'get_{component_type}s')()
            for component in components:
                if self.apk.get_component_exported(component):
                    exported_components.append({
                        'type': component_type,
                        'name': component,
                        'permission': self.apk.get_component_permission(component)
                    })
        
        if exported_components:
            return [
                Finding(
                    title="Exported Components",
                    description="The following components are exported and may be accessible to other apps.",
                    severity=Severity.MEDIUM,
                    context={
                        'components': exported_components,
                        'recommendation': 'Review exported components and set android:exported="false" if not needed. If needed, protect with appropriate permissions.'
                    }
                )
            ]
        return []
        
    async def _check_network_security(self) -> List[Finding]:
        """Check network security configuration."""
        if not self._app_info.get('network_security_config'):
            return [
                Finding(
                    title="No Network Security Configuration",
                    description="The application does not have a Network Security Configuration file.",
                    severity=Severity.MEDIUM,
                    context={
                        'recommendation': 'Implement a Network Security Configuration to secure network traffic and prevent cleartext traffic.'
                    }
                )
            ]
        return []

    def _check_debuggable(self) -> List[Finding]:
        """Check if the app is debuggable."""
        if self.app_info.get('is_debuggable'):
            return [self._add_finding(
                finding_type="DEBUGGABLE_APP",
                title="Application is debuggable",
                severity=Severity.HIGH,
                description="The application has android:debuggable="true" in the manifest.",
                remediation="Set android:debuggable="false" in the AndroidManifest.xml."
            )]
        return []
    
    def _check_backup_allowed(self) -> List[Finding]:
        """Check if backup is allowed for the app."""
        if self.app_info.get('is_backup_allowed') == 'true':
            return [self._add_finding(
                finding_type="BACKUP_ALLOWED",
                title="Application allows backup",
                severity=Severity.MEDIUM,
                description="The application has android:allowBackup="true" in the manifest.",
                remediation="Set android:allowBackup="false" in the AndroidManifest.xml."
            )]
        return []
    
    def _check_exported_components(self) -> List[Finding]:
        """Check for insecurely exported components."""
        findings = []
        
        for component_type in ['activity', 'service', 'receiver', 'provider']:
            components = getattr(self.apk, f'get_{component_type}s')()
            for component in components:
                if self.apk.get_component_exported(component):
                    findings.append(self._add_finding(
                        finding_type=f"EXPORTED_{component_type.upper()}",
                        title=f"Exported {component_type}: {component}",
                        severity=Severity.HIGH,
                        description=f"The {component_type} {component} is exported and can be launched by other applications.",
                        remediation=f"Review if this {component_type} needs to be exported. If not, set android:exported="false"."
                    ))
        
        return findings
    
    def _check_permissions(self) -> List[Finding]:
        """Check for dangerous or unnecessary permissions."""
        dangerous_perms = [
            'android.permission.READ_SMS',
            'android.permission.SEND_SMS',
            'android.permission.RECEIVE_SMS',
            'android.permission.READ_CALL_LOG',
            'android.permission.READ_CONTACTS',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.CAMERA',
            'android.permission.RECORD_AUDIO',
            'android.permission.WRITE_EXTERNAL_STORAGE',
        ]
        
        findings = []
        for perm in dangerous_perms:
            if perm in self.app_info.get('permissions', []):
                findings.append(self._add_finding(
                    finding_type="DANGEROUS_PERMISSION",
                    title=f"Dangerous permission requested: {perm}",
                    severity=Severity.MEDIUM,
                    description=f"The application requests the {perm} permission.",
                    remediation="Review if this permission is necessary for the app's core functionality."
                ))
        
        return findings
    
    def _check_ssl_validation(self) -> List[Finding]:
        """Check for SSL validation bypass."""
        ssl_bypass_patterns = [
            'setHostnameVerifier',
            'ALLOW_ALL_HOSTNAME_VERIFIER',
            'TrustAllCerts',
            'TrustAllHostnameVerifier',
            'checkServerTrusted',
        ]
        
        findings = []
        for file_path in self.apk.get_files():
            if file_path.endswith('.smali'):
                try:
                    content = self.apk.get_file(file_path).decode('utf-8', errors='ignore')
                    for pattern in ssl_bypass_patterns:
                        if pattern in content:
                            findings.append(self._add_finding(
                                finding_type="SSL_VALIDATION_DISABLED",
                                title="SSL Certificate Validation Disabled",
                                severity=Severity.HIGH,
                                description="The app contains code that disables SSL certificate validation.",
                                details={'file': file_path},
                                remediation="Ensure proper SSL certificate validation is implemented."
                            ))
                            break
                except Exception:
                    continue
        
        return findings
    
    def _check_insecure_storage(self) -> List[Finding]:
        """Check for insecure data storage."""
        sensitive_keywords = [
            'password', 'secret', 'api_key', 'token', 'auth', 'credential',
            'ssn', 'social', 'security', 'credit', 'card', 'cvv', 'cvc',
            'account', 'bank', 'routing', 'pin', 'dob', 'birth', 'address'
        ]
        
        findings = []
        for file_path in self.apk.get_files():
            if file_path.endswith(('.smali', '.xml')):
                try:
                    content = self.apk.get_file(file_path).decode('utf-8', errors='ignore')
                    for kw in sensitive_keywords:
                        if kw in content.lower():
                            findings.append(self._add_finding(
                                finding_type="HARDCODED_SECRETS",
                                title=f"Potential hardcoded secret in {file_path}",
                                severity=Severity.HIGH,
                                description=f"The file contains potential sensitive information: {kw}",
                                details={'file': file_path},
                                remediation="Remove sensitive information from the code and resources."
                            ))
                            break
                except Exception:
                    continue
        
        return findings
    
    def _check_webview_security(self) -> List[Finding]:
        """Check for WebView security issues."""
        webview_issues = []
        
        for file_path in self.apk.get_files():
            if file_path.endswith('.smali'):
                try:
                    content = self.apk.get_file(file_path).decode('utf-8', errors='ignore')
                    
                    # Check for JavaScript enabled
                    if 'setJavaScriptEnabled(Z)V' in content and 'Z1' in content:
                        webview_issues.append('JavaScript enabled')
                    
                    # Check for file access
                    if 'setAllowFileAccess(Z)V' in content and 'Z1' in content:
                        webview_issues.append('File access enabled')
                    
                    # Check for content access
                    if 'setAllowContentAccess(Z)V' in content and 'Z1' in content:
                        webview_issues.append('Content access enabled')
                    
                    # Check for JavaScript interfaces
                    if 'addJavascriptInterface' in content:
                        webview_issues.append('JavaScript interfaces detected')
                    
                except Exception:
                    continue
        
        if webview_issues:
            return [self._add_finding(
                finding_type="WEBVIEW_ISSUES",
                title="WebView Security Issues",
                severity=Severity.HIGH,
                description="The app contains WebView components with potential security issues.",
                details={'issues': webview_issues},
                remediation=(
                    "Review WebView settings and ensure proper security measures are in place. "
                    "Disable JavaScript if not needed, and validate all inputs to WebView."
                )
            )]
        
        return []
