"""
iOS Security Scanner for VulnBuster.

This module provides functionality to scan iOS applications (IPA files)
for security vulnerabilities and misconfigurations.
"""
import asyncio
import logging
import plistlib
import re
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Any

from ..models import Finding, Severity, Platform
from .scanner import MobileScanner
from .advanced_analysis import AdvancedMobileAnalyzer

logger = logging.getLogger(__name__)

class IOSScanner(MobileScanner):
    """Scanner for iOS application security assessment."""
    
    def __init__(self, ipa_path: str):
        """Initialize the iOS scanner.
        
        Args:
            ipa_path: Path to the IPA file to scan
        """
        super().__init__(ipa_path, Platform.IOS)
        self.info_plist: Dict[str, Any] = {}
        self.binary_path: Optional[Path] = None
    
    async def extract_app_info(self) -> Dict[str, Any]:
        """Extract basic information about the iOS application."""
        logger.info(f"Extracting app info from {self.app_path}")
        
        try:
            # Extract the IPA file
            with zipfile.ZipFile(self.app_path, 'r') as ipa_file:
                # Find the Info.plist file
                plist_path = next(
                    (f for f in ipa_file.namelist() 
                     if f.endswith('.app/Info.plist')),
                    None
                )
                
                if not plist_path:
                    raise ValueError("Info.plist not found in the IPA file")
                
                # Extract and parse Info.plist
                with ipa_file.open(plist_path) as plist_file:
                    self.info_plist = plistlib.load(plist_file)
                
                # Find the binary
                app_dir = plist_path.split('/')[0]
                binary_name = self.info_plist.get('CFBundleExecutable')
                if binary_name:
                    self.binary_path = Path(app_dir) / binary_name
            
            # Extract basic app info
            app_info = {
                'bundle_id': self.info_plist.get('CFBundleIdentifier'),
                'version': self.info_plist.get('CFBundleShortVersionString'),
                'build': self.info_plist.get('CFBundleVersion'),
                'minimum_os_version': self.info_plist.get('MinimumOSVersion'),
                'device_family': self.info_plist.get('UIDeviceFamily'),
                'entitlements': self.info_plist.get('Entitlements', {}),
                'url_handlers': self.info_plist.get('CFBundleURLTypes', []),
                'exported_utis': self.info_plist.get('UTExportedTypeDeclarations', []),
                'imported_utis': self.info_plist.get('UTImportedTypeDeclarations', []),
                'background_modes': self.info_plist.get('UIBackgroundModes', []),
                'app_transport_security': self.info_plist.get('NSAppTransportSecurity', {}),
                'permissions': self._extract_permissions(),
            }
            
            return app_info
            
        except Exception as e:
            logger.error(f"Error extracting app info: {str(e)}", exc_info=True)
            raise
    
    def _extract_permissions(self) -> Dict[str, List[str]]:
        """Extract permissions from Info.plist."""
        permissions = {}
        
        # Privacy-related permissions
        privacy_keys = [
            'NSBluetoothPeripheralUsageDescription',
            'NSCalendarsUsageDescription',
            'NSCameraUsageDescription',
            'NSContactsUsageDescription',
            'NSFaceIDUsageDescription',
            'NSHealthShareUsageDescription',
            'NSHealthUpdateUsageDescription',
            'NSHomeKitUsageDescription',
            'NSLocationAlwaysAndWhenInUseUsageDescription',
            'NSLocationAlwaysUsageDescription',
            'NSLocationWhenInUseUsageDescription',
            'NSMicrophoneUsageDescription',
            'NSMotionUsageDescription',
            'NSPhotoLibraryUsageDescription',
            'NSRemindersUsageDescription',
            'NSSiriUsageDescription',
            'NSSpeechRecognitionUsageDescription',
        ]
        
        for key in privacy_keys:
            if key in self.info_plist:
                permissions[key] = self.info_plist[key]
        
        return permissions
    
    async def scan(self) -> List[Finding]:
        """Perform the security scan on the iOS application."""
        findings = []
        
        try:
            # Extract basic app info
            app_info = await self.extract_app_info()
            
            # Add app info to findings
            findings.append(
                Finding(
                    title="Application Information",
                    description="Basic information about the iOS application.",
                    severity=Severity.INFO,
                    context=app_info
                )
            )
            
            # Run basic security checks in parallel
            basic_checks = [
                self._check_entitlements(),
                self._check_plist_security(),
                self._check_binary_protections()
            ]
            
            # Run advanced analysis
            advanced_analyzer = AdvancedMobileAnalyzer(str(self.app_path), 'ios')
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
            logger.error(f"Error during iOS scan: {str(e)}", exc_info=True)
            raise
    
    def _check_app_transport_security(self) -> List[Finding]:
        """Check App Transport Security (ATS) settings."""
        ats = self.app_info.get('app_transport_security', {})
        findings = []
        
        # Check if ATS is disabled
        if ats.get('NSAllowsArbitraryLoads') is True:
            findings.append(self._add_finding(
                finding_type="ATS_DISABLED",
                title="App Transport Security Disabled",
                severity=Severity.HIGH,
                description="The app disables App Transport Security, allowing insecure HTTP connections.",
                details={
                    'impact': 'The app may be vulnerable to Man-in-the-Middle (MITM) attacks.',
                    'config': ats
                },
                remediation=(
                    "Enable ATS by setting NSAllowsArbitraryLoads to false in Info.plist. "
                    "Use NSExceptionDomains to specify any required exceptions."
                )
            ))
        
        # Check for specific ATS exceptions
        if 'NSExceptionDomains' in ats:
            for domain, settings in ats['NSExceptionDomains'].items():
                if settings.get('NSExceptionAllowsInsecureHTTPLoads') is True:
                    findings.append(self._add_finding(
                        finding_type="ATS_EXCEPTION_INSECURE_HTTP",
                        title=f"Insecure HTTP Allowed for {domain}",
                        severity=Severity.MEDIUM,
                        description=f"The app allows insecure HTTP connections to {domain}.",
                        details={
                            'domain': domain,
                            'settings': settings
                        },
                        remediation=(
                            f"Remove the exception for {domain} or ensure it's necessary. "
                            "Use HTTPS for all network connections."
                        )
                    ))
        
        return findings
    
    def _check_permissions(self) -> List[Finding]:
        """Check for sensitive permissions."""
        sensitive_permissions = {
            'NSCameraUsageDescription': 'Camera access',
            'NSMicrophoneUsageDescription': 'Microphone access',
            'NSLocationWhenInUseUsageDescription': 'Location access (when in use)',
            'NSLocationAlwaysAndWhenInUseUsageDescription': 'Location access (always)',
            'NSPhotoLibraryUsageDescription': 'Photo library access',
            'NSContactsUsageDescription': 'Contacts access',
            'NSHealthShareUsageDescription': 'Health data access',
            'NSFaceIDUsageDescription': 'Face ID access',
            'NSSiriUsageDescription': 'Siri integration',
        }
        
        findings = []
        for key, description in sensitive_permissions.items():
            if key in self.app_info.get('permissions', {}):
                findings.append(self._add_finding(
                    finding_type=f"PERMISSION_{key}",
                    title=f"Permission Requested: {description}",
                    severity=Severity.INFO,  # Just informational, as permissions are user-controlled
                    description=f"The app requests permission for: {description}",
                    details={
                        'description': self.app_info['permissions'][key],
                        'privacy_impact': 'High' if 'Location' in description or 'Camera' in description else 'Medium'
                    },
                    remediation=(
                        "Ensure the permission is necessary for the app's core functionality. "
                        "Provide a clear description of why the permission is needed in the Info.plist."
                    )
                ))
        
        return findings
    
    def _check_exported_components(self) -> List[Finding]:
        """Check for exported components and URL schemes."""
        findings = []
        
        # Check URL schemes
        url_handlers = self.app_info.get('url_handlers', [])
        for handler in url_handlers:
            schemes = handler.get('CFBundleURLSchemes', [])
            for scheme in schemes:
                findings.append(self._add_finding(
                    finding_type="URL_SCHEME_REGISTERED",
                    title=f"URL Scheme Registered: {scheme}",
                    severity=Severity.MEDIUM,
                    description=f"The app registers the URL scheme: {scheme}",
                    details={
                        'scheme': scheme,
                        'handler': handler
                    },
                    remediation=(
                        f"Ensure the URL scheme '{scheme}' is properly validated when opened. "
                        "Implement input validation and authentication/authorization checks."
                    )
                ))
        
        # Check document types
        exported_utis = self.app_info.get('exported_utis', [])
        for uti in exported_utis:
            if uti.get('UTTypeConformsTo') == ['public.data']:
                findings.append(self._add_finding(
                    finding_type="EXPORTED_UTI",
                    title=f"Exported UTI: {uti.get('UTTypeIdentifier')}",
                    severity=Severity.LOW,
                    description=f"The app exports the UTI: {uti.get('UTTypeIdentifier')}",
                    details={
                        'uti': uti.get('UTTypeIdentifier'),
                        'description': uti.get('UTTypeDescription')
                    },
                    remediation=(
                        f"Review if the UTI '{uti.get('UTTypeIdentifier')}' needs to be exported. "
                        "Only export UTIs that are necessary for the app's functionality."
                    )
                ))
        
        return findings
    
    async def _check_binary_security(self) -> List[Finding]:
        """Check binary security settings."""
        findings = []
        
        # Check if binary exists and is not encrypted
        if not self.binary_path or not (self.app_path.parent / self.binary_path).exists():
            logger.warning("Binary not found in the IPA file")
            return findings
        
        # Check for PIE (Position Independent Executable)
        # This would require otool or similar binary analysis tools
        
        # Check for stack smashing protection
        # This would require otool or similar binary analysis tools
        
        return findings
    
    def _check_url_handlers(self) -> List[Finding]:
        """Check for insecure URL handling."""
        findings = []
        
        # Check for universal links
        if 'com.apple.developer.associated-domains' in self.app_info.get('entitlements', {}):
            domains = self.app_info['entitlements']['com.apple.developer.associated-domains']
            for domain in domains:
                if domain.startswith('applinks:'):
                    domain = domain.replace('applinks:', '')
                    findings.append(self._add_finding(
                        finding_type="UNIVERSAL_LINK_CONFIGURED",
                        title=f"Universal Link Configured: {domain}",
                        severity=Severity.INFO,
                        description=f"The app is configured to handle universal links for: {domain}",
                        details={'domain': domain},
                        remediation=(
                            f"Ensure the domain {domain} is properly secured with an apple-app-site-association file. "
                            "Implement proper validation of universal links in the app."
                        )
                    ))
        
        return findings
    
    def _check_pasteboard(self) -> List[Finding]:
        """Check for pasteboard usage."""
        # This would require static analysis of the binary
        # Look for UIPasteboard usage without proper clearing
        return []
    
    def _check_keychain(self) -> List[Finding]:
        """Check for insecure keychain usage."""
        # This would require static analysis of the binary
        # Look for kSecAttrAccessibleAlways or kSecAttrAccessibleAfterFirstUnlock
        return []
