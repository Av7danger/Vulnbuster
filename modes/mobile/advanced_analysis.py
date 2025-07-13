"""
Advanced Mobile Security Analysis Module for VulnBuster.

This module provides cutting-edge security analysis for mobile applications,
leveraging both static and dynamic analysis techniques with AI-powered insights.
"""
import asyncio
import hashlib
import json
import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any

import lief
import requests
from androguard.core.bytecodes.apk import APK
from androguard.core.analysis.analysis import Analysis
from androguard.misc import AnalyzeAPK

from ..models import Finding, Severity
from .utils import extract_strings, run_command, calculate_hashes

logger = logging.getLogger(__name__)

@dataclass
class BinaryAnalysis:
    """Results of binary security analysis."""
    has_pie: bool = False
    has_nx: bool = False
    has_relro: bool = False
    has_canary: bool = False
    has_rpath: bool = False
    has_runpath: bool = False
    has_fortify: bool = False
    has_symbols: bool = False
    has_debug_info: bool = False
    suspicious_sections: List[str] = field(default_factory=list)
    suspicious_imports: List[str] = field(default_factory=list)
    suspicious_strings: List[str] = field(default_factory=list)

class AdvancedMobileAnalyzer:
    """Advanced security analyzer for mobile applications."""
    
    def __init__(self, app_path: str, platform: str):
        """Initialize the advanced analyzer.
        
        Args:
            app_path: Path to the mobile application file
            platform: Target platform ('android' or 'ios')
        """
        self.app_path = Path(app_path)
        self.platform = platform.lower()
        self.temp_dir = Path(tempfile.mkdtemp(prefix="vulnbuster_"))
        self.binaries: List[Path] = []
        self.analysis_results: Dict[str, Any] = {}
        self.findings: List[Finding] = []
        
        # Known malicious patterns and indicators
        self.malicious_indicators = {
            'crypto': [
                'crypt', 'aes', 'des', 'rsa', 'md5', 'sha1', 'base64',
                'cipher', 'encrypt', 'decrypt', 'keystore', 'keychain'
            ],
            'obfuscation': [
                'proguard', 'dexguard', 'ollvm', 'armariris', 'tigress',
                'x86get_pc_thunk', 'x86.get_pc_thunk', 'ptrace', 'anti_debug',
                'anti-debug', 'antidebug', 'anti debug', 'anti_emu', 'antiemu'
            ],
            'exploits': [
                'exec', 'system', 'popen', 'strcpy', 'strcat', 'sprintf',
                'gets', 'memcpy', 'memmove', 'strncpy', 'strncat', 'vsprintf',
                'gets', 'getenv', 'setuid', 'setgid', 'chmod', 'chown'
            ]
        }
    
    async def analyze(self) -> List[Finding]:
        """Perform advanced security analysis."""
        try:
            # Extract and analyze the application
            await self._extract_application()
            await self._analyze_binaries()
            await self._check_vulnerable_libraries()
            await self._check_malicious_patterns()
            
            # Platform-specific analysis
            if self.platform == 'android':
                await self._analyze_android_specific()
            elif self.platform == 'ios':
                await self._analyze_ios_specific()
                
            return self.findings
            
        except Exception as e:
            logger.error(f"Advanced analysis failed: {str(e)}", exc_info=True)
            raise
        finally:
            # Clean up temporary files
            await self._cleanup()
    
    async def _extract_application(self):
        """Extract the application package for analysis."""
        try:
            if self.platform == 'android':
                # For Android, we can use androguard to extract the APK
                self.apk = APK(self.app_path)
                self.binaries = [self.app_path]  # Will analyze the DEX files
            elif self.platform == 'ios':
                # For iOS, we need to extract the IPA and find the main binary
                await self._extract_ipa()
        except Exception as e:
            logger.error(f"Failed to extract application: {str(e)}")
            raise
    
    async def _extract_ipa(self):
        """Extract iOS IPA file and find the main binary."""
        try:
            # Create a temporary directory for extraction
            extract_dir = self.temp_dir / "extracted_ipa"
            extract_dir.mkdir(exist_ok=True)
            
            # Extract the IPA (which is just a zip file)
            with zipfile.ZipFile(self.app_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
            
            # Find the .app directory
            app_dirs = list(extract_dir.glob("Payload/*.app"))
            if not app_dirs:
                raise ValueError("No .app directory found in IPA")
                
            app_dir = app_dirs[0]
            
            # The binary has the same name as the .app directory (without .app)
            binary_name = app_dir.stem
            binary_path = app_dir / binary_name
            
            if binary_path.exists():
                self.binaries.append(binary_path)
            else:
                # Sometimes the binary is in the MacOS directory for macOS apps
                macos_dir = app_dir / "Contents" / "MacOS"
                if macos_dir.exists():
                    binaries = list(macos_dir.glob("*"))
                    if binaries:
                        self.binaries.extend(binaries)
        except Exception as e:
            logger.error(f"Failed to extract IPA: {str(e)}")
            raise
    
    async def _analyze_binaries(self):
        """Analyze binary files for security issues."""
        for binary_path in self.binaries:
            try:
                binary = lief.parse(str(binary_path))
                if binary is None:
                    continue
                    
                analysis = BinaryAnalysis()
                
                # Check binary protections
                if binary.has_pie:
                    analysis.has_pie = True
                
                if binary.has_nx:
                    analysis.has_nx = True
                
                # Check for suspicious sections
                for section in binary.sections:
                    section_name = section.name.strip('\x00')
                    if section_name.lower() in ['.plt', '.got', '.plt.got', '.plt.sec']:
                        continue
                    
                    if section.has(lief.ELF.SECTION_FLAGS.EXECUTE):
                        analysis.suspicious_sections.append(
                            f"Executable section found: {section_name}"
                        )
                
                # Check for suspicious imports
                for imported_library in binary.imported_libraries:
                    if any(indicator in imported_library.lower() 
                          for indicators in self.malicious_indicators.values() 
                          for indicator in indicators):
                        analysis.suspicious_imports.append(imported_library)
                
                # Save the analysis
                self.analysis_results[str(binary_path)] = {
                    'protections': {
                        'pie': analysis.has_pie,
                        'nx': analysis.has_nx,
                        'relro': analysis.has_relro,
                        'canary': analysis.has_canary,
                        'fortify': analysis.has_fortify
                    },
                    'suspicious_sections': analysis.suspicious_sections,
                    'suspicious_imports': analysis.suspicious_imports,
                    'suspicious_strings': analysis.suspicious_strings
                }
                
                # Generate findings
                if not analysis.has_pie:
                    self.findings.append(
                        Finding(
                            title="Missing PIE (Position Independent Executable)",
                            description=f"The binary {binary_path.name} is not compiled with PIE, making it vulnerable to code injection attacks.",
                            severity=Severity.HIGH,
                            context={
                                'binary': str(binary_path.name),
                                'recommendation': 'Recompile the binary with -fPIE -pie flags.'
                            }
                        )
                    )
                
                if not analysis.has_nx:
                    self.findings.append(
                        Finding(
                            title="Missing NX (No-Execute) Protection",
                            description=f"The binary {binary_path.name} does not have NX protection, making it vulnerable to code execution attacks.",
                            severity=Severity.HIGH,
                            context={
                                'binary': str(binary_path.name),
                                'recommendation': 'Recompile the binary with -z noexecstack -z now flags.'
                            }
                        )
                    )
                
                for section in analysis.suspicious_sections:
                    self.findings.append(
                        Finding(
                            title="Suspicious Binary Section",
                            description=f"The binary {binary_path.name} contains a potentially suspicious section: {section}",
                            severity=Severity.MEDIUM,
                            context={
                                'binary': str(binary_path.name),
                                'section': section,
                                'recommendation': 'Review the binary for potential malicious code or obfuscation.'
                            }
                        )
                    )
                
                for imp in analysis.suspicious_imports:
                    self.findings.append(
                        Finding(
                            title="Suspicious Import Detected",
                            description=f"The binary {binary_path.name} imports a potentially suspicious library: {imp}",
                            severity=Severity.MEDIUM,
                            context={
                                'binary': str(binary_path.name),
                                'import': imp,
                                'recommendation': 'Review the use of this library and ensure it is necessary and secure.'
                            }
                        )
                    )
                
            except Exception as e:
                logger.error(f"Failed to analyze binary {binary_path}: {str(e)}")
    
    async def _analyze_android_specific(self):
        """Perform Android-specific security analysis."""
        try:
            # Check for native libraries
            lib_dir = self.temp_dir / "lib"
            if lib_dir.exists():
                for so_file in lib_dir.glob("**/*.so"):
                    self.binaries.append(so_file)
            
            # Check for hardcoded secrets
            strings = extract_strings(self.app_path)
            self._check_for_secrets(strings)
            
            # Check for debug information
            if self.apk.get_debuggable():
                self.findings.append(
                    Finding(
                        title="Debug Mode Enabled",
                        description="The application is marked as debuggable in the manifest.",
                        severity=Severity.HIGH,
                        context={
                            'recommendation': 'Set android:debuggable="false" in AndroidManifest.xml.'
                        }
                    )
                )
            
            # Check for backup allowed
            if self.apk.get_application_attr_value('allowBackup') != 'false':
                self.findings.append(
                    Finding(
                        title="Backup Allowed",
                        description="The application allows backup, which could lead to data leakage.",
                        severity=Severity.MEDIUM,
                        context={
                            'recommendation': 'Set android:allowBackup="false" in AndroidManifest.xml.'
                        }
                    )
                )
            
            # Check for insecure network security config
            nsc = self.apk.get_network_security_config()
            if nsc and 'cleartextTrafficPermitted="true"' in nsc:
                self.findings.append(
                    Finding(
                        title="Cleartext Traffic Allowed",
                        description="The application allows cleartext network traffic, which could lead to information disclosure.",
                        severity=Severity.HIGH,
                        context={
                            'recommendation': 'Set cleartextTrafficPermitted="false" in network security config.'
                        }
                    )
                )
            
            # Check for WebView vulnerabilities
            if any('WebView' in activity for activity in self.apk.get_activities()):
                self.findings.append(
                    Finding(
                        title="WebView Usage Detected",
                        description="The application uses WebView, which can introduce security risks if not properly configured.",
                        severity=Severity.MEDIUM,
                        context={
                            'recommendation': 'Ensure JavaScript is disabled if not needed, and implement proper URL validation.'
                        }
                    )
                )
            
        except Exception as e:
            logger.error(f"Android-specific analysis failed: {str(e)}")
    
    async def _analyze_ios_specific(self):
        """Perform iOS-specific security analysis."""
        try:
            # Check for insecure URL schemes
            plist_path = self.temp_dir / "extracted_ipa" / "Payload" / "*.app" / "Info.plist"
            plist_files = list(self.temp_dir.glob("**/Info.plist"))
            
            for plist_file in plist_files:
                await self._analyze_plist(plist_file)
            
            # Check for jailbreak detection bypass
            jailbreak_indicators = [
                '/Applications/Cydia.app',
                '/Library/MobileSubstrate/MobileSubstrate.dylib',
                '/bin/bash',
                '/usr/sbin/sshd',
                '/etc/apt',
                'cydia://',
                'cydia://package/com.example.package'
            ]
            
            for binary_path in self.binaries:
                strings = extract_strings(str(binary_path))
                for indicator in jailbreak_indicators:
                    if any(indicator in s for s in strings):
                        self.findings.append(
                            Finding(
                                title="Jailbreak Detection Bypass",
                                description=f"The binary {binary_path.name} contains jailbreak detection bypass code.",
                                severity=Severity.MEDIUM,
                                context={
                                    'binary': str(binary_path.name),
                                    'indicator': indicator,
                                    'recommendation': 'Implement proper jailbreak detection and security controls.'
                                }
                            )
                        )
            
            # Check for insecure data storage
            insecure_storage_paths = [
                'Library/Caches/',
                'Library/Preferences/',
                'tmp/',
                'Documents/'
            ]
            
            for path in insecure_storage_paths:
                self.findings.append(
                    Finding(
                        title="Potential Insecure Data Storage",
                        description=f"The application may store sensitive data in an insecure location: {path}",
                        severity=Severity.MEDIUM,
                        context={
                            'path': path,
                            'recommendation': 'Store sensitive data in the Keychain or use encrypted storage.'
                        }
                    )
                )
            
        except Exception as e:
            logger.error(f"iOS-specific analysis failed: {str(e)}")
    
    async def _analyze_plist(self, plist_path: Path):
        """Analyze iOS Info.plist file for security issues."""
        try:
            # This is a simplified example - in a real implementation, you would use a proper plist parser
            with open(plist_path, 'r', encoding='utf-8', errors='ignore') as f:
                plist_content = f.read()
            
            # Check for insecure URL schemes
            if 'CFBundleURLTypes' in plist_content:
                self.findings.append(
                    Finding(
                        title="Custom URL Scheme Detected",
                        description="The application registers custom URL schemes, which could be exploited if not properly validated.",
                        severity=Severity.MEDIUM,
                        context={
                            'file': str(plist_path),
                            'recommendation': 'Implement proper URL scheme validation and handling.'
                        }
                    )
                )
            
            # Check for insecure transport settings
            if 'NSAppTransportSecurity' in plist_content and 'NSAllowsArbitraryLoads</key><true/>' in plist_content:
                self.findings.append(
                    Finding(
                        title="Insecure Transport Security Settings",
                        description="The application disables ATS (App Transport Security), allowing insecure network connections.",
                        severity=Severity.HIGH,
                        context={
                            'file': str(plist_path),
                            'recommendation': 'Enable ATS and use secure connections with proper certificate validation.'
                        }
                    )
                )
            
            # Check for background modes that could indicate sensitive functionality
            sensitive_background_modes = [
                'location',
                'audio',
                'voip',
                'external-accessory',
                'bluetooth-central',
                'bluetooth-peripheral',
                'fetch',
                'remote-notification'
            ]
            
            for mode in sensitive_background_modes:
                if f'<string>{mode}</string>' in plist_content:
                    self.findings.append(
                        Finding(
                            title=f"Sensitive Background Mode: {mode}",
                            description=f"The application uses the {mode} background mode, which could impact battery life and user privacy.",
                            severity=Severity.LOW,
                            context={
                                'file': str(plist_path),
                                'mode': mode,
                                'recommendation': f'Ensure the {mode} background mode is necessary and properly implemented.'
                            }
                        )
                    )
            
        except Exception as e:
            logger.error(f"Failed to analyze plist {plist_path}: {str(e)}")
    
    async def _check_vulnerable_libraries(self):
        """Check for known vulnerable libraries."""
        try:
            # This is a simplified example - in a real implementation, you would use a proper
            # vulnerability database like OWASP Dependency-Check or OSS Index
            vulnerable_libs = {
                'sqlite': {
                    'versions': ['< 3.26.0'],
                    'cve': 'CVE-2019-19603',
                    'severity': Severity.HIGH,
                    'description': 'SQLite before 3.26.0 allows a crash if a sub-select uses both DISTINCT and a window function and also has certain ORDER BY usage.'
                },
                'openssl': {
                    'versions': ['< 1.1.1'],
                    'cve': 'CVE-2021-23840',
                    'severity': Severity.CRITICAL,
                    'description': 'The OpenSSL public API function X509_issuer_and_serial_hash() could be used to construct a certificate that may take a long time to parse on 32-bit systems.'
                },
                'libpng': {
                    'versions': ['< 1.6.37'],
                    'cve': 'CVE-2019-7317',
                    'severity': Severity.HIGH,
                    'description': 'A use-after-free in png_image_free in png.c in libpng 1.6.36 allows remote attackers to cause a denial of service (application crash) via a crafted file.'
                }
            }
            
            for binary_path in self.binaries:
                # In a real implementation, you would extract version information from the binary
                # and check it against the vulnerable versions
                for lib_name, vuln_info in vulnerable_libs.items():
                    if lib_name.lower() in str(binary_path).lower():
                        self.findings.append(
                            Finding(
                                title=f"Potentially Vulnerable Library: {lib_name}",
                                description=f"The application uses {lib_name} which may be vulnerable to {vuln_info['cve']}.",
                                severity=vuln_info['severity'],
                                context={
                                    'library': lib_name,
                                    'cve': vuln_info['cve'],
                                    'description': vuln_info['description'],
                                    'recommendation': f'Update {lib_name} to the latest version.'
                                }
                            )
                        )
        except Exception as e:
            logger.error(f"Failed to check for vulnerable libraries: {str(e)}")
    
    async def _check_malicious_patterns(self):
        """Check for known malicious patterns and indicators."""
        try:
            for binary_path in self.binaries:
                strings = extract_strings(str(binary_path))
                
                # Check for crypto indicators
                for indicator in self.malicious_indicators['crypto']:
                    if any(indicator in s.lower() for s in strings):
                        self.findings.append(
                            Finding(
                                title="Cryptographic Operation Detected",
                                description=f"The binary {binary_path.name} contains cryptographic operations using {indicator}.",
                                severity=Severity.INFO,
                                context={
                                    'binary': str(binary_path.name),
                                    'indicator': indicator,
                                    'recommendation': 'Review the use of cryptographic operations and ensure they are implemented securely.'
                                }
                            )
                        )
                
                # Check for obfuscation indicators
                for indicator in self.malicious_indicators['obfuscation']:
                    if any(indicator in s.lower() for s in strings):
                        self.findings.append(
                            Finding(
                                title="Potential Code Obfuscation",
                                description=f"The binary {binary_path.name} may be obfuscated using {indicator}.",
                                severity=Severity.MEDIUM,
                                context={
                                    'binary': str(binary_path.name),
                                    'indicator': indicator,
                                    'recommendation': 'Review the obfuscation techniques used and ensure they are not hiding malicious behavior.'
                                }
                            )
                        )
                
                # Check for exploit indicators
                for indicator in self.malicious_indicators['exploits']:
                    if any(indicator in s.lower() for s in strings):
                        self.findings.append(
                            Finding(
                                title="Potentially Dangerous Function",
                                description=f"The binary {binary_path.name} contains the potentially dangerous function: {indicator}",
                                severity=Severity.HIGH,
                                context={
                                    'binary': str(binary_path.name),
                                    'function': indicator,
                                    'recommendation': f'Review the use of {indicator} and ensure it is not vulnerable to exploitation.'
                                }
                            )
                        )
        except Exception as e:
            logger.error(f"Failed to check for malicious patterns: {str(e)}")
    
    def _check_for_secrets(self, strings: List[str]):
        """Check for hardcoded secrets in strings."""
        try:
            # Common secret patterns
            secret_patterns = {
                'api_key': r'(?i)(?:api[_-]?key|apikey)[=:][\s\"]*([a-z0-9_\-]{10,})',
                'aws_key': r'(?i)AKIA[0-9A-Z]{16}',
                'aws_secret': r'(?i)aws[_-]?secret[_-]?key[=:][\s\"]*([a-z0-9_\-+\/]{20,})',
                'password': r'(?i)(?:password|passwd|pwd)[=:][\s\"]*([^\s\"]+)',
                'token': r'(?i)(?:token|bearer)[=:][\s\"]*([a-z0-9_\-]{10,})',
                'database': r'(?i)(?:database|db)[_-]?(?:password|pwd|passwd)[=:][\s\"]*([^\s\"]+)',
                'jwt': r'eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.?[a-zA-Z0-9_\-]*',
                'private_key': r'-----BEGIN (RSA|DSA|EC|PGP|OPENSSH) PRIVATE KEY-----'
            }
            
            for name, pattern in secret_patterns.items():
                for s in strings:
                    matches = re.findall(pattern, s)
                    for match in matches:
                        if isinstance(match, tuple):
                            secret = match[0]
                        else:
                            secret = match
                        
                        # Skip false positives
                        if len(secret) < 8:
                            continue
                        
                        self.findings.append(
                            Finding(
                                title=f"Potential Hardcoded Secret: {name}",
                                description=f"A potential {name} was found in the application: {secret[:10]}...",
                                severity=Severity.HIGH,
                                context={
                                    'type': name,
                                    'partial_secret': f"{secret[:4]}...{secret[-4:]}",
                                    'recommendation': 'Remove hardcoded secrets and use secure storage solutions like Keychain (iOS) or Keystore (Android).'
                                }
                            )
                        )
        except Exception as e:
            logger.error(f"Failed to check for secrets: {str(e)}")
    
    async def _cleanup(self):
        """Clean up temporary files."""
        try:
            if self.temp_dir.exists():
                import shutil
                shutil.rmtree(self.temp_dir)
        except Exception as e:
            logger.error(f"Failed to clean up temporary files: {str(e)}")
