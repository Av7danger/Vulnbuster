"""
Base Mobile Security Scanner Module.

This module provides scanning capabilities for mobile applications (Android/iOS)
to identify security vulnerabilities and misconfigurations using both static
and dynamic analysis techniques with AI-powered detection.
"""
import abc
import asyncio
import json
import logging
import os
import tempfile
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Dict, List, Optional, Set, Any, Tuple, Union

from ..models import Finding, Severity, Platform
from .dynamic_analyzer import DynamicAnalyzer, HookConfig, HookType
from .advanced_hooks import AdvancedHooks, HookCategory
from .ai_training import AIModelTrainer, TrainingConfig, AIModelType, FeatureType, ModelEvaluation

logger = logging.getLogger(__name__)

class ScanType(Enum):
    """Types of mobile security scans."""
    STATIC = "static"
    DYNAMIC = "dynamic"
    FULL = "full"
    AI_ASSISTED = "ai_assisted"  # AI-powered analysis

@dataclass
class MobileScanConfig:
    """Configuration for mobile security scans."""
    platform: Platform
    app_path: Path
    output_dir: Path
    scan_type: ScanType = ScanType.FULL
    enable_frida: bool = True
    enable_debug: bool = False
    enable_ai: bool = True  # Enable AI-powered analysis
    custom_rules: Optional[Path] = None
    timeout: int = 300  # seconds
    excluded_checks: List[str] = field(default_factory=list)
    ai_model_dir: Optional[Path] = None  # Directory for AI models
    enable_advanced_hooks: bool = True  # Enable platform-specific hooks

class MobileScanner:
    """Mobile application security scanner for Android and iOS."""
    
    def __init__(self, config: MobileScanConfig):
        """Initialize the mobile scanner with the given configuration."""
        self.config = config
        self.findings: List[Finding] = []
        self.ai_trainer: Optional[AIModelTrainer] = None
        self._setup_scan_environment()
    
    async def scan(self) -> List[Finding]:
        """Run the mobile security scan."""
        logger.info(f"Starting {self.config.platform.value} mobile security scan")
        
        try:
            # Initialize AI trainer if enabled
            if self.config.enable_ai:
                model_dir = self.config.ai_model_dir or Path("models/mobile")
                self.ai_trainer = AIModelTrainer(model_dir=model_dir)
            
            # Run static analysis
            if self.config.scan_type in [ScanType.STATIC, ScanType.FULL, ScanType.AI_ASSISTED]:
                await self._run_static_analysis()
            
            # Run dynamic analysis if enabled
            if self.config.scan_type in [ScanType.DYNAMIC, ScanType.FULL, ScanType.AI_ASSISTED] and self.config.enable_frida:
                await self._run_dynamic_analysis()
            
            # Run AI-assisted analysis if enabled
            if self.config.scan_type == ScanType.AI_ASSISTED and self.ai_trainer:
                await self._run_ai_analysis()
            
            # Generate report
            report_path = await self._generate_report()
            logger.info(f"Scan completed. Found {len(self.findings)} security issues. Report saved to: {report_path}")
            
            return self.findings
            
        except Exception as e:
            logger.error(f"Error during mobile security scan: {str(e)}", exc_info=True)
            raise
    
    def _setup_scan_environment(self) -> None:
        """Set up the scanning environment."""
        # Create output directory if it doesn't exist
        self.config.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Validate platform
        if self.config.platform not in [Platform.ANDROID, Platform.IOS]:
            raise ValueError(f"Unsupported platform: {self.config.platform}")
        
        # Validate application path
        if not self.config.app_path.exists():
            raise FileNotFoundError(f"Application not found: {self.config.app_path}")
        
        logger.debug("Scan environment set up successfully.")
    
    async def _run_static_analysis(self) -> None:
        """Run static analysis on the mobile application."""
        logger.info("Starting static analysis...")
        
        try:
            # Decompile the application
            decompiled_dir = await self._decompile_application()
            
            # Analyze application manifest
            await self._analyze_manifest(decompiled_dir)
            
            # Check for hardcoded secrets
            await self._check_hardcoded_secrets(decompiled_dir)
            
            # Analyze third-party libraries
            await self._analyze_dependencies(decompiled_dir)
            
            # Check for insecure configurations
            await self._check_insecure_configs(decompiled_dir)
            
        except Exception as e:
            logger.error(f"Error during static analysis: {str(e)}", exc_info=True)
            self.findings.append(
                Finding(
                    title="Static Analysis Error",
                    description=f"An error occurred during static analysis: {str(e)}",
                    severity=Severity.MEDIUM,
                    category="Analysis Error",
                    file_path=str(self.config.app_path)
                )
            )
        
        logger.info("Static analysis completed.")
    
    async def _run_dynamic_analysis(self) -> None:
        """Run dynamic analysis on the mobile application."""
        logger.info("Starting dynamic analysis...")
        
        if not self.config.enable_frida:
            logger.warning("Frida is disabled. Skipping dynamic analysis.")
            return
        
        try:
            # Initialize dynamic analyzer
            analyzer = DynamicAnalyzer(
                platform=self.config.platform,
                app_path=self.config.app_path,
                output_dir=self.config.output_dir,
                enable_debug=self.config.enable_debug
            )
            
            # Add platform-specific hooks if enabled
            if self.config.enable_advanced_hooks:
                await self._setup_advanced_hooks(analyzer)
            
            # Start the application with instrumentation
            await analyzer.start()
            
            # Perform interactive testing (if needed)
            await self._perform_interactive_tests(analyzer)
            
            # Stop the analyzer and collect findings
            await analyzer.stop()
            self.findings.extend(analyzer.findings)
            
            # Save dynamic analysis data for AI processing
            if self.config.enable_ai and self.ai_trainer:
                await self._save_dynamic_analysis_data(analyzer)
            
        except Exception as e:
            logger.error(f"Error during dynamic analysis: {str(e)}", exc_info=True)
            self.findings.append(
                Finding(
                    title="Dynamic Analysis Error",
                    description=f"An error occurred during dynamic analysis: {str(e)}",
                    severity=Severity.MEDIUM,
                    category="Analysis Error",
                    file_path=str(self.config.app_path)
                )
            )
        
        logger.info("Dynamic analysis completed.")
    
    async def _run_ai_analysis(self) -> None:
        """Run AI-powered analysis on the collected data."""
        if not self.ai_trainer:
            logger.warning("AI trainer not initialized. Skipping AI analysis.")
            return
        
        logger.info("Starting AI-powered analysis...")
        
        try:
            # Load and preprocess data
            X, y, feature_names = await self._prepare_ai_data()
            
            if len(X) == 0 or len(y) == 0:
                logger.warning("Insufficient data for AI analysis.")
                return
            
            # Configure and train the model
            config = TrainingConfig(
                model_type=AIModelType.RANDOM_FOREST,
                feature_type=FeatureType.NUMERICAL,
                use_smote=True,
                cv_folds=5,
                scoring='f1_weighted',
                n_jobs=-1
            )
            
            # Train the model
            model, evaluation = self.ai_trainer.train_model(
                X, y,
                config=config,
                model_name=f"{self.config.platform.value}_vulnerability_detection",
                feature_names=feature_names,
                save_model=True
            )
            
            # Generate AI findings
            await self._generate_ai_findings(model, evaluation)
            
        except Exception as e:
            logger.error(f"Error during AI analysis: {str(e)}", exc_info=True)
            self.findings.append(
                Finding(
                    title="AI Analysis Error",
                    description=f"An error occurred during AI analysis: {str(e)}",
                    severity=Severity.LOW,
                    category="Analysis Error"
                )
            )
        
        logger.info("AI-powered analysis completed.")
    
    async def _setup_advanced_hooks(self, analyzer: DynamicAnalyzer) -> None:
        """Set up advanced platform-specific hooks."""
        logger.info("Setting up advanced hooks...")
        
        try:
            # Initialize advanced hooks
            advanced_hooks = AdvancedHooks(self.config.platform)
            
            # Add all hooks to the analyzer
            for hook in advanced_hooks.get_hooks():
                if hook.enabled and hook.name not in self.config.excluded_checks:
                    for hook_config in hook.hooks:
                        analyzer.add_hook(hook_config)
            
            logger.info(f"Added {len(advanced_hooks.get_hooks())} advanced hooks.")
            
        except Exception as e:
            logger.error(f"Error setting up advanced hooks: {str(e)}", exc_info=True)
            raise
    
    async def _decompile_application(self) -> Path:
        """Decompile the mobile application for static analysis."""
        # Create a temporary directory for decompiled files
        decompiled_dir = Path(tempfile.mkdtemp(prefix=f"decompiled_{self.config.platform.value}_"))
        
        logger.info(f"Decompiling {self.config.platform.value} application to {decompiled_dir}")
        
        try:
            if self.config.platform == Platform.ANDROID:
                # Use jadx or apktool for Android
                cmd = f"jadx -d {decompiled_dir} {self.config.app_path}"
                process = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await process.communicate()
                
                if process.returncode != 0:
                    raise RuntimeError(f"Failed to decompile Android application: {cmd}")
                
            elif self.config.platform == Platform.IOS:
                # Use class-dump or similar for iOS
                # This is a simplified example
                logger.warning("iOS decompilation requires additional tools. Using placeholder.")
                (decompiled_dir / "Info.plist").write_text("<placeholder>")
            
            return decompiled_dir
            
        except Exception as e:
            logger.error(f"Error during application decompilation: {str(e)}")
            raise
    
    async def _analyze_manifest(self, decompiled_dir: Path) -> None:
        """Analyze the application manifest for security issues."""
        logger.info("Analyzing application manifest...")
        
        try:
            if self.config.platform == Platform.ANDROID:
                manifest_path = decompiled_dir / "resources" / "AndroidManifest.xml"
                if not manifest_path.exists():
                    logger.warning("AndroidManifest.xml not found in decompiled files.")
                    return
                
                # Parse AndroidManifest.xml and check for issues
                manifest_content = manifest_path.read_text(encoding='utf-8', errors='ignore')
                
                # Check for debug mode
                if 'android:debuggable="true"' in manifest_content:
                    self.findings.append(
                        Finding(
                            title="Debug Mode Enabled",
                            description="The application has debugging enabled in production.",
                            severity=Severity.HIGH,
                            category="Insecure Configuration",
                            file_path=str(manifest_path),
                            line_number=manifest_content.find('android:debuggable') + 1
                        )
                    )
                
                # Check for backup allowance
                if 'android:allowBackup="true"' in manifest_content:
                    self.findings.append(
                        Finding(
                            title="Backup Allowed",
                            description="The application allows backups, which could lead to data exposure.",
                            severity=Severity.MEDIUM,
                            category="Insecure Configuration",
                            file_path=str(manifest_path),
                            line_number=manifest_content.find('android:allowBackup') + 1
                        )
                    )
                
                # Check for cleartext traffic
                if 'android:usesCleartextTraffic="true"' in manifest_content:
                    self.findings.append(
                        Finding(
                            title="Cleartext Traffic Allowed",
                            description="The application allows cleartext network traffic.",
                            severity=Severity.HIGH,
                            category="Insecure Communication",
                            file_path=str(manifest_path),
                            line_number=manifest_content.find('android:usesCleartextTraffic') + 1
                        )
                    )
            
            elif self.config.platform == Platform.IOS:
                # Check Info.plist for iOS
                info_plist = decompiled_dir / "Info.plist"
                if not info_plist.exists():
                    logger.warning("Info.plist not found in decompiled files.")
                    return
                
                # Parse Info.plist and check for issues
                plist_content = info_plist.read_text(encoding='utf-8', errors='ignore')
                
                # Check for insecure transport settings
                if 'NSAppTransportSecurity' in plist_content and 'NSAllowsArbitraryLoads' in plist_content:
                    self.findings.append(
                        Finding(
                            title="Insecure Transport Settings",
                            description="The application allows arbitrary loads, bypassing ATS restrictions.",
                            severity=Severity.HIGH,
                            category="Insecure Communication",
                            file_path=str(info_plist)
                        )
                    )
                
                # Check for jailbreak detection bypasses
                if 'UISupportedExternalAccessoryProtocols' in plist_content:
                    self.findings.append(
                        Finding(
                            title="Potential Jailbreak Detection Bypass",
                            description="The application may be vulnerable to jailbreak detection bypasses.",
                            severity=Severity.MEDIUM,
                            category="Security Controls Bypass",
                            file_path=str(info_plist)
                        )
                    )
        
        except Exception as e:
            logger.error(f"Error analyzing manifest: {str(e)}", exc_info=True)
            raise
    
    async def _check_hardcoded_secrets(self, decompiled_dir: Path) -> None:
        """Check for hardcoded secrets in the decompiled code."""
        logger.info("Checking for hardcoded secrets...")
        
        try:
            # Common patterns for API keys, tokens, passwords, etc.
            secret_patterns = [
                r'(?i)api[_-]?key[\s\t]*[=:][\s\t]*["\']([^\s\'\"]{10,})["\']',
                r'(?i)secret[\s\t]*[=:][\s\t]*["\']([^\s\'\"]{8,})["\']',
                r'(?i)password[\s\t]*[=:][\s\t]*["\']([^\s\'\"]{6,})["\']',
                r'(?i)token[\s\t]*[=:][\s\t]*["\']([^\s\'\"]{10,})["\']',
                r'(?i)access[_-]?key[\s\t]*[=:][\s\t]*["\']([^\s\'\"]{10,})["\']',
                r'(?i)secret[_-]?key[\s\t]*[=:][\s\t]*["\']([^\s\'\"]{10,})["\']',
                r'(?i)private[_-]?key[\s\t]*[=:][\s\t]*["\']([^\s\'\"]{10,})["\']',
                r'(?i)client[_-]?id[\s\t]*[=:][\s\t]*["\']([^\s\'\"]{8,})["\']',
                r'(?i)client[_-]?secret[\s\t]*[=:][\s\t]*["\']([^\s\'\"]{8,})["\']',
            ]
            
            # Search for secrets in all files
            for file_path in decompiled_dir.rglob('*'):
                if file_path.is_file() and not file_path.is_symlink():
                    try:
                        # Skip binary files
                        if self._is_binary_file(file_path):
                            continue
                        
                        # Read file content
                        content = file_path.read_text(encoding='utf-8', errors='ignore')
                        
                        # Check for each pattern
                        for pattern in secret_patterns:
                            matches = list(re.finditer(pattern, content, re.MULTILINE))
                            for match in matches:
                                # Skip false positives
                                if self._is_false_positive(match.group(0)):
                                    continue
                                
                                # Get the line number
                                line_number = content[:match.start()].count('\n') + 1
                                
                                # Add finding
                                self.findings.append(
                                    Finding(
                                        title="Hardcoded Secret Detected",
                                        description=f"Potential hardcoded secret found: {match.group(0)[:50]}...",
                                        severity=Severity.HIGH,
                                        category="Hardcoded Secrets",
                                        file_path=str(file_path.relative_to(decompiled_dir)),
                                        line_number=line_number,
                                        code_snippet=self._get_code_snippet(content, line_number)
                                    )
                                )
                    
                    except Exception as e:
                        logger.warning(f"Error processing file {file_path}: {str(e)}")
                        continue
        
        except Exception as e:
            logger.error(f"Error checking for hardcoded secrets: {str(e)}", exc_info=True)
            raise
    
    def _is_binary_file(self, file_path: Path) -> bool:
        """Check if a file is binary."""
        try:
            # Check common binary file extensions
            binary_extensions = ['.apk', '.aab', '.ipa', '.a', '.so', '.dylib', '.dll', '.exe', '.class', '.dex', '.jar', '.zip', '.png', '.jpg', '.jpeg', '.gif', '.mp3', '.mp4', '.pdf']
            if file_path.suffix.lower() in binary_extensions:
                return True
                
            # Check for non-text characters in the first 1024 bytes
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                if b'\x00' in chunk:  # Null bytes are a good indicator of binary files
                    return True
                    
            return False
            
        except Exception:
            return True  # If we can't read the file, assume it's binary
    
    def _is_false_positive(self, match: str) -> bool:
        """Check if a matched secret is a false positive."""
        # Common false positives
        false_positives = [
            'example', 'test', 'dummy', 'placeholder', 'changeme', 'your_', 'my_', 'this_',
            'api_key', 'api-key', 'api_key_here', 'your_api_key', 'your-api-key',
            'secret_key', 'secret-key', 'your_secret_key', 'your-secret-key',
            'password', 'passwd', 'pwd', 'your_password', 'your-password',
            'token', 'access_token', 'your_token', 'your-token',
            '1234', '0000', '1111', '2222', '3333', '4444', '5555', '6666', '7777', '8888', '9999',
            '0123456789', '1234567890', '12345678', '87654321', '123123123', '11111111', '00000000',
            'qwerty', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1q2w3e4r', '1qaz2wsx', '1qazxsw2',
            'qazwsx', 'qwerty123', 'password1', 'password123', 'letmein', 'welcome', 'admin', 'root',
            'localhost', '127.0.0.1', '0.0.0.0', '::1', '::', '0:0:0:0:0:0:0:1'
        ]
        
        match_lower = match.lower()
        return any(fp in match_lower for fp in false_positives)
    
    def _get_code_snippet(self, content: str, line_number: int, context_lines: int = 3) -> str:
        """Get a code snippet around the specified line number."""
        lines = content.splitlines()
        start = max(0, line_number - 1 - context_lines)
        end = min(len(lines), line_number + context_lines)
        
        snippet = []
        for i in range(start, end):
            prefix = '> ' if i == line_number - 1 else '  '
            snippet.append(f"{prefix}{i+1}: {lines[i]}")
        
        return '\n'.join(snippet)
    
    async def _analyze_dependencies(self, decompiled_dir: Path) -> None:
        """Analyze third-party dependencies for known vulnerabilities."""
        logger.info("Analyzing third-party dependencies...")
        
        try:
            if self.config.platform == Platform.ANDROID:
                # Check for build.gradle files
                for build_gradle in decompiled_dir.rglob('build.gradle'):
                    content = build_gradle.read_text(encoding='utf-8', errors='ignore')
                    
                    # Check for outdated or vulnerable dependencies
                    if 'implementation' in content or 'api' in content:
                        # In a real implementation, we would parse the dependencies and check against a vulnerability database
                        self.findings.append(
                            Finding(
                                title="Dependencies Analysis Required",
                                description="The application contains third-party dependencies that should be checked for known vulnerabilities.",
                                severity=Severity.INFO,
                                category="Dependencies",
                                file_path=str(build_gradle.relative_to(decompiled_dir))
                            )
                        )
            
            elif self.config.platform == Platform.IOS:
                # Check for Podfile
                podfile = decompiled_dir / 'Podfile'
                if podfile.exists():
                    self.findings.append(
                        Finding(
                            title="CocoaPods Dependencies Detected",
                            description="The application uses CocoaPods for dependency management. Check for known vulnerabilities in the dependencies.",
                            severity=Severity.INFO,
                            category="Dependencies",
                            file_path=str(podfile.relative_to(decompiled_dir))
                        )
                    )
        
        except Exception as e:
            logger.error(f"Error analyzing dependencies: {str(e)}", exc_info=True)
            self.findings.append(
                Finding(
                    title="Dependency Analysis Error",
                    description=f"An error occurred while analyzing dependencies: {str(e)}",
                    severity=Severity.MEDIUM,
                    category="Analysis Error"
                )
            )
    
    async def _check_insecure_configs(self, decompiled_dir: Path) -> None:
        """Check for insecure configurations in the application."""
        logger.info("Checking for insecure configurations...")
        
        try:
            if self.config.platform == Platform.ANDROID:
                await self._check_android_configs(decompiled_dir)
            elif self.config.platform == Platform.IOS:
                await self._check_ios_configs(decompiled_dir)
        
        except Exception as e:
            logger.error(f"Error checking insecure configurations: {str(e)}", exc_info=True)
            self.findings.append(
                Finding(
                    title="Configuration Analysis Error",
                    description=f"An error occurred while checking configurations: {str(e)}",
                    severity=Severity.MEDIUM,
                    category="Analysis Error"
                )
            )
    
    async def _check_android_configs(self, decompiled_dir: Path) -> None:
        """Check for insecure Android configurations."""
        # Check for WebView configurations
        for file_path in decompiled_dir.rglob('*.java'):
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            # Check for WebView with JavaScript enabled
            if 'setJavaScriptEnabled(true)' in content and 'setJavaScriptEnabled(false)' not in content:
                line_number = content.find('setJavaScriptEnabled(true)') + 1
                self.findings.append(
                    Finding(
                        title="WebView JavaScript Enabled",
                        description="WebView has JavaScript enabled, which can lead to XSS vulnerabilities.",
                        severity=Severity.MEDIUM,
                        category="Insecure Configuration",
                        file_path=str(file_path.relative_to(decompiled_dir)),
                        line_number=line_number,
                        code_snippet=self._get_code_snippet(content, line_number)
                    )
                )
            
            # Check for WebView file access
            if 'setAllowFileAccess(true)' in content and 'setAllowFileAccessFromFileURLs(true)' in content:
                line_number = content.find('setAllowFileAccess(true)') + 1
                self.findings.append(
                    Finding(
                        title="Insecure WebView File Access",
                        description="WebView allows file access from file URLs, which can lead to local file inclusion.",
                        severity=Severity.HIGH,
                        category="Insecure Configuration",
                        file_path=str(file_path.relative_to(decompiled_dir)),
                        line_number=line_number,
                        code_snippet=self._get_code_snippet(content, line_number)
                    )
                )
    
    async def _check_ios_configs(self, decompiled_dir: Path) -> None:
        """Check for insecure iOS configurations."""
        # Check Info.plist for insecure settings
        info_plist = decompiled_dir / 'Info.plist'
        if info_plist.exists():
            content = info_plist.read_text(encoding='utf-8', errors='ignore')
            
            # Check for disabled ATS (App Transport Security)
            if 'NSAppTransportSecurity' in content and 'NSAllowsArbitraryLoads</key><true/>' in content:
                self.findings.append(
                    Finding(
                        title="App Transport Security Disabled",
                        description="App Transport Security (ATS) is disabled, allowing insecure network connections.",
                        severity=Severity.HIGH,
                        category="Insecure Configuration",
                        file_path=str(info_plist.relative_to(decompiled_dir))
                    )
                )
            
            # Check for disabled backup encryption
            if 'NSFileProtectionComplete' not in content and 'NSFileProtectionCompleteUnlessOpen' not in content:
                self.findings.append(
                    Finding(
                        title="Insecure Data Storage",
                        description="The app does not use complete file protection for sensitive data.",
                        severity=Severity.MEDIUM,
                        category="Insecure Storage",
                        file_path=str(info_plist.relative_to(decompiled_dir))
                    )
                )
    
    async def _perform_interactive_tests(self, analyzer: DynamicAnalyzer) -> None:
        """Perform interactive tests on the application."""
        logger.info("Performing interactive tests...")
        
        try:
            # In a real implementation, this would interact with the app UI
            # to test for security issues like input validation, authentication bypass, etc.
            # This is a placeholder for the actual implementation.
            
            # Example: Test for insecure data storage
            await analyzer.test_insecure_storage()
            
            # Example: Test for sensitive data in logs
            await analyzer.test_logging()
            
            # Example: Test for insecure network communication
            await analyzer.test_network_communication()
            
        except Exception as e:
            logger.error(f"Error during interactive tests: {str(e)}", exc_info=True)
            self.findings.append(
                Finding(
                    title="Interactive Test Error",
                    description=f"An error occurred during interactive testing: {str(e)}",
                    severity=Severity.MEDIUM,
                    category="Testing Error"
                )
            )
    
    async def _save_dynamic_analysis_data(self, analyzer: DynamicAnalyzer) -> None:
        """Save dynamic analysis data for AI processing."""
        try:
            # In a real implementation, this would save the collected data
            # in a format suitable for AI/ML processing
            data_dir = self.config.output_dir / 'ai_data'
            data_dir.mkdir(exist_ok=True)
            
            # Save API calls
            api_calls_path = data_dir / 'api_calls.json'
            with open(api_calls_path, 'w') as f:
                json.dump(analyzer.get_api_calls(), f, indent=2)
            
            # Save network traffic
            network_path = data_dir / 'network_traffic.json'
            with open(network_path, 'w') as f:
                json.dump(analyzer.get_network_traffic(), f, indent=2)
            
            # Save file operations
            file_ops_path = data_dir / 'file_operations.json'
            with open(file_ops_path, 'w') as f:
                json.dump(analyzer.get_file_operations(), f, indent=2)
            
            logger.info(f"Saved dynamic analysis data to {data_dir}")
            
        except Exception as e:
            logger.error(f"Error saving dynamic analysis data: {str(e)}", exc_info=True)
            self.findings.append(
                Finding(
                    title="Data Collection Error",
                    description=f"An error occurred while saving dynamic analysis data: {str(e)}",
                    severity=Severity.MEDIUM,
                    category="Analysis Error"
                )
            )
    
    async def _prepare_ai_data(self) -> Tuple[list, list, list]:
        """Prepare data for AI analysis."""
        # In a real implementation, this would prepare the data for the AI model
        # by extracting features from the static and dynamic analysis results
        
        X = []  # Features
        y = []  # Labels
        feature_names = []  # Feature names
        
        # Add features from findings
        for finding in self.findings:
            # Extract features from the finding
            features = {
                'severity': finding.severity.value,
                'category': len(finding.category),  # Simple feature based on category length
                'description_length': len(finding.description)
            }
            
            # Add to feature matrix
            X.append(list(features.values()))
            y.append(1 if finding.severity in [Severity.HIGH, Severity.CRITICAL] else 0)
            
            # Set feature names if not already set
            if not feature_names:
                feature_names = list(features.keys())
        
        return X, y, feature_names
    
    async def _generate_ai_findings(self, model: Any, evaluation: dict) -> None:
        """Generate findings based on AI analysis."""
        try:
            # In a real implementation, this would use the trained model
            # to generate additional findings or prioritize existing ones
            
            # Example: Add a finding about the model's performance
            self.findings.append(
                Finding(
                    title="AI Analysis Completed",
                    description=f"AI analysis completed with {evaluation.get('accuracy', 0):.2f} accuracy.",
                    severity=Severity.INFO,
                    category="AI Analysis"
                )
            )
            
            # Example: Add high-risk findings based on model predictions
            if evaluation.get('high_risk_issues', 0) > 0:
                self.findings.append(
                    Finding(
                        title="Potential High-Risk Issues Detected",
                        description=f"The AI model identified {evaluation.get('high_risk_issues')} potential high-risk issues that require manual review.",
                        severity=Severity.HIGH,
                        category="AI Analysis"
                    )
                )
            
        except Exception as e:
            logger.error(f"Error generating AI findings: {str(e)}", exc_info=True)
            self.findings.append(
                Finding(
                    title="AI Analysis Error",
                    description=f"An error occurred during AI analysis: {str(e)}",
                    severity=Severity.MEDIUM,
                    category="Analysis Error"
                )
            )
    
    async def _generate_report(self) -> Path:
        """Generate a report of the findings."""
        try:
            report_path = self.config.output_dir / 'security_report.json'
            
            # Convert findings to JSON-serializable format
            report_data = {
                'app_path': str(self.config.app_path),
                'platform': self.config.platform.value,
                'timestamp': datetime.now().isoformat(),
                'findings': [
                    {
                        'title': f.title,
                        'description': f.description,
                        'severity': f.severity.value,
                        'category': f.category,
                        'file_path': f.file_path,
                        'line_number': f.line_number,
                        'code_snippet': f.code_snippet
                    }
                    for f in self.findings
                ]
            }
            
            # Write the report
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2)
            
            logger.info(f"Security report generated: {report_path}")
            return report_path
            
        except Exception as e:
            logger.error(f"Error generating report: {str(e)}", exc_info=True)
            raise
    
    def _add_finding(
        self,
        finding_type: str,
        title: str,
        severity: Severity,
        description: str,
        details: Optional[Dict] = None,
        remediation: Optional[str] = None,
        references: Optional[List[str]] = None
    ) -> Finding:
        """Helper method to create and add a finding.
        
        Args:
            finding_type: Type of finding (e.g., 'INSECURE_STORAGE')
            title: Short title of the finding
            severity: Severity level
            description: Detailed description
            details: Additional details about the finding
            remediation: Recommended remediation steps
            references: List of reference URLs
            
        Returns:
            The created Finding object
        """
        if details is None:
            details = {}
        if references is None:
            references = []
            
        finding = Finding(
            platform=self.platform,
            finding_type=finding_type,
            title=title,
            severity=severity,
            description=description,
            details=details,
            remediation=remediation,
            references=references
        )
        
        return finding
