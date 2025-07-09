"""
VulnBuster Android Mode Scanner
Comprehensive APK security analysis and vulnerability detection
"""

import asyncio
import logging
import zipfile
import xml.etree.ElementTree as ET
import re
import json
import base64
import os
from typing import Dict, Any, List, Optional, Set
from pathlib import Path
from datetime import datetime
import tempfile
import shutil
import random
import yaml
import hashlib
import csv
try:
    from tqdm import tqdm
except ImportError:
    tqdm = None
import jinja2
from core import ai as mixtral_ai

from core.utils import color_print, print_banner
import argparse
from modules.static_analyzer import StaticAPKAnalyzer

class AndroidScanner:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.apk_path: str = ""
        self.temp_dir = None
        self.manifest_data = {}
        self.findings = []
        self.scan_results = {
            'metadata': {},
            'security_issues': [],
            'api_keys': [],
            'endpoints': [],
            'components': [],
            'permissions': [],
            'manifest_analysis': {},
            'wordlist': [],
            'dynamic_analysis': {},
            'ai_summary': '',
            'ai_remediation': '',
            'ai_rule_suggestions': []
        }
        
        # Regex patterns for detection
        self.patterns = {
            'aws_keys': [
                r'AKIA[0-9A-Z]{16}',
                r'aws_access_key_id',
                r'aws_secret_access_key'
            ],
            'google_api': [
                r'AIza[0-9A-Za-z\-_]{35}',
                r'google_api_key',
                r'google_services\.json'
            ],
            'firebase': [
                r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
                r'firebase_token',
                r'firebase_config'
            ],
            'stripe': [
                r'sk_live_[0-9a-zA-Z]{24}',
                r'pk_live_[0-9a-zA-Z]{24}',
                r'stripe_key'
            ],
            'paypal': [
                r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
                r'paypal_client_id'
            ],
            'jwt': [
                r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
                r'bearer\s+[A-Za-z0-9\-._~+/]+=*'
            ],
            'base64': [
                r'[A-Za-z0-9+/]{20,}={0,2}'
            ],
            'http_endpoints': [
                r'https?://[^\s<>"\']+',
                r'http://[^\s<>"\']+'
            ],
            'internal_endpoints': [
                r'[a-zA-Z0-9.-]+\.(com|org|net|io|co|me|tv|app|dev)',
                r'api\.[a-zA-Z0-9.-]+',
                r'[a-zA-Z0-9.-]+\.api\.[a-zA-Z0-9.-]+'
            ]
        }
        
        # Dangerous permissions
        self.dangerous_permissions = [
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE',
            'android.permission.READ_PHONE_STATE',
            'android.permission.READ_CONTACTS',
            'android.permission.READ_CALL_LOG',
            'android.permission.READ_SMS',
            'android.permission.SEND_SMS',
            'android.permission.CAMERA',
            'android.permission.RECORD_AUDIO',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.ACCESS_COARSE_LOCATION',
            'android.permission.SYSTEM_ALERT_WINDOW',
            'android.permission.WRITE_SETTINGS',
            'android.permission.REQUEST_INSTALL_PACKAGES',
            'android.permission.INSTALL_PACKAGES'
        ]
        
    async def run(self, target: str, args: Any) -> List[Dict[str, Any]]:
        """Main entry point for Android APK scanning"""
        try:
            self.apk_path = target
            
            color_print(f"🔍 Starting Android APK analysis: {self.apk_path}", 'info')
            
            # Validate APK
            if not await self._validate_apk():
                return []
            
            # Extract APK contents
            if not await self._extract_apk():
                return []
            
            # Perform requested scans
            await self._perform_scans(args)
            
            # Generate reports
            await self._generate_reports()
            
            # Cleanup
            await self._cleanup()
            
            return self.findings
            
        except Exception as e:
            color_print(f"❌ Android scan failed: {e}", 'error')
            logging.error(f"Android scan error: {e}")
            await self._cleanup()
            return []
    
    async def _validate_apk(self) -> bool:
        """Validate APK file"""
        try:
            if not self.apk_path or not isinstance(self.apk_path, str) or not os.path.exists(self.apk_path):
                color_print(f"❌ APK file not found: {self.apk_path}", 'error')
                return False
            
            if not zipfile.is_zipfile(self.apk_path):
                color_print(f"❌ Invalid APK file (not a valid ZIP): {self.apk_path}", 'error')
                return False
            
            # Check for required APK files
            with zipfile.ZipFile(self.apk_path, 'r') as apk:
                required_files = ['AndroidManifest.xml', 'classes.dex']
                missing_files = [f for f in required_files if f not in apk.namelist()]
                
                if missing_files:
                    color_print(f"⚠️  APK missing required files: {missing_files}", 'warning')
            
            color_print("✅ APK validation passed", 'success')
            return True
            
        except Exception as e:
            color_print(f"❌ APK validation failed: {e}", 'error')
            return False
    
    async def _extract_apk(self) -> bool:
        """Extract APK contents to temporary directory"""
        try:
            self.temp_dir = tempfile.mkdtemp(prefix="vulnbuster_android_")
            
            with zipfile.ZipFile(self.apk_path, 'r') as apk:
                apk.extractall(self.temp_dir)
            
            color_print(f"✅ APK extracted to: {self.temp_dir}", 'info')
            return True
            
        except Exception as e:
            color_print(f"❌ APK extraction failed: {e}", 'error')
            return False
    
    async def _perform_scans(self, args: Any):
        """Perform requested scans"""
        try:
            # --- Integrate StaticAPKAnalyzer ---
            if self.apk_path and isinstance(self.apk_path, str) and os.path.exists(self.apk_path):
                static_analyzer = StaticAPKAnalyzer(self.apk_path)
                static_results = static_analyzer.analyze()
                # Merge static analyzer results into scan_results
                self.scan_results['manifest_analysis'] = static_results.get('manifest', {})
                self.scan_results['dex_strings'] = static_results.get('dex_strings', [])
                self.scan_results['class_names'] = static_results.get('class_names', [])
                self.scan_results['method_names'] = static_results.get('method_names', [])
                self.scan_results['dangerous_apis'] = static_results.get('dangerous_apis', [])
                self.scan_results['embedded'] = static_results.get('embedded', {})
                self.scan_results['resource_secrets'] = static_results.get('secrets', [])
                color_print("[StaticAPKAnalyzer] Results integrated.", 'success')
                color_print("[StaticAPKAnalyzer] AI Summary:", 'info')
                color_print(static_analyzer.ai_summary(), 'info')
                # Print summary of new findings
                color_print(f"[StaticAPKAnalyzer] Classes: {len(self.scan_results['class_names'])}", 'info')
                color_print(f"[StaticAPKAnalyzer] Methods: {len(self.scan_results['method_names'])}", 'info')
                color_print(f"[StaticAPKAnalyzer] Dangerous APIs: {self.scan_results['dangerous_apis']}", 'warning')
                color_print(f"[StaticAPKAnalyzer] Embedded URLs: {len(self.scan_results['embedded'].get('urls', []))}", 'info')
                color_print(f"[StaticAPKAnalyzer] Embedded Secrets: {len(self.scan_results['embedded'].get('secrets', []))}", 'warning')
            # --- End integration ---
            steps = [
                (self._extract_metadata, "Extracting metadata"),
                (self._scan_apis, "Scanning APIs"),
                (self._scan_api_keys, "Scanning API keys"),
                (self._scan_components, "Scanning components"),
                (self._analyze_manifest, "Analyzing manifest"),
                (self._build_wordlist, "Building wordlist"),
                (self._security_checks, "Performing security checks"),
                (self._dex_string_analysis, "DEX string/code analysis"),
                (self._resource_asset_analysis, "Resource/asset analysis"),
                (self._obfuscation_packing_detection, "Obfuscation/packing detection"),
                (self._certificate_signature_analysis, "Certificate/signature analysis"),
                (self._third_party_sdk_detection, "Third-party SDK/library detection"),
                (self._custom_rule_engine, "Custom rule engine"),
                (self._ai_rule_suggestions, "AI rule suggestions"),
                (self._virustotal_stub, "VirusTotal/MobSF integration stub"),
                (self._decompilation_integration, "Decompilation (JADX) integration"),
                (self._static_code_analysis, "Static code analysis"),
                (self._dynamic_analysis, "Dynamic analysis"),
                (self._ai_summary_and_remediation, "AI summary/remediation"),
                (self._auto_poc_generation, "Auto PoC/exploit script generation"),
                (self._ai_chat_stub, "AI chat/REPL integration stub"),
            ]
            iterator = tqdm(steps, desc="Scan Progress") if tqdm else steps
            for func, desc in iterator:
                color_print(f"➡️  {desc}", 'info')
                await func(args) if 'args' in func.__code__.co_varnames else await func()
            # After all scans, generate AI summary and exploit chain
            try:
                summary = await mixtral_ai.summarize_scan(self.scan_results)
                self.scan_results['ai_summary'] = summary
            except Exception as e:
                self.scan_results['ai_summary'] = f"[AI summary error: {e}]"
            try:
                chain = await mixtral_ai.generate_exploit_chain(self.scan_results.get('security_issues', []))
                self.scan_results['ai_exploit_chain'] = chain
            except Exception as e:
                self.scan_results['ai_exploit_chain'] = f"[AI exploit chain error: {e}]"
            # For each finding, try to generate a PoC if applicable
            for finding in self.scan_results.get('security_issues', []):
                if finding.get('type') in ['custom_rule', 'dex_string', 'resource_aws_keys', 'resource_google_api', 'obfuscation', 'certificate']:
                    try:
                        poc = await mixtral_ai.build_poc(finding)
                        finding['ai_poc'] = poc
                    except Exception as e:
                        finding['ai_poc'] = f"[AI PoC error: {e}]"
        except Exception as e:
            color_print(f"❌ Scan error: {e}", 'error')

    async def _third_party_sdk_detection(self, *args, **kwargs):
        """Detect third-party SDKs/libraries in DEX and manifest"""
        try:
            if not self.temp_dir:
                color_print("[SDK] temp_dir is not set.", 'error')
                return
            known_sdks = [
                'com.facebook', 'com.google.firebase', 'com.crashlytics', 'com.adjust', 'com.flurry',
                'com.onesignal', 'com.appsflyer', 'com.bugsnag', 'com.mixpanel', 'com.segment',
                'com.paypal', 'com.stripe', 'com.squareup', 'com.amplitude', 'com.branch',
                'com.chartboost', 'com.applovin', 'com.unity3d', 'com.vungle', 'com.ironsource',
                'com.moat', 'com.inmobi', 'com.tapjoy', 'com.adcolony', 'com.startapp',
            ]
            found_sdks = set()
            # Scan DEX files for package names
            dex_files = [f for f in os.listdir(self.temp_dir) if f.endswith('.dex')]
            for dex in dex_files:
                dex_path = os.path.join(self.temp_dir, dex)
                with open(dex_path, 'rb') as f:
                    data = f.read()
                for sdk in known_sdks:
                    if sdk.encode() in data:
                        found_sdks.add(sdk)
            # Scan manifest for package names
            manifest_path = os.path.join(self.temp_dir, 'AndroidManifest.xml')
            if os.path.exists(manifest_path):
                with open(manifest_path, 'rb') as f:
                    content = f.read()
                for sdk in known_sdks:
                    if sdk.encode() in content:
                        found_sdks.add(sdk)
            if found_sdks:
                self.scan_results['security_issues'].append({'type': 'third_party_sdk', 'sdks': list(found_sdks)})
                color_print(f"[SDK] Detected third-party SDKs: {', '.join(found_sdks)}", 'warning')
        except Exception as e:
            color_print(f"[SDK] Detection failed: {e}", 'error')

    async def _custom_rule_engine(self, *args, **kwargs):
        """Apply user-defined custom regex rules from config/custom_rules.yaml or .json, with context-aware matching and metadata support"""
        try:
            if not self.temp_dir:
                color_print("[Custom Rules] temp_dir is not set.", 'error')
                return
            rule_path_yaml = os.path.join('config', 'custom_rules.yaml')
            rule_path_json = os.path.join('config', 'custom_rules.json')
            rules = None
            if os.path.exists(rule_path_yaml):
                with open(rule_path_yaml, 'r', encoding='utf-8') as f:
                    rules = yaml.safe_load(f)
            elif os.path.exists(rule_path_json):
                with open(rule_path_json, 'r', encoding='utf-8') as f:
                    rules = json.load(f)
            if not rules or 'regexes' not in rules:
                color_print("[Custom Rules] No regexes defined in custom_rules.yaml/.json.", 'info')
                return
            regexes = rules['regexes']
            for rule in regexes:
                # Support rule as dict with metadata or as plain string
                if isinstance(rule, dict):
                    pattern = rule.get('pattern')
                    context = rule.get('context', 'any')
                    severity = rule.get('severity', 'info')
                    description = rule.get('description', '')
                    remediation = rule.get('remediation', '')
                else:
                    pattern = rule
                    context = 'any'
                    severity = 'info'
                    description = ''
                    remediation = ''
                if not isinstance(pattern, str):
                    continue
                # Context-aware matching
                search_targets = []
                if context == 'manifest' or context == 'any':
                    manifest_path = os.path.join(self.temp_dir, 'AndroidManifest.xml') if self.temp_dir else None
                    if manifest_path and isinstance(manifest_path, str) and os.path.exists(manifest_path):
                        search_targets.append(manifest_path)
                if context == 'dex' or context == 'any':
                    if self.temp_dir and isinstance(self.temp_dir, str):
                        for root, _, files in os.walk(self.temp_dir):
                            for file in files:
                                if file.endswith('.dex'):
                                    file_path = os.path.join(root, file)
                                    search_targets.append(file_path)
                if context == 'resources' or context == 'any':
                    for subdir in ['res', 'assets']:
                        dir_path = os.path.join(self.temp_dir, subdir) if self.temp_dir else None
                        if dir_path and isinstance(dir_path, str) and os.path.exists(dir_path):
                            for root, _, files in os.walk(dir_path):
                                for file in files:
                                    file_path = os.path.join(root, file)
                                    search_targets.append(file_path)
                # Search in targets
                for file_path in search_targets:
                    try:
                        with open(file_path, 'rb') as f:
                            content = f.read().decode(errors='ignore')
                        for match in re.findall(pattern, content):
                            finding = {
                                'type': 'custom_rule',
                                'rule': pattern,
                                'file': file_path,
                                'value': match,
                                'context': context,
                                'severity': severity,
                                'description': description,
                                'remediation': remediation
                            }
                            # AI-powered rule explanation
                            try:
                                explanation = await mixtral_ai.explain_rule(pattern)
                                finding['ai_explanation'] = explanation
                            except Exception as e:
                                finding['ai_explanation'] = f"[AI error: {e}]"
                            self.scan_results['security_issues'].append(finding)
                            color_print(f"[Custom Rule] Match in {file_path}: {match}", 'warning')
                    except Exception:
                        continue
        except Exception as e:
            color_print(f"[Custom Rules] Engine failed: {e}", 'error')

    async def _ai_summary_and_remediation(self, *args, **kwargs):
        """Generate AI-powered summary and remediation advice for findings (stub)"""
        try:
            # TODO: Integrate with LLM (OpenAI, local LLM, etc.)
            color_print("[AI] Generating AI-powered summary and remediation (stub)", 'info')
            summary = "[AI] This is a stub summary. Integrate with an LLM for real results."
            remediation = "[AI] This is a stub remediation. Integrate with an LLM for real results."
            self.scan_results['ai_summary'] = summary
            self.scan_results['ai_remediation'] = remediation
        except Exception as e:
            color_print(f"[AI] Summary/remediation failed: {e}", 'error')
            self.scan_results['ai_summary'] = str(e)
            self.scan_results['ai_remediation'] = str(e)

    async def _ai_rule_suggestions(self, *args, **kwargs):
        """Suggest new rules or highlight suspicious patterns using LLM (stub)"""
        try:
            # TODO: Integrate with LLM for rule suggestions
            color_print("[AI] Suggesting new rules (stub)", 'info')
            self.scan_results['ai_rule_suggestions'] = [
                {'suggestion': '[AI] Example: Add a rule for detecting hardcoded OAuth tokens.'}
            ]
        except Exception as e:
            color_print(f"[AI] Rule suggestion failed: {e}", 'error')
            self.scan_results['ai_rule_suggestions'] = [str(e)]

    async def _virustotal_stub(self, *args, **kwargs):
        """Stub for VirusTotal/MobSF integration"""
        try:
            apk_hash = None
            if self.apk_path and isinstance(self.apk_path, str) and os.path.exists(self.apk_path):
                with open(self.apk_path, 'rb') as f:
                    apk_hash = hashlib.sha256(f.read()).hexdigest()
            color_print(f"[VirusTotal] APK SHA256: {apk_hash}", 'info')
            color_print("[VirusTotal] Online check not implemented. Configure API key for integration.", 'warning')
        except Exception as e:
            color_print(f"[VirusTotal] Stub failed: {e}", 'error')

    async def _ai_chat_stub(self, *args, **kwargs):
        color_print("[AI Chat] REPL integration not yet implemented. Use the main AI REPL for questions.", 'warning')

    async def _decompilation_integration(self, *args, **kwargs):
        color_print("[JADX] Decompilation integration not yet implemented. Place decompiled code in temp dir for static analysis.", 'warning')

    async def _static_code_analysis(self, *args, **kwargs):
        """Scan decompiled code for insecure API usage and hardcoded secrets"""
        try:
            if not self.temp_dir:
                color_print("[Static Analysis] temp_dir is not set.", 'error')
                return
            # Example insecure API patterns
            insecure_apis = [
                r'WebView\.addJavascriptInterface',
                r'WebView\.loadUrl',
                r'Cipher\.getInstance\("DES"',
                r'Cipher\.getInstance\("RC2"',
                r'Cipher\.getInstance\("RC4"',
                r'Cipher\.getInstance\("AES/ECB',
                r'KeyStore\.getInstance\("BKS"',
                r'getSharedPreferences\(',
                r'openOrCreateDatabase\(',
                r'Runtime\.getRuntime\(\)\.exec',
                r'ProcessBuilder\(',
                r'Class\.forName\(',
                r'loadLibrary\(',
                r'setJavaScriptEnabled\(true\)',
            ]
            findings = []
            decompiled_dir = os.path.join(self.temp_dir, 'decompiled') if self.temp_dir else ''
            if not decompiled_dir or not os.path.exists(decompiled_dir):
                color_print("[Static Analysis] No decompiled code found (run JADX or similar).", 'info')
                return
            for root, _, files in os.walk(decompiled_dir):
                for file in files:
                    if file.endswith('.java') or file.endswith('.smali'):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                            for api in insecure_apis:
                                for match in re.findall(api, content):
                                    finding = {'type': 'insecure_api', 'api': api, 'file': file_path, 'value': match, 'remediation': 'Review and replace with secure alternative.'}
                                    self.scan_results['security_issues'].append(finding)
                                    findings.append(finding)
                            # Also scan for secrets
                            for name, patterns in self.patterns.items():
                                for pat in patterns:
                                    for match in re.findall(pat, content):
                                        finding = {'type': f'static_secret_{name}', 'file': file_path, 'value': match, 'remediation': 'Remove hardcoded secrets from code.'}
                                        self.scan_results['security_issues'].append(finding)
                                        findings.append(finding)
                        except Exception:
                            continue
            if findings:
                color_print(f"[Static Analysis] Found {len(findings)} issues in decompiled code.", 'warning')
        except Exception as e:
            color_print(f"[Static Analysis] Failed: {e}", 'error')

    async def _dynamic_analysis(self, args: Any):
        """Perform dynamic analysis: emulator/device, UI automation, network capture, Frida, mitmproxy, ADB (scaffolded)"""
        try:
            color_print("[Dynamic] Starting dynamic analysis (Frida, mitmproxy, ADB)", 'info')
            dynamic_results = {
                'frida': None,
                'mitmproxy': None,
                'adb': None,
                'errors': []
            }
            # --- Frida integration (stub) ---
            try:
                # TODO: Implement Frida hooks, API tracing, memory inspection
                color_print("[Dynamic] Frida integration (stub)", 'info')
                dynamic_results['frida'] = {
                    'status': 'stub',
                    'details': 'Frida integration not implemented. Use Frida scripts for runtime analysis.'
                }
            except Exception as e:
                dynamic_results['errors'].append(f"Frida error: {e}")
            # --- mitmproxy network logging (stub) ---
            try:
                # TODO: Implement mitmproxy traffic capture and annotation
                color_print("[Dynamic] mitmproxy network logging (stub)", 'info')
                dynamic_results['mitmproxy'] = {
                    'status': 'stub',
                    'details': 'mitmproxy integration not implemented. Route emulator/device traffic for capture.'
                }
            except Exception as e:
                dynamic_results['errors'].append(f"mitmproxy error: {e}")
            # --- ADB file system and live interaction (stub) ---
            try:
                # TODO: Implement ADB file system browser, shell, app interaction
                color_print("[Dynamic] ADB file system/browser (stub)", 'info')
                dynamic_results['adb'] = {
                    'status': 'stub',
                    'details': 'ADB integration not implemented. Use ADB for file system, shell, and app control.'
                }
            except Exception as e:
                dynamic_results['errors'].append(f"ADB error: {e}")
            self.scan_results['dynamic_analysis'] = dynamic_results
            color_print("[Dynamic] Dynamic analysis complete (scaffolded)", 'success')
        except Exception as e:
            color_print(f"[Dynamic] Analysis failed: {e}", 'error')
            if 'dynamic_analysis' not in self.scan_results:
                self.scan_results['dynamic_analysis'] = {'errors': []}
            self.scan_results['dynamic_analysis']['errors'].append(str(e))

    async def _auto_poc_generation(self, *args, **kwargs):
        """Auto-generate PoC/exploit scripts for key findings"""
        try:
            poc_dir = os.path.join('reports', 'poc')
            os.makedirs(poc_dir, exist_ok=True)
            for issue in self.scan_results['security_issues']:
                if issue['type'] in ['dex_string', 'resource_aws_keys', 'resource_google_api', 'obfuscation', 'certificate']:
                    poc_path = os.path.join(poc_dir, f"poc_{issue['type']}_{random.randint(1000,9999)}.md")
                    with open(poc_path, 'w', encoding='utf-8') as f:
                        f.write(f"# Proof of Concept for {issue['type']}\n\n")
                        f.write(f"**Finding:** {issue}\n\n")
                        f.write("## Suggested Exploit Steps\n")
                        f.write("- Manual review required.\n")
                        f.write("- Use ADB, Frida, or custom scripts as appropriate.\n")
            color_print(f"[PoC] Auto PoC scripts generated in {poc_dir}", 'success')
        except Exception as e:
            color_print(f"[PoC] Auto PoC generation failed: {e}", 'error')

    def _ai_risk_score(self):
        """AI-generated risk score and executive summary (stub)"""
        issues = self.scan_results['security_issues']
        score = min(10, len(issues) // 2 + random.randint(0, 3))
        summary = f"This APK scan found {len(issues)} potential security issues. Risk score: {score}/10. "
        if score >= 8:
            summary += "High risk. Immediate remediation recommended."
        elif score >= 5:
            summary += "Moderate risk. Review and address findings."
        else:
            summary += "Low risk. Minor issues detected."
        return summary, score

    async def _extract_metadata(self):
        """Extract APK metadata from AndroidManifest.xml"""
        try:
            manifest_path = os.path.join(self.temp_dir, 'AndroidManifest.xml')
            
            if not os.path.exists(manifest_path):
                color_print("⚠️  AndroidManifest.xml not found", 'warning')
                return
            
            # Parse manifest
            manifest_data = await self._parse_manifest(manifest_path)
            
            if manifest_data:
                self.scan_results['metadata'] = {
                    'package_name': manifest_data.get('package', 'Unknown'),
                    'version_code': manifest_data.get('versionCode', 'Unknown'),
                    'version_name': manifest_data.get('versionName', 'Unknown'),
                    'min_sdk': manifest_data.get('minSdkVersion', 'Unknown'),
                    'target_sdk': manifest_data.get('targetSdkVersion', 'Unknown'),
                    'permissions': manifest_data.get('permissions', []),
                    'activities': manifest_data.get('activities', []),
                    'services': manifest_data.get('services', []),
                    'receivers': manifest_data.get('receivers', []),
                    'providers': manifest_data.get('providers', [])
                }
                
                color_print("✅ Metadata extracted successfully", 'success')
                
                # Print metadata summary
                self._print_metadata_summary()
            
        except Exception as e:
            color_print(f"❌ Metadata extraction failed: {e}", 'error')
    
    async def _parse_manifest(self, manifest_path: str) -> Optional[Dict[str, Any]]:
        """Parse AndroidManifest.xml (handle both binary and plain XML)"""
        try:
            # Try to read as plain XML first
            try:
                with open(manifest_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Parse XML
                root = ET.fromstring(content)
                return self._extract_manifest_data(root)
                
            except (UnicodeDecodeError, ET.ParseError):
                # Try binary manifest parsing
                return await self._parse_binary_manifest(manifest_path)
                
        except Exception as e:
            color_print(f"❌ Manifest parsing failed: {e}", 'error')
            return None
    
    def _extract_manifest_data(self, root: ET.Element) -> Dict[str, Any]:
        """Extract data from parsed XML manifest"""
        data = {}
        
        # Get manifest attributes
        manifest = root.find('.')
        if manifest is not None:
            data['package'] = manifest.get('package', 'Unknown')
            data['versionCode'] = manifest.get('android:versionCode', 'Unknown')
            data['versionName'] = manifest.get('android:versionName', 'Unknown')
        
        # Get uses-sdk
        uses_sdk = root.find('.//uses-sdk')
        if uses_sdk is not None:
            data['minSdkVersion'] = uses_sdk.get('android:minSdkVersion', 'Unknown')
            data['targetSdkVersion'] = uses_sdk.get('android:targetSdkVersion', 'Unknown')
        
        # Get permissions
        permissions = []
        for perm in root.findall('.//uses-permission'):
            permissions.append(perm.get('android:name', 'Unknown'))
        data['permissions'] = permissions
        
        # Get components
        data['activities'] = self._extract_components(root, 'activity')
        data['services'] = self._extract_components(root, 'service')
        data['receivers'] = self._extract_components(root, 'receiver')
        data['providers'] = self._extract_components(root, 'provider')
        
        return data
    
    def _extract_components(self, root: ET.Element, component_type: str) -> List[Dict[str, Any]]:
        """Extract component information"""
        components = []
        
        for component in root.findall(f'.//{component_type}'):
            comp_data = {
                'name': component.get('android:name', 'Unknown'),
                'exported': component.get('android:exported', 'Unknown'),
                'intent_filters': []
            }
            
            # Get intent filters
            for intent_filter in component.findall('.//intent-filter'):
                filter_data = {
                    'actions': [action.get('android:name') for action in intent_filter.findall('.//action')],
                    'categories': [cat.get('android:name') for cat in intent_filter.findall('.//category')],
                    'data': []
                }
                
                # Get data elements
                for data in intent_filter.findall('.//data'):
                    data_info = {
                        'scheme': data.get('android:scheme'),
                        'host': data.get('android:host'),
                        'port': data.get('android:port'),
                        'path': data.get('android:path'),
                        'mimeType': data.get('android:mimeType')
                    }
                    filter_data['data'].append(data_info)
                
                comp_data['intent_filters'].append(filter_data)
            
            components.append(comp_data)
        
        return components
    
    async def _parse_binary_manifest(self, manifest_path: str) -> Optional[Dict[str, Any]]:
        """Basic binary manifest parsing (simplified)"""
        try:
            # This is a simplified binary parser
            # In a full implementation, you'd use a proper binary XML parser
            
            with open(manifest_path, 'rb') as f:
                content = f.read()
            
            # Look for common patterns in binary manifest
            data = {}
            
            # Extract package name (simplified)
            package_match = re.search(rb'package="([^"]+)"', content)
            if package_match:
                data['package'] = package_match.group(1).decode('utf-8', errors='ignore')
            
            # Extract version info
            version_match = re.search(rb'android:versionCode="([^"]+)"', content)
            if version_match:
                data['versionCode'] = version_match.group(1).decode('utf-8', errors='ignore')
            
            # Extract permissions
            permissions = []
            for match in re.finditer(rb'android:name="([^"]+)"', content):
                perm = match.group(1).decode('utf-8', errors='ignore')
                if 'permission' in perm:
                    permissions.append(perm)
            data['permissions'] = permissions
            
            return data
            
        except Exception as e:
            color_print(f"❌ Binary manifest parsing failed: {e}", 'error')
            return None
    
    async def _scan_apis(self):
        """Scan for API endpoints and network calls"""
        try:
            color_print("🔍 Scanning for API endpoints...", 'info')
            
            endpoints = set()
            
            # Scan all files in APK
            for root, dirs, files in os.walk(self.temp_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    try:
                        # Read file content
                        if file.endswith(('.xml', '.txt', '.json', '.properties')):
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                        else:
                            # For binary files, try to extract strings
                            with open(file_path, 'rb') as f:
                                content = f.read().decode('utf-8', errors='ignore')
                        
                        # Find HTTP endpoints
                        for pattern in self.patterns['http_endpoints']:
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            endpoints.update(matches)
                        
                        # Find internal endpoints
                        for pattern in self.patterns['internal_endpoints']:
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            endpoints.update(matches)
                    
                    except Exception as e:
                        continue
            
            self.scan_results['endpoints'] = list(endpoints)
            
            color_print(f"✅ Found {len(endpoints)} endpoints", 'success')
            
            # Print endpoints
            if endpoints:
                color_print("\n🌐 Detected Endpoints:", 'info')
                for endpoint in sorted(endpoints):
                    color_print(f"  - {endpoint}", 'info')
            
        except Exception as e:
            color_print(f"❌ API scanning failed: {e}", 'error')
    
    async def _scan_api_keys(self):
        """Scan for API keys and secrets"""
        try:
            color_print("🔍 Scanning for API keys and secrets...", 'info')
            
            found_keys = []
            
            # Scan all files in APK
            for root, dirs, files in os.walk(self.temp_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    try:
                        # Read file content
                        if file.endswith(('.xml', '.txt', '.json', '.properties')):
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                        else:
                            # For binary files, try to extract strings
                            with open(file_path, 'rb') as f:
                                content = f.read().decode('utf-8', errors='ignore')
                        
                        # Check each pattern
                        for key_type, patterns in self.patterns.items():
                            if key_type in ['http_endpoints', 'internal_endpoints']:
                                continue
                            
                            for pattern in patterns:
                                matches = re.findall(pattern, content, re.IGNORECASE)
                                for match in matches:
                                    found_keys.append({
                                        'type': key_type,
                                        'value': match,
                                        'file': os.path.relpath(file_path, self.temp_dir),
                                        'severity': 'high' if key_type in ['aws_keys', 'stripe'] else 'medium'
                                    })
                    
                    except Exception as e:
                        continue
            
            self.scan_results['api_keys'] = found_keys
            
            color_print(f"✅ Found {len(found_keys)} potential secrets", 'success')
            
            # Print findings
            if found_keys:
                color_print("\n🔑 Detected Secrets:", 'warning')
                for key in found_keys:
                    severity_color = 'error' if key['severity'] == 'high' else 'warning'
                    color_print(f"  [{key['type'].upper()}] {key['value'][:50]}... in {key['file']}", severity_color)
            
        except Exception as e:
            color_print(f"❌ API key scanning failed: {e}", 'error')
    
    async def _scan_components(self):
        """Scan for exported components and security issues"""
        try:
            color_print("🔍 Scanning components...", 'info')
            
            components = []
            security_issues = []
            
            # Analyze activities
            for activity in self.scan_results['metadata'].get('activities', []):
                comp_info = {
                    'type': 'Activity',
                    'name': activity['name'],
                    'exported': activity['exported'],
                    'intent_filters': activity['intent_filters']
                }
                components.append(comp_info)
                
                # Check for security issues
                if activity['exported'] == 'true':
                    security_issues.append({
                        'type': 'Exported Activity',
                        'component': activity['name'],
                        'severity': 'medium',
                        'description': 'Activity is exported and accessible from other apps'
                    })
            
            # Analyze services
            for service in self.scan_results['metadata'].get('services', []):
                comp_info = {
                    'type': 'Service',
                    'name': service['name'],
                    'exported': service['exported'],
                    'intent_filters': service['intent_filters']
                }
                components.append(comp_info)
                
                if service['exported'] == 'true':
                    security_issues.append({
                        'type': 'Exported Service',
                        'component': service['name'],
                        'severity': 'medium',
                        'description': 'Service is exported and accessible from other apps'
                    })
            
            # Analyze receivers
            for receiver in self.scan_results['metadata'].get('receivers', []):
                comp_info = {
                    'type': 'BroadcastReceiver',
                    'name': receiver['name'],
                    'exported': receiver['exported'],
                    'intent_filters': receiver['intent_filters']
                }
                components.append(comp_info)
                
                if receiver['exported'] == 'true':
                    security_issues.append({
                        'type': 'Exported Receiver',
                        'component': receiver['name'],
                        'severity': 'medium',
                        'description': 'BroadcastReceiver is exported and accessible from other apps'
                    })
            
            self.scan_results['components'] = components
            self.scan_results['security_issues'].extend(security_issues)
            
            color_print(f"✅ Analyzed {len(components)} components", 'success')
            
            # Print components
            if components:
                color_print("\n📱 Components:", 'info')
                for comp in components:
                    export_status = "🔓 EXPORTED" if comp['exported'] == 'true' else "🔒 INTERNAL"
                    color_print(f"  {comp['type']}: {comp['name']} ({export_status})", 'info')
            
        except Exception as e:
            color_print(f"❌ Component scanning failed: {e}", 'error')
    
    async def _analyze_manifest(self):
        """Detailed manifest analysis"""
        try:
            color_print("🔍 Analyzing AndroidManifest.xml...", 'info')
            
            manifest_analysis = {
                'package_info': self.scan_results['metadata'],
                'security_flags': {},
                'permission_analysis': {},
                'component_analysis': {}
            }
            
            # Check for security flags
            manifest_path = os.path.join(self.temp_dir, 'AndroidManifest.xml')
            if os.path.exists(manifest_path):
                with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Check for debuggable flag
                if 'android:debuggable="true"' in content:
                    manifest_analysis['security_flags']['debuggable'] = True
                    self.scan_results['security_issues'].append({
                        'type': 'Debug Mode Enabled',
                        'severity': 'high',
                        'description': 'App is debuggable in production'
                    })
                
                # Check for cleartext traffic
                if 'android:usesCleartextTraffic="true"' in content:
                    manifest_analysis['security_flags']['cleartext_traffic'] = True
                    self.scan_results['security_issues'].append({
                        'type': 'Cleartext Traffic Allowed',
                        'severity': 'medium',
                        'description': 'App allows cleartext HTTP traffic'
                    })
            
            # Analyze permissions
            permissions = self.scan_results['metadata'].get('permissions', [])
            dangerous_found = []
            
            for perm in permissions:
                if perm in self.dangerous_permissions:
                    dangerous_found.append(perm)
            
            manifest_analysis['permission_analysis'] = {
                'total_permissions': len(permissions),
                'dangerous_permissions': dangerous_found,
                'permission_list': permissions
            }
            
            if dangerous_found:
                for perm in dangerous_found:
                    self.scan_results['security_issues'].append({
                        'type': 'Dangerous Permission',
                        'permission': perm,
                        'severity': 'medium',
                        'description': f'App requests dangerous permission: {perm}'
                    })
            
            self.scan_results['manifest_analysis'] = manifest_analysis
            
            color_print("✅ Manifest analysis completed", 'success')
            
            # Print analysis
            self._print_manifest_analysis(manifest_analysis)
            
        except Exception as e:
            color_print(f"❌ Manifest analysis failed: {e}", 'error')
    
    async def _build_wordlist(self):
        """Build wordlist from APK resources"""
        try:
            color_print("🔍 Building wordlist from APK resources...", 'info')
            
            words = set()
            
            # Extract strings from strings.xml
            strings_files = [
                os.path.join(self.temp_dir, 'res', 'values', 'strings.xml'),
                os.path.join(self.temp_dir, 'res', 'values-v21', 'strings.xml'),
                os.path.join(self.temp_dir, 'res', 'values-v23', 'strings.xml')
            ]
            
            for strings_file in strings_files:
                if os.path.exists(strings_file):
                    try:
                        with open(strings_file, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        
                        # Extract string values
                        string_matches = re.findall(r'<string[^>]*>([^<]+)</string>', content)
                        words.update(string_matches)
                        
                    except Exception as e:
                        continue
            
            # Extract from other resource files
            for root, dirs, files in os.walk(self.temp_dir):
                for file in files:
                    if file.endswith(('.xml', '.txt', '.json')):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                            
                            # Extract potential words
                            word_matches = re.findall(r'\b[a-zA-Z][a-zA-Z0-9_]{2,}\b', content)
                            words.update(word_matches)
                            
                        except Exception as e:
                            continue
            
            # Clean and filter words
            filtered_words = []
            for word in words:
                if len(word) >= 3 and not word.isdigit():
                    filtered_words.append(word)
            
            self.scan_results['wordlist'] = filtered_words
            
            # Save wordlist
            package_name = self.scan_results['metadata'].get('package_name', 'unknown')
            wordlist_path = f"wordlists/android_{package_name}.txt"
            
            os.makedirs('wordlists', exist_ok=True)
            with open(wordlist_path, 'w', encoding='utf-8') as f:
                for word in sorted(filtered_words):
                    f.write(word + '\n')
            
            color_print(f"✅ Generated wordlist with {len(filtered_words)} words: {wordlist_path}", 'success')
            
        except Exception as e:
            color_print(f"❌ Wordlist generation failed: {e}", 'error')
    
    async def _security_checks(self):
        """Perform additional security checks"""
        try:
            color_print("🔍 Performing security checks...", 'info')
            
            # Check for SSL pinning
            ssl_pinning_found = False
            
            for root, dirs, files in os.walk(self.temp_dir):
                for file in files:
                    if file.endswith(('.smali', '.java', '.xml')):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                            
                            # Check for SSL pinning indicators
                            ssl_indicators = [
                                'TrustManager',
                                'HostnameVerifier',
                                'setSSLSocketFactory',
                                'certificatePinner',
                                'X509TrustManager'
                            ]
                            
                            for indicator in ssl_indicators:
                                if indicator in content:
                                    ssl_pinning_found = True
                                    break
                            
                            if ssl_pinning_found:
                                break
                                
                        except Exception as e:
                            continue
                
                if ssl_pinning_found:
                    break
            
            if ssl_pinning_found:
                self.scan_results['security_issues'].append({
                    'type': 'SSL Pinning Detected',
                    'severity': 'info',
                    'description': 'App implements SSL certificate pinning'
                })
            else:
                self.scan_results['security_issues'].append({
                    'type': 'No SSL Pinning',
                    'severity': 'medium',
                    'description': 'App does not implement SSL certificate pinning'
                })
            
            color_print("✅ Security checks completed", 'success')
            
        except Exception as e:
            color_print(f"❌ Security checks failed: {e}", 'error')

    async def _dex_string_analysis(self):
        """Extract and analyze printable strings from DEX files, flag suspicious content"""
        try:
            dex_files = [f for f in os.listdir(self.temp_dir) if f.endswith('.dex')]
            suspicious_patterns = [
                r'https?://[\w\.-]+',
                r'api_key|secret|token|password|auth',
                r'\b[A-Za-z0-9_\-]{32,}\b',
                r'\bsk_live_[0-9a-zA-Z]{24}\b',
                r'\bAKIA[0-9A-Z]{16}\b',
                r'AIza[0-9A-Za-z\-_]{35}',
                r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
            ]
            findings = []
            for dex in dex_files:
                dex_path = os.path.join(self.temp_dir, dex)
                with open(dex_path, 'rb') as f:
                    data = f.read()
                # Extract printable strings
                strings = set(re.findall(rb'[\x20-\x7E]{6,}', data))
                for s in strings:
                    s_dec = s.decode(errors='ignore')
                    for pat in suspicious_patterns:
                        if re.search(pat, s_dec):
                            findings.append({'dex_file': dex, 'string': s_dec, 'pattern': pat})
                            self.scan_results['security_issues'].append({'type': 'dex_string', 'value': s_dec, 'pattern': pat})
            if findings:
                color_print(f"[DEX] Found {len(findings)} suspicious strings in DEX files.", 'warning')
        except Exception as e:
            color_print(f"[DEX] String analysis failed: {e}", 'error')

    async def _resource_asset_analysis(self):
        """Scan res/ and assets/ for sensitive files and secrets"""
        try:
            for subdir in ['res', 'assets']:
                dir_path = os.path.join(self.temp_dir, subdir)
                if os.path.exists(dir_path):
                    for root, _, files in os.walk(dir_path):
                        for file in files:
                            file_path = os.path.join(root, file)
                            try:
                                with open(file_path, 'rb') as f:
                                    content = f.read()
                                # Look for secrets in text files
                                if file.endswith(('.xml', '.json', '.txt', '.js', '.properties', '.cfg', '.ini')):
                                    text = content.decode(errors='ignore')
                                    for name, patterns in self.patterns.items():
                                        for pat in patterns:
                                            for match in re.findall(pat, text):
                                                self.scan_results['security_issues'].append({'type': f'resource_{name}', 'file': file_path, 'value': match})
                                                color_print(f"[Resource] Secret in {file_path}: {match}", 'warning')
                            except Exception:
                                continue
        except Exception as e:
            color_print(f"[Resource] Asset analysis failed: {e}", 'error')

    async def _obfuscation_packing_detection(self):
        """Detect obfuscators/packers in DEX and manifest"""
        try:
            # Check for ProGuard, DexGuard, Bangcle, etc.
            proguard_files = ['proguard.cfg', 'proguard-project.txt', 'META-INF/proguard', 'META-INF/dexguard']
            found = []
            for f in proguard_files:
                if os.path.exists(os.path.join(self.temp_dir, f)):
                    found.append(f)
            # Check for suspicious class names in DEX
            suspicious_classes = []
            dex_files = [f for f in os.listdir(self.temp_dir) if f.endswith('.dex')]
            for dex in dex_files:
                dex_path = os.path.join(self.temp_dir, dex)
                with open(dex_path, 'rb') as f:
                    data = f.read()
                # Look for class names like a/a/a, b/b/b, etc.
                if re.search(rb'L[a-z]/[a-z]/[a-z];', data):
                    suspicious_classes.append(dex)
            if found or suspicious_classes:
                self.scan_results['security_issues'].append({'type': 'obfuscation', 'files': found, 'dex': suspicious_classes})
                color_print(f"[Obfuscation] Detected: files={found}, dex={suspicious_classes}", 'warning')
        except Exception as e:
            color_print(f"[Obfuscation] Detection failed: {e}", 'error')

    async def _certificate_signature_analysis(self):
        """Extract and analyze signing certificate details"""
        try:
            meta_inf = os.path.join(self.temp_dir, 'META-INF')
            if os.path.exists(meta_inf):
                for file in os.listdir(meta_inf):
                    if file.endswith(('.RSA', '.DSA', '.EC')):
                        cert_path = os.path.join(meta_inf, file)
                        try:
                            with open(cert_path, 'rb') as f:
                                cert_data = f.read()
                            # Look for 'Android Debug' or weak keys
                            if b'Android Debug' in cert_data or b'testkey' in cert_data:
                                self.scan_results['security_issues'].append({'type': 'certificate', 'file': cert_path, 'issue': 'debug/test key'})
                                color_print(f"[Cert] Debug/test key in {cert_path}", 'warning')
                        except Exception:
                            continue
        except Exception as e:
            color_print(f"[Cert] Signature analysis failed: {e}", 'error')
    
    def _print_metadata_summary(self):
        """Print APK metadata summary"""
        metadata = self.scan_results['metadata']
        
        color_print("\n📱 APK Metadata:", 'info')
        color_print(f"  Package: {metadata.get('package_name', 'Unknown')}", 'info')
        color_print(f"  Version: {metadata.get('version_name', 'Unknown')} ({metadata.get('version_code', 'Unknown')})", 'info')
        color_print(f"  SDK: {metadata.get('min_sdk', 'Unknown')} - {metadata.get('target_sdk', 'Unknown')}", 'info')
        color_print(f"  Permissions: {len(metadata.get('permissions', []))}", 'info')
        color_print(f"  Activities: {len(metadata.get('activities', []))}", 'info')
        color_print(f"  Services: {len(metadata.get('services', []))}", 'info')
        color_print(f"  Receivers: {len(metadata.get('receivers', []))}", 'info')
    
    def _print_manifest_analysis(self, analysis: Dict[str, Any]):
        """Print manifest analysis results"""
        color_print("\n📋 Manifest Analysis:", 'info')
        
        # Security flags
        flags = analysis.get('security_flags', {})
        if flags:
            color_print("  Security Flags:", 'warning')
            for flag, value in flags.items():
                status = "🔴 ENABLED" if value else "🟢 DISABLED"
                color_print(f"    {flag}: {status}", 'warning')
        
        # Permission analysis
        perm_analysis = analysis.get('permission_analysis', {})
        color_print(f"  Total Permissions: {perm_analysis.get('total_permissions', 0)}", 'info')
        
        dangerous_perms = perm_analysis.get('dangerous_permissions', [])
        if dangerous_perms:
            color_print("  Dangerous Permissions:", 'warning')
            for perm in dangerous_perms:
                color_print(f"    - {perm}", 'warning')
    
    async def _generate_reports(self):
        """Generate HTML and Markdown reports using Jinja2 templates"""
        try:
            os.makedirs('reports', exist_ok=True)
            # HTML report
            env = jinja2.Environment(loader=jinja2.FileSystemLoader('templates'))
            html_template = env.get_template('report_android.html.j2')
            html_report = html_template.render(scan_results=self.scan_results)
            html_path = os.path.join('reports', f'android_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html')
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_report)
            color_print(f"[Report] HTML report generated: {html_path}", 'success')
            # Markdown report
            md_template = env.get_template('summary_android.md.j2')
            md_report = md_template.render(scan_results=self.scan_results)
            md_path = os.path.join('reports', f'android_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md')
            with open(md_path, 'w', encoding='utf-8') as f:
                f.write(md_report)
            color_print(f"[Report] Markdown summary generated: {md_path}", 'success')
        except Exception as e:
            color_print(f"[Report] Generation failed: {e}", 'error')
    
    async def _cleanup(self):
        """Clean up temporary files"""
        try:
            if self.temp_dir and os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
                color_print("🧹 Temporary files cleaned up", 'info')
        except Exception as e:
            color_print(f"⚠️  Cleanup warning: {e}", 'warning')

    async def _dex_smali_analysis_stub(self):
        """Stub for DEX/Smali decompilation and analysis"""
        color_print("[Stub] DEX/Smali analysis not yet implemented.", 'warning')

    async def _dynamic_analysis_stub(self):
        """Stub for emulator-based dynamic analysis (Frida/objection)"""
        color_print("[Stub] Dynamic analysis not yet implemented.", 'warning')

    async def _certificate_signature_analysis_stub(self):
        """Stub for certificate/signature analysis (debug/test keys, weak certs)"""
        color_print("[Stub] Certificate/signature analysis not yet implemented.", 'warning')

    async def _third_party_sdk_tracker_detection_stub(self):
        """Stub for third-party SDK/tracker detection"""
        color_print("[Stub] Third-party SDK/tracker detection not yet implemented.", 'warning')

    async def _malware_heuristics_stub(self):
        """Stub for malware heuristics (permissions, background services, SMS/call interception)"""
        color_print("[Stub] Malware heuristics not yet implemented.", 'warning')

# Main entry point for the scanner
async def run(target: str, args: Any) -> List[Dict[str, Any]]:
    """Main entry point for Android APK scanning"""
    config = {
        'verbose': getattr(args, 'verbose', False),
        'output': getattr(args, 'output', 'reports')
    }
    
    scanner = AndroidScanner(config)
    return await scanner.run(target, args) 

def main():
    parser = argparse.ArgumentParser(description='Android Security Scanner')
    parser.add_argument('apk', help='Path to APK file')
    args = parser.parse_args()

    analyzer = StaticAPKAnalyzer(args.apk)
    results = analyzer.analyze()
    print('--- Static Analysis Results ---')
    for k, v in results.items():
        print(f'{k}: {v}')
    print('\n--- AI Summary ---')
    print(analyzer.ai_summary())

if __name__ == '__main__':
    main() 