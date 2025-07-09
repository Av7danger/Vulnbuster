"""
VulnBuster iOS Mode Scanner
Comprehensive IPA security analysis and vulnerability detection
"""

import asyncio
import logging
import zipfile
import plistlib
import re
import json
import os
import csv
import random
from typing import Dict, Any, List, Optional
from pathlib import Path
from datetime import datetime
import tempfile
import shutil
try:
    from tqdm import tqdm
except ImportError:
    tqdm = None
import core.ai as mixtral_ai

class IOSScanner:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.ipa_path = None
        self.temp_dir = None
        self.info_plist = {}
        self.findings = []
        self.scan_results = {
            'metadata': {},
            'security_issues': [],
            'api_keys': [],
            'endpoints': [],
            'sdk_detection': [],
            'plist': {},
            'wordlist': [],
            'dynamic_analysis': {},
            'ai_summary': '',
            'ai_remediation': '',
            'ai_rule_suggestions': []
        }
        self.patterns = {
            'aws_keys': [r'AKIA[0-9A-Z]{16}', r'aws_access_key_id', r'aws_secret_access_key'],
            'google_api': [r'AIza[0-9A-Za-z\-_]{35}', r'google_api_key'],
            'firebase': [r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}', r'firebase_token'],
            'stripe': [r'sk_live_[0-9a-zA-Z]{24}', r'pk_live_[0-9a-zA-Z]{24}'],
            'paypal': [r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}'],
            'jwt': [r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'],
            'base64': [r'[A-Za-z0-9+/]{20,}={0,2}'],
            'http_endpoints': [r'https?://[^\s<>"]+'],
        }
        self.known_sdks = [
            'Firebase', 'Facebook', 'GoogleSignIn', 'Crashlytics', 'Appsflyer', 'OneSignal',
            'Stripe', 'PayPal', 'Branch', 'Mixpanel', 'Amplitude', 'Unity', 'Adjust', 'Flurry',
        ]

    async def run(self, target: str, args: Any) -> List[Dict[str, Any]]:
        try:
            self.ipa_path = target
            print(f"🔍 Starting iOS IPA analysis: {self.ipa_path}")
            if not (self.ipa_path and isinstance(self.ipa_path, str) and await self._validate_ipa()):
                return []
            if not (self.ipa_path and isinstance(self.ipa_path, str) and await self._extract_ipa()):
                return []
            await self._perform_scans(args)
            await self._generate_reports()
            await self._cleanup()
            return self.findings
        except Exception as e:
            print(f"❌ iOS scan failed: {e}")
            await self._cleanup()
            return []

    async def _validate_ipa(self) -> bool:
        try:
            if not (self.ipa_path and isinstance(self.ipa_path, str) and os.path.exists(self.ipa_path)):
                print(f"❌ IPA file not found: {self.ipa_path}")
                return False
            if not zipfile.is_zipfile(self.ipa_path):
                print(f"❌ Invalid IPA file (not a valid ZIP): {self.ipa_path}")
                return False
            with zipfile.ZipFile(self.ipa_path, 'r') as ipa:
                if 'Info.plist' not in ipa.namelist() and not any(f.endswith('Info.plist') for f in ipa.namelist()):
                    print(f"⚠️  IPA missing Info.plist")
            print("✅ IPA validation passed")
            return True
        except Exception as e:
            print(f"❌ IPA validation failed: {e}")
            return False

    async def _extract_ipa(self) -> bool:
        try:
            if not (self.ipa_path and isinstance(self.ipa_path, str)):
                print(f"❌ IPA path is invalid: {self.ipa_path}")
                return False
            self.temp_dir = tempfile.mkdtemp(prefix="vulnbuster_ios_")
            with zipfile.ZipFile(self.ipa_path, 'r') as ipa:
                ipa.extractall(self.temp_dir)
            print(f"✅ IPA extracted to: {self.temp_dir}")
            return True
        except Exception as e:
            print(f"❌ IPA extraction failed: {e}")
            return False

    async def _perform_scans(self, args: Any):
        steps = [
            (self._extract_metadata, "Extracting metadata"),
            (self._scan_info_plist, "Parsing Info.plist"),
            (self._scan_mobileprovision, "Parsing embedded.mobileprovision"),
            (self._scan_resources, "Resource/asset analysis"),
            (self._scan_api_keys, "API key/secret detection"),
            (self._scan_endpoints, "Endpoint detection"),
            (self._sdk_detection, "Third-party SDK detection"),
            (self._custom_rule_engine, "Custom rule engine"),
            (self._ai_rule_suggestions, "AI rule suggestions"),
            (self._static_code_analysis_stub, "Static code analysis stub"),
            (self._dynamic_analysis, "Dynamic analysis"),
            (self._ai_summary_and_remediation, "AI summary/remediation"),
            (self._auto_poc_generation, "Auto PoC/exploit script generation"),
        ]
        iterator = tqdm(steps, desc="iOS Scan Progress") if tqdm else steps
        for func, desc in iterator:
            print(f"➡️  {desc}")
            await func()

    async def _extract_metadata(self):
        try:
            self.scan_results['metadata'] = {
                'ipa_path': self.ipa_path,
                'scan_date': datetime.now().isoformat(),
            }
        except Exception:
            pass

    async def _scan_info_plist(self):
        try:
            plist_path = None
            if self.temp_dir:
                for root, _, files in os.walk(self.temp_dir):
                    for file in files:
                        if file == 'Info.plist':
                            plist_path = os.path.join(root, file)
                            break
            if plist_path and os.path.exists(plist_path):
                with open(plist_path, 'rb') as f:
                    self.info_plist = plistlib.load(f)
                self.scan_results['plist'] = self.info_plist
                print(f"✅ Parsed Info.plist: {plist_path}")
            else:
                print("⚠️  Info.plist not found")
        except Exception as e:
            print(f"❌ Info.plist parsing failed: {e}")

    async def _scan_mobileprovision(self):
        try:
            if self.temp_dir:
                for root, _, files in os.walk(self.temp_dir):
                    for file in files:
                        if file.endswith('.mobileprovision'):
                            path = os.path.join(root, file)
                            with open(path, 'rb') as f:
                                content = f.read()
                            # Extract entitlements and team info (simple regex)
                            team = re.findall(rb'<key>TeamName</key>\s*<string>([^<]+)</string>', content)
                            if team:
                                self.scan_results['metadata']['team'] = team[0].decode(errors='ignore')
                            break
        except Exception:
            pass

    async def _scan_resources(self):
        try:
            if self.temp_dir:
                for root, _, files in os.walk(self.temp_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        if file.endswith(('.plist', '.json', '.txt', '.js', '.xml', '.strings')):
                            try:
                                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()
                                for name, patterns in self.patterns.items():
                                    for pat in patterns:
                                        for match in re.findall(pat, content):
                                            self.scan_results['security_issues'].append({'type': f'resource_{name}', 'file': file_path, 'value': match, 'remediation': 'Remove hardcoded secrets from resources.'})
                            except Exception:
                                continue
        except Exception as e:
            print(f"[Resource] Analysis failed: {e}")

    async def _scan_api_keys(self):
        try:
            if self.temp_dir:
                for root, _, files in os.walk(self.temp_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        if file.endswith(('.plist', '.json', '.txt', '.js', '.xml', '.strings')):
                            try:
                                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()
                                for name, patterns in self.patterns.items():
                                    for pat in patterns:
                                        for match in re.findall(pat, content):
                                            self.scan_results['api_keys'].append({'type': name, 'file': file_path, 'value': match})
                            except Exception:
                                continue
        except Exception as e:
            print(f"[API Key] Detection failed: {e}")

    async def _scan_endpoints(self):
        try:
            endpoints = set()
            if self.temp_dir:
                for root, _, files in os.walk(self.temp_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        for pat in self.patterns['http_endpoints']:
                            for match in re.findall(pat, file_path):
                                endpoints.add(match)
            self.scan_results['endpoints'] = list(endpoints)
        except Exception as e:
            print(f"[Endpoint] Detection failed: {e}")

    async def _sdk_detection(self):
        try:
            found_sdks = set()
            for root, _, files in os.walk(self.temp_dir):
                for file in files:
                    for sdk in self.known_sdks:
                        if sdk.lower() in file.lower():
                            found_sdks.add(sdk)
            self.scan_results['sdk_detection'] = list(found_sdks)
        except Exception as e:
            print(f"[SDK Detection] Failed: {e}")

    async def _static_code_analysis_stub(self):
        print("[Stub] Static code analysis not yet implemented. Place decompiled code in temp dir for future analysis.")

    async def _auto_poc_generation(self):
        try:
            poc_dir = Path('reports/poc')
            poc_dir.mkdir(parents=True, exist_ok=True)
            for issue in self.scan_results['security_issues']:
                if issue['type'].startswith('resource_'):
                    poc_path = poc_dir / f"poc_{issue['type']}_{random.randint(1000,9999)}.md"
                    with open(poc_path, 'w', encoding='utf-8') as f:
                        f.write(f"# Proof of Concept for {issue['type']}\n\n")
                        f.write(f"**Finding:** {issue}\n\n")
                        f.write("## Suggested Exploit Steps\n")
                        f.write("- Manual review required.\n")
                        f.write("- Use Frida, objection, or custom scripts as appropriate.\n")
        except Exception as e:
            print(f"[PoC] Auto PoC generation failed: {e}")

    async def _ipa_decompilation_stub(self):
        """Stub for IPA decompilation (class-dump, otool, Hopper)"""
        print("[Stub] IPA decompilation not yet implemented.")

    async def _entitlements_provisioning_analysis_stub(self):
        """Stub for entitlements/provisioning analysis"""
        print("[Stub] Entitlements/provisioning analysis not yet implemented.")

    async def _dynamic_analysis(self):
        """Perform dynamic analysis: emulator/device, UI automation, network capture (stubbed)"""
        try:
            print("[Dynamic] Starting dynamic analysis (stub)")
            dynamic_results = {
                'emulator': None,
                'ui_automation': None,
                'network_capture': None,
                'oob_detection': None,
                'errors': []
            }
            # --- Emulator/device interaction (stub) ---
            try:
                # TODO: Integrate with simctl, install IPA, launch, collect logs
                print("[Dynamic] Emulator/device interaction (stub)")
                dynamic_results['emulator'] = {
                    'status': 'stub',
                    'details': 'Emulator/device interaction not implemented. Use simctl to install/launch IPA and collect logs.'
                }
            except Exception as e:
                dynamic_results['errors'].append(f"Emulator/device error: {e}")
            # --- UI automation (stub) ---
            try:
                # TODO: Integrate with XCUITest/Appium for UI fuzzing
                print("[Dynamic] UI automation (stub)")
                dynamic_results['ui_automation'] = {
                    'status': 'stub',
                    'details': 'UI automation not implemented. Use Appium/XCUITest for UI fuzzing.'
                }
            except Exception as e:
                dynamic_results['errors'].append(f"UI automation error: {e}")
            # --- Network capture (stub) ---
            try:
                # TODO: Integrate with mitmproxy/tcpdump for traffic capture
                print("[Dynamic] Network capture (stub)")
                dynamic_results['network_capture'] = {
                    'status': 'stub',
                    'details': 'Network capture not implemented. Use mitmproxy/tcpdump for traffic analysis.'
                }
            except Exception as e:
                dynamic_results['errors'].append(f"Network capture error: {e}")
            # --- OOB/callback detection (stub) ---
            try:
                # TODO: Integrate OOB/callback detection for SSRF, blind XSS, etc.
                print("[Dynamic] OOB/callback detection (stub)")
                dynamic_results['oob_detection'] = {
                    'status': 'stub',
                    'details': 'OOB/callback detection not implemented.'
                }
            except Exception as e:
                dynamic_results['errors'].append(f"OOB detection error: {e}")
            # Save results
            self.scan_results['dynamic_analysis'] = dynamic_results
            print("[Dynamic] Dynamic analysis complete (stub)")
        except Exception as e:
            print(f"[Dynamic] Analysis failed: {e}")
            if 'dynamic_analysis' not in self.scan_results:
                self.scan_results['dynamic_analysis'] = {'errors': []}
            self.scan_results['dynamic_analysis']['errors'].append(str(e))

    async def _third_party_sdk_tracker_detection_stub(self):
        """Stub for third-party SDK/tracker detection"""
        print("[Stub] Third-party SDK/tracker detection not yet implemented.")

    async def _malware_privacy_heuristics_stub(self):
        """Stub for malware/privacy heuristics (privacy-violating APIs, trackers, background tasks)"""
        print("[Stub] Malware/privacy heuristics not yet implemented.")

    async def _ai_summary_and_remediation(self):
        """Generate AI-powered summary and remediation advice for findings (stub)"""
        try:
            # TODO: Integrate with LLM (OpenAI, local LLM, etc.)
            print("[AI] Generating AI-powered summary and remediation (stub)")
            summary = "[AI] This is a stub summary. Integrate with an LLM for real results."
            remediation = "[AI] This is a stub remediation. Integrate with an LLM for real results."
            self.scan_results['ai_summary'] = summary
            self.scan_results['ai_remediation'] = remediation
        except Exception as e:
            print(f"[AI] Summary/remediation failed: {e}")
            self.scan_results['ai_summary'] = str(e)
            self.scan_results['ai_remediation'] = str(e)

    async def _ai_rule_suggestions(self):
        """Suggest new rules or highlight suspicious patterns using LLM (stub)"""
        try:
            # TODO: Integrate with LLM for rule suggestions
            print("[AI] Suggesting new rules (stub)")
            self.scan_results['ai_rule_suggestions'] = [
                {'suggestion': '[AI] Example: Add a rule for detecting hardcoded OAuth tokens.'}
            ]
        except Exception as e:
            print(f"[AI] Rule suggestion failed: {e}")
            self.scan_results['ai_rule_suggestions'] = [str(e)]

    async def _custom_rule_engine(self):
        """Apply user-defined custom regex rules from config/custom_rules.yaml or .json, with context-aware matching and metadata support"""
        try:
            if not self.temp_dir:
                print("[Custom Rules] temp_dir is not set.")
                return
            import yaml
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
                print("[Custom Rules] No regexes defined in custom_rules.yaml/.json.")
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
                if context == 'plist' or context == 'any':
                    for root, _, files in os.walk(self.temp_dir):
                        for file in files:
                            if file.endswith('.plist'):
                                search_targets.append(os.path.join(root, file))
                if context == 'resources' or context == 'any':
                    for subdir in ['Resources', 'res', 'assets']:
                        dir_path = os.path.join(self.temp_dir, subdir)
                        if os.path.exists(dir_path):
                            for root, _, files in os.walk(dir_path):
                                for file in files:
                                    search_targets.append(os.path.join(root, file))
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
                            self.scan_results['security_issues'].append(finding)
                            print(f"[Custom Rule] Match in {file_path}: {match}")
                            try:
                                explanation = await mixtral_ai.explain_rule(pattern)
                                finding['ai_explanation'] = explanation
                            except Exception as e:
                                finding['ai_explanation'] = f"[AI error: {e}]"
                    except Exception:
                        continue
        except Exception as e:
            print(f"[Custom Rules] Engine failed: {e}")

    def _ai_risk_score(self):
        issues = self.scan_results['security_issues']
        score = min(10, len(issues) // 2 + random.randint(0, 3))
        summary = f"This IPA scan found {len(issues)} potential security issues. Risk score: {score}/10. "
        if score >= 8:
            summary += "High risk. Immediate remediation recommended."
        elif score >= 5:
            summary += "Moderate risk. Review and address findings."
        else:
            summary += "Low risk. Minor issues detected."
        return summary, score

    async def _generate_reports(self):
        try:
            os.makedirs('reports', exist_ok=True)
            ipa_name = os.path.splitext(os.path.basename(self.ipa_path))[0]
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            summary, score = self._ai_risk_score()
            json_report = {
                'scan_info': {
                    'ipa_path': self.ipa_path,
                    'scan_date': datetime.now().isoformat(),
                    'scanner': 'VulnBuster iOS Scanner',
                    'ai_summary': summary,
                    'risk_score': score
                },
                'results': self.scan_results,
                'findings': self.scan_results['security_issues']
            }
            json_path = f"reports/ios_{ipa_name}_{timestamp}.json"
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(json_report, f, indent=2)
            txt_path = f"reports/ios_{ipa_name}_{timestamp}.txt"
            with open(txt_path, 'w', encoding='utf-8') as f:
                f.write("VulnBuster iOS IPA Scan Report\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Executive Summary: {summary}\n\n")
                metadata = self.scan_results['metadata']
                f.write(f"IPA: {metadata.get('ipa_path', 'Unknown')}\n")
                f.write(f"Risk Score: {score}/10\n\n")
                f.write("Security Issues:\n")
                f.write("-" * 20 + "\n")
                for issue in self.scan_results['security_issues']:
                    f.write(f"[{issue.get('type','').upper()}] {issue}\n")
                    if 'remediation' in issue:
                        f.write(f"  Remediation: {issue['remediation']}\n")
            csv_path = f"reports/ios_{ipa_name}_{timestamp}.csv"
            with open(csv_path, 'w', encoding='utf-8', newline='') as csvfile:
                fieldnames = ['type', 'file', 'value', 'remediation']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for issue in self.scan_results['security_issues']:
                    writer.writerow({
                        'type': issue.get('type', ''),
                        'file': issue.get('file', ''),
                        'value': str(issue.get('value', '')),
                        'remediation': issue.get('remediation', '')
                    })
            print(f"✅ Reports generated: {json_path}, {txt_path}, {csv_path}")
        except Exception as e:
            print(f"❌ Report generation failed: {e}")
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
        for finding in self.scan_results.get('security_issues', []):
            if finding.get('type') in ['custom_rule', 'resource_aws_keys', 'resource_google_api', 'obfuscation', 'certificate']:
                try:
                    poc = await mixtral_ai.build_poc(finding)
                    finding['ai_poc'] = poc
                except Exception as e:
                    finding['ai_poc'] = f"[AI PoC error: {e}]"

    async def _cleanup(self):
        try:
            if self.temp_dir and os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
        except Exception:
            pass 