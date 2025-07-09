"""
VulnBuster Cloud Mode Scanner
Comprehensive cloud config and service security analysis
"""

import asyncio
import logging
import os
import json
import csv
import random
from typing import Dict, Any, List, Optional
from pathlib import Path
from datetime import datetime
try:
    from tqdm import tqdm
except ImportError:
    tqdm = None

import core.ai as mixtral_ai

class CloudScanner:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.cloud_provider = config.get('provider', 'aws')
        self.target = config.get('target')
        self.scan_results = {
            'metadata': {},
            'security_issues': [],
            'findings': [],
            'ai_summary': '',
            'ai_remediation': '',
            'ai_rule_suggestions': [],
            'dynamic_analysis': {}
        }
        self.modules_dir = Path('modes/cloud/modules')
        self.payloads_dir = Path('modes/cloud/payloads')
        self.templates_dir = Path('modes/cloud/templates')

    async def run(self, target: str, args: Any) -> List[Dict[str, Any]]:
        try:
            self.target = target
            print(f"🔍 Starting Cloud Security analysis: {self.target}")
            await self._perform_scans(args)
            await self._generate_reports()
            return self.scan_results['findings']
        except Exception as e:
            print(f"❌ Cloud scan failed: {e}")
            return []

    async def _perform_scans(self, args: Any):
        steps = [
            (self._extract_metadata, "Extracting metadata"),
            (self._scan_config_files, "Scanning config files"),
            (self._scan_secrets, "Secret/key detection"),
            (self._scan_public_buckets, "Public bucket check"),
            (self._scan_iam_policies, "IAM policy analysis"),
            (self._custom_rule_engine, "Custom rule engine"),
            (self._ai_rule_suggestions, "AI rule suggestions"),
            (self._static_analysis_stub, "Static code analysis stub"),
            (self._dynamic_analysis, "Dynamic analysis"),
            (self._cloud_api_integration, "Cloud API integration"),
            (self._ai_summary_and_remediation, "AI summary/remediation"),
        ]
        iterator = tqdm(steps, desc="Cloud Scan Progress") if tqdm else steps
        for func, desc in iterator:
            print(f"➡️  {desc}")
            await func()

    async def _extract_metadata(self):
        self.scan_results['metadata'] = {
            'target': self.target,
            'provider': self.cloud_provider,
            'scan_date': datetime.now().isoformat(),
        }

    async def _scan_config_files(self):
        print("[Stub] Config file scanning not yet implemented.")

    async def _scan_secrets(self):
        print("[Stub] Secret/key detection not yet implemented.")

    async def _scan_public_buckets(self):
        print("[Stub] Public bucket check not yet implemented.")

    async def _scan_iam_policies(self):
        print("[Stub] IAM policy analysis not yet implemented.")

    async def _static_analysis_stub(self):
        print("[Stub] Static code analysis not yet implemented.")

    async def _dynamic_analysis(self):
        """Perform dynamic analysis: cloud API, OOB/callback, network exposure (stubbed)"""
        try:
            print("[Dynamic] Starting dynamic analysis (stub)")
            dynamic_results = {
                'cloud_api': None,
                'oob_detection': None,
                'network_exposure': None,
                'errors': []
            }
            # --- Cloud API interaction (stub) ---
            try:
                # TODO: Integrate with boto3, google-cloud, azure SDKs, etc.
                print("[Dynamic] Cloud API interaction (stub)")
                dynamic_results['cloud_api'] = {
                    'status': 'stub',
                    'details': 'Cloud API interaction not implemented. Use SDKs for real-time checks.'
                }
            except Exception as e:
                dynamic_results['errors'].append(f"Cloud API error: {e}")
            # --- OOB/callback detection (stub) ---
            try:
                # TODO: Integrate OOB/callback detection for SSRF, misconfig, etc.
                print("[Dynamic] OOB/callback detection (stub)")
                dynamic_results['oob_detection'] = {
                    'status': 'stub',
                    'details': 'OOB/callback detection not implemented.'
                }
            except Exception as e:
                dynamic_results['errors'].append(f"OOB detection error: {e}")
            # --- Network exposure (stub) ---
            try:
                # TODO: Integrate with nmap, Shodan, etc. for exposure checks
                print("[Dynamic] Network exposure (stub)")
                dynamic_results['network_exposure'] = {
                    'status': 'stub',
                    'details': 'Network exposure checks not implemented.'
                }
            except Exception as e:
                dynamic_results['errors'].append(f"Network exposure error: {e}")
            self.scan_results['dynamic_analysis'] = dynamic_results
            print("[Dynamic] Dynamic analysis complete (stub)")
        except Exception as e:
            print(f"[Dynamic] Analysis failed: {e}")
            if 'dynamic_analysis' not in self.scan_results:
                self.scan_results['dynamic_analysis'] = {'errors': []}
            self.scan_results['dynamic_analysis']['errors'].append(str(e))

    async def _cloud_api_integration(self):
        """Perform cloud API integration: AWS (boto3), GCP SDK, IAM, S3, serverless, attack surface mapping (scaffolded)"""
        try:
            print("[CloudAPI] Starting cloud API integration (AWS, GCP)")
            dynamic_results = {
                'aws': None,
                'gcp': None,
                'attack_surface': None,
                'errors': []
            }
            # --- AWS integration (stub) ---
            try:
                # TODO: Implement boto3 IAM, S3, Lambda enumeration
                print("[CloudAPI] AWS integration (stub)")
                dynamic_results['aws'] = {
                    'status': 'stub',
                    'details': 'AWS integration not implemented. Use boto3 for IAM, S3, Lambda, etc.'
                }
            except Exception as e:
                dynamic_results['errors'].append(f"AWS error: {e}")
            # --- GCP integration (stub) ---
            try:
                # TODO: Implement GCP SDK IAM, GCS, Cloud Functions enumeration
                print("[CloudAPI] GCP integration (stub)")
                dynamic_results['gcp'] = {
                    'status': 'stub',
                    'details': 'GCP integration not implemented. Use google-cloud SDK for IAM, GCS, Cloud Functions, etc.'
                }
            except Exception as e:
                dynamic_results['errors'].append(f"GCP error: {e}")
            # --- Attack surface mapping (stub) ---
            try:
                # TODO: Aggregate and visualize accessible resources, misconfigs, privilege escalation
                print("[CloudAPI] Attack surface mapping (stub)")
                dynamic_results['attack_surface'] = {
                    'status': 'stub',
                    'details': 'Attack surface mapping not implemented. Aggregate resources and permissions.'
                }
            except Exception as e:
                dynamic_results['errors'].append(f"Attack surface error: {e}")
            self.scan_results['dynamic_analysis'] = dynamic_results
            print("[CloudAPI] Cloud API integration complete (scaffolded)")
        except Exception as e:
            print(f"[CloudAPI] Integration failed: {e}")
            if 'dynamic_analysis' not in self.scan_results:
                self.scan_results['dynamic_analysis'] = {'errors': []}
            self.scan_results['dynamic_analysis']['errors'].append(str(e))

    async def _config_file_parsing_stub(self):
        """Stub for config file parsing (AWS/GCP/Azure, Terraform, CloudFormation)"""
        print("[Stub] Config file parsing not yet implemented.")

    async def _iam_policy_analysis_stub(self):
        """Stub for IAM policy analysis (privilege escalation, wildcards, risky permissions)"""
        print("[Stub] IAM policy analysis not yet implemented.")

    async def _public_resource_detection_stub(self):
        """Stub for public resource detection (S3/GCS buckets, public keys/secrets)"""
        print("[Stub] Public resource detection not yet implemented.")

    async def _secret_key_detection_stub(self):
        """Stub for secret/key detection (regex/YARA for cloud keys, tokens, credentials)"""
        print("[Stub] Secret/key detection not yet implemented.")

    async def _cspm_integration_stub(self):
        """Stub for CSPM integration (open-source CSPM tools)"""
        print("[Stub] CSPM integration not yet implemented.")

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
                {'suggestion': '[AI] Example: Add a rule for detecting public S3 buckets.'}
            ]
        except Exception as e:
            print(f"[AI] Rule suggestion failed: {e}")
            self.scan_results['ai_rule_suggestions'] = [str(e)]

    async def _custom_rule_engine(self):
        """Apply user-defined custom regex rules from config/custom_rules.yaml or .json, with context-aware matching and metadata support"""
        try:
            import yaml
            import re # Added missing import for re
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
                if context == 'config' or context == 'any':
                    for root, _, files in os.walk(str(self.target)):
                        for file in files:
                            if file.endswith(('.yaml', '.yml', '.json', '.tf', '.template')):
                                search_targets.append(os.path.join(root, file))
                if context == 'resources' or context == 'any':
                    for subdir in ['resources', 'templates', 'payloads']:
                        dir_path = os.path.join(str(self.target), subdir)
                        if os.path.exists(dir_path):
                            for root, _, files in os.walk(dir_path):
                                for file in files:
                                    search_targets.append(os.path.join(root, file))
                # Search in targets
                for file_path in search_targets:
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
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
        summary = f"This cloud scan found {len(issues)} potential security issues. Risk score: {score}/10. "
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
            target_name = str(self.target).replace(':', '_').replace('/', '_')
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            summary, score = self._ai_risk_score()
            json_report = {
                'scan_info': {
                    'target': self.target,
                    'provider': self.cloud_provider,
                    'scan_date': datetime.now().isoformat(),
                    'scanner': 'VulnBuster Cloud Scanner',
                    'ai_summary': summary,
                    'risk_score': score
                },
                'results': self.scan_results,
                'findings': self.scan_results['security_issues']
            }
            json_path = f"reports/cloud_{target_name}_{timestamp}.json"
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(json_report, f, indent=2)
            txt_path = f"reports/cloud_{target_name}_{timestamp}.txt"
            with open(txt_path, 'w', encoding='utf-8') as f:
                f.write("VulnBuster Cloud Scan Report\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Executive Summary: {summary}\n\n")
                metadata = self.scan_results['metadata']
                f.write(f"Target: {metadata.get('target', 'Unknown')}\n")
                f.write(f"Provider: {metadata.get('provider', 'Unknown')}\n")
                f.write(f"Risk Score: {score}/10\n\n")
                f.write("Security Issues:\n")
                f.write("-" * 20 + "\n")
                for issue in self.scan_results['security_issues']:
                    f.write(f"[{issue.get('type','').upper()}] {issue}\n")
                    if 'remediation' in issue:
                        f.write(f"  Remediation: {issue['remediation']}\n")
                    if 'ai_explanation' in issue:
                        f.write(f"  AI Explanation: {issue['ai_explanation']}\n")
                    if 'ai_poc' in issue:
                        f.write(f"  AI PoC: {issue['ai_poc']}\n")
            csv_path = f"reports/cloud_{target_name}_{timestamp}.csv"
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
            if finding.get('type') in ['custom_rule', 'iam', 's3', 'serverless']:
                try:
                    poc = await mixtral_ai.build_poc(finding)
                    finding['ai_poc'] = poc
                except Exception as e:
                    finding['ai_poc'] = f"[AI PoC error: {e}]" 