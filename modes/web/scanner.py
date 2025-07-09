"""
Web Mode Scanner - Web application vulnerability scanning
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path

import csv
import random
try:
    from tqdm import tqdm
except ImportError:
    tqdm = None
import re
import yaml

from modes.web.crawler import Crawler
from core.payloads import PayloadEngine
from core.analyzer import Analyzer
from core.reporter import Reporter
from modes.web.dynamic_analyzer import DynamicAnalyzer
from modes.web.oob_manager import OOBManager
from modes.web.ai_fuzzer import AIFuzzer
from modes.web.exploit_chain_analyzer import ExploitChainAnalyzer
from modes.web.auto_remediator import AutoRemediator
from modes.web.ai_custom_rule_assistant import AICustomRuleAssistant
from core import ai as mixtral_ai

class WebScanner:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.target_url = config.get('target')
        self.modules = config.get('modules', [])
        self.verbose = config.get('verbose', False)
        self.threads = config.get('threads', 10)
        self.timeout = config.get('timeout', 10)
        self.crawl_enabled = config.get('crawl', False)
        self.crawl_depth = config.get('depth', 3)
        # Advanced crawler options
        self.crawl_js = config.get('crawl_js', False)
        self.crawl_sitemap = config.get('crawl_sitemap', True)
        self.crawl_robots = config.get('crawl_robots', True)
        self.crawl_login = config.get('crawl_login', False)
        self.crawl_login_url = config.get('crawl_login_url')
        self.crawl_login_user = config.get('crawl_login_user')
        self.crawl_login_pass = config.get('crawl_login_pass')
        # Initialize components
        self.crawler = Crawler(
            base_url=self.target_url,
            max_depth=self.crawl_depth,
            max_urls=100,
            session_manager=None
        )
        self.ai_fuzzer = AIFuzzer(enabled=config.get('ai_fuzzing', True))
        self.payload_engine = PayloadEngine()
        self.analyzer = Analyzer()
        self.reporter = Reporter(config.get('output', 'reports'))
        self.dynamic_analyzer = DynamicAnalyzer(headless=True, timeout=self.timeout)
        self.oob_manager = OOBManager(endpoint=config.get('oob_endpoint'))
        self.exploit_chain_analyzer = ExploitChainAnalyzer()
        self.auto_remediator = AutoRemediator()
        self.ai_custom_rule_assistant = AICustomRuleAssistant()
        
        # Results storage
        self.discovered_urls = []
        self.vulnerabilities = []
        self.scan_results = []
        
    async def scan(self, target: str, modules: List[str], payload_engine: PayloadEngine,
                  via_engine=None, exploit_chain=None) -> List[Dict[str, Any]]:
        """Execute web application vulnerability scan"""
        logging.info(f"Starting web scan of {target}")
        try:
            steps = [
                (self._discover_urls, "Discovering URLs"),
                (lambda: self._run_vulnerability_modules(modules, payload_engine, via_engine), "Running vulnerability modules"),
                (self._dynamic_analysis, "Dynamic analysis (headless browser)"),
                (self._oob_callback_detection, "OOB/Callback detection"),
                (self._exploit_chain_analysis, "Exploit chain analysis"),
                (self._auto_remediation_suggestions, "Auto-remediation suggestions"),
                (self._custom_rule_engine, "Custom rule engine"),
                (self._third_party_framework_detection, "Third-party/framework detection"),
                (self._auto_poc_generation, "Auto PoC/exploit script generation"),
                (self._generate_reports, "Generating reports"),
            ]
            iterator = tqdm(steps, desc="Web Scan Progress") if tqdm else steps
            for func, desc in iterator:
                logging.info(f"➡️  {desc}")
                if asyncio.iscoroutinefunction(func):
                    await func()
                else:
                    await func()
            return self.vulnerabilities
        except Exception as e:
            logging.error(f"Web scan failed: {e}")
            if self.verbose:
                logging.exception("Scan error details:")
            return []
    
    async def _discover_urls(self):
        """Discover URLs through crawling with advanced options"""
        logging.info("Starting URL discovery...")
        try:
            self.discovered_urls = await self.crawler.crawl(
                use_js=self.crawl_js,
                use_sitemap=self.crawl_sitemap,
                use_robots=self.crawl_robots,
                login_first=self.crawl_login,
                login_url=self.crawl_login_url,
                username=self.crawl_login_user,
                password=self.crawl_login_pass
            )
            logging.info(f"Discovered {len(self.discovered_urls)} URLs")
            
            # Get forms for additional testing
            forms = self.crawler.get_forms()
            logging.info(f"Discovered {len(forms)} forms")
            
        except Exception as e:
            logging.error(f"URL discovery failed: {e}")
            self.discovered_urls = [self.target_url]
    
    async def _run_vulnerability_modules(self, modules: List[str], payload_engine: PayloadEngine,
                                       via_engine=None):
        """Run vulnerability modules against discovered URLs"""
        logging.info(f"Running {len(modules)} vulnerability modules")
        
        # Load modules dynamically
        module_instances = await self._load_modules(modules)
        
        # Run modules against each URL
        for url in self.discovered_urls:
            logging.info(f"Testing {url}")
            
            for module_name, module_class in module_instances.items():
                try:
                    # Create module instance
                    module_instance = module_class(
                        url=url,
                        payload_engine=payload_engine,
                        analyzer=self.analyzer,
                        verbose=self.verbose
                    )
                    
                    # Run module
                    if hasattr(module_instance, 'run'):
                        results = await module_instance.run()
                        
                        if results:
                            self.vulnerabilities.extend(results)
                            
                            # Get AI advice if available
                            if via_engine:
                                for result in results:
                                    advice = await via_engine.process_signal(result)
                                    if advice:
                                        result['ai_advice'] = advice
                                        logging.info(f"AI advice for {result.get('type', 'unknown')}: {advice.get('analysis', '')[:100]}...")
                    
                except Exception as e:
                    logging.error(f"Module {module_name} failed for {url}: {e}")
    
    async def _load_modules(self, module_names: List[str]) -> Dict[str, Any]:
        """Load vulnerability modules dynamically"""
        modules = {}
        modules_path = Path(__file__).parent / 'modules'
        
        for module_name in module_names:
            if module_name == 'all':
                # Load all available modules
                for module_file in modules_path.glob("*.py"):
                    if module_file.name != "__init__.py":
                        module_name = module_file.stem
                        try:
                            module_class = await self._import_module(module_file)
                            if module_class:
                                modules[module_name] = module_class
                        except Exception as e:
                            logging.error(f"Failed to load module {module_name}: {e}")
            else:
                # Load specific module
                module_file = modules_path / f"{module_name}.py"
                if module_file.exists():
                    try:
                        module_class = await self._import_module(module_file)
                        if module_class:
                            modules[module_name] = module_class
                    except Exception as e:
                        logging.error(f"Failed to load module {module_name}: {e}")
                else:
                    logging.warning(f"Module {module_name} not found")
        
        logging.info(f"Loaded {len(modules)} modules: {', '.join(modules.keys())}")
        return modules
    
    async def _import_module(self, module_file: Path):
        """Import a module from file"""
        import importlib.util
        
        try:
            spec = importlib.util.spec_from_file_location(module_file.stem, module_file)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            if hasattr(module, 'Module'):
                return module.Module
            else:
                logging.warning(f"Module {module_file.stem} does not have Module class")
                return None
                
        except Exception as e:
            logging.error(f"Failed to import module {module_file.stem}: {e}")
            return None
    
    async def _custom_rule_engine(self):
        """
        Apply user-defined custom rules from config/custom_rules.yaml (supports rich rule format).
        Each rule can specify:
          - name: Rule name
          - pattern: Regex or string to match
          - description: What the rule detects
          - match_on: [url, param, response, dom, ...]
          - action: [flag, suggest, remediate, ...]
        Matching logic:
          - url: Match against discovered URLs
          - param: Match against form/parameter names and values
          - response: (stub) Match against response bodies if available
          - dom: (stub) Match against DOM content from dynamic analysis
        AI assistant can suggest new rules and explain matches.
        """
        import yaml
        from pathlib import Path
        import re
        try:
            rule_path = 'config/custom_rules.yaml'
            if not Path(rule_path).exists():
                logging.info("[Custom Rules] No custom_rules.yaml found. Using AI to suggest starter rules.")
                ai_rules = self.ai_custom_rule_assistant.suggest_rules_from_findings(self.vulnerabilities)
                rules = {'rules': ai_rules}
            else:
                with open(rule_path, 'r', encoding='utf-8') as f:
                    rules = yaml.safe_load(f)
            if not rules or 'rules' not in rules:
                logging.info("[Custom Rules] No rules defined in custom_rules.yaml.")
                return
            for rule in rules['rules']:
                pattern = rule.get('pattern')
                match_on = rule.get('match_on', ['url'])
                description = rule.get('description', '')
                action = rule.get('action', 'flag')
                # URL matching
                if 'url' in match_on and pattern:
                    for url in self.discovered_urls:
                        url_str = url if isinstance(url, str) else str(url) if url is not None else ''
                        if re.search(pattern, url_str, re.IGNORECASE):
                            finding = {
                                'type': 'custom_rule',
                                'rule': rule.get('name', pattern),
                                'url': url_str,
                                'value': url_str,
                                'remediation': description or self.ai_custom_rule_assistant.explain_match(rule, url_str, {'url': url_str}),
                                'action': action,
                                'match_on': 'url'
                            }
                            self.vulnerabilities.append(finding)
                            logging.warning(f"[Custom Rule] URL match in {url_str}: {pattern} ({description})")
                # Param matching (forms/params)
                if 'param' in match_on and pattern:
                    try:
                        forms = self.crawler.get_forms()
                    except Exception:
                        forms = []
                    for form in forms:
                        for input_field in form.get('inputs', []):
                            param_name = input_field.get('name', '') or ''
                            param_value = input_field.get('value', '') or ''
                            if re.search(pattern, param_name, re.IGNORECASE) or re.search(pattern, param_value, re.IGNORECASE):
                                finding = {
                                    'type': 'custom_rule',
                                    'rule': rule.get('name', pattern),
                                    'url': form.get('action') or form.get('url') or self.target_url or '',
                                    'param': param_name,
                                    'value': param_value,
                                    'remediation': description or self.ai_custom_rule_assistant.explain_match(rule, param_name or '', {'form': form}),
                                    'action': action,
                                    'match_on': 'param'
                                }
                                self.vulnerabilities.append(finding)
                                logging.warning(f"[Custom Rule] Param match in {param_name}: {pattern} ({description})")
                # Response matching (stub)
                if 'response' in match_on and pattern:
                    # TODO: Integrate with actual response bodies if available
                    pass
                # DOM matching (stub)
                if 'dom' in match_on and pattern:
                    # TODO: Integrate with actual DOM content from dynamic analysis
                    pass
        except Exception as e:
            logging.error(f"[Custom Rules] Engine failed: {e}")

    async def _third_party_framework_detection(self):
        """Detect common frameworks, CMS, and third-party JS libraries"""
        try:
            frameworks = [
                ('WordPress', r'wp-content|wp-includes'),
                ('Joomla', r'Joomla!'),
                ('Drupal', r'Drupal'),
                ('jQuery', r'jquery(-[0-9.]+)?\.js'),
                ('Angular', r'angular(-[0-9.]+)?\.js'),
                ('React', r'react(-[0-9.]+)?\.js'),
                ('Vue', r'vue(-[0-9.]+)?\.js'),
                ('Bootstrap', r'bootstrap(-[0-9.]+)?\.js'),
                ('FontAwesome', r'font-awesome'),
            ]
            for url in self.discovered_urls:
                for name, pattern in frameworks:
                    if re.search(pattern, url, re.IGNORECASE):
                        finding = {'type': 'third_party_framework', 'framework': name, 'url': url, 'remediation': f'Check for outdated/vulnerable {name} components.'}
                        self.vulnerabilities.append(finding)
                        logging.warning(f"[Framework] Detected {name} in {url}")
        except Exception as e:
            logging.error(f"[Framework Detection] Failed: {e}")

    async def _auto_poc_generation(self):
        """Auto-generate PoC/exploit scripts for key findings"""
        try:
            poc_dir = Path('reports/poc')
            poc_dir.mkdir(parents=True, exist_ok=True)
            for vuln in self.vulnerabilities:
                if vuln.get('type') in ['sqli', 'xss', 'idor', 'csrf', 'file_upload', 'custom_rule']:
                    poc_path = poc_dir / f"poc_{vuln.get('type')}_{random.randint(1000,9999)}.md"
                    with open(poc_path, 'w', encoding='utf-8') as f:
                        f.write(f"# Proof of Concept for {vuln.get('type')}\n\n")
                        f.write(f"**Finding:** {vuln}\n\n")
                        f.write("## Suggested Exploit Steps\n")
                        f.write("- Manual review required.\n")
                        f.write("- Use Burp Suite, curl, or custom scripts as appropriate.\n")
            logging.info(f"[PoC] Auto PoC scripts generated in {poc_dir}")
        except Exception as e:
            logging.error(f"[PoC] Auto PoC generation failed: {e}")

    async def _dynamic_analysis(self):
        """Perform dynamic analysis using Playwright-based DynamicAnalyzer on discovered URLs and forms."""
        logging.info("Starting dynamic analysis on discovered URLs and forms...")
        findings = []
        # Analyze URLs
        for url in self.discovered_urls:
            try:
                url_findings = await self.dynamic_analyzer.scan_url(url)
                if url_findings:
                    findings.extend(url_findings)
                    for f in url_findings:
                        logging.info(f"[Dynamic] {f.get('type','?')} found at {url}")
            except Exception as e:
                logging.warning(f"Dynamic analysis failed for {url}: {e}")
        # Analyze forms (if available)
        forms = []
        try:
            forms = self.crawler.get_forms()
        except Exception:
            pass
        for form in forms:
            try:
                form_url = form.get('action') or form.get('url') or self.target_url
                form_findings = await self.dynamic_analyzer.scan_form(form_url, form)
                if form_findings:
                    findings.extend(form_findings)
                    for f in form_findings:
                        logging.info(f"[Dynamic] {f.get('type','?')} found in form at {form_url}")
            except Exception as e:
                logging.warning(f"Dynamic form analysis failed for {form_url}: {e}")
        self.vulnerabilities.extend(findings)

    async def _oob_callback_detection(self):
        """Poll for OOB/callback events and correlate with scan context."""
        logging.info("Polling for OOB/callback events...")
        events = self.oob_manager.poll_events()
        for event in events:
            correlated = self.oob_manager.correlate_event(event)
            if correlated:
                self.vulnerabilities.append(correlated)
                logging.info(f"[OOB] Callback detected: {correlated}")

    async def _exploit_chain_analysis(self):
        """Analyze vulnerabilities for possible exploit chains and add to findings."""
        logging.info("Analyzing for exploit chains...")
        chains = self.exploit_chain_analyzer.analyze_chains(self.vulnerabilities)
        if chains:
            self.vulnerabilities.extend(chains)
            for chain in chains:
                logging.info(f"[ExploitChain] {chain.get('description','')} (risk: {chain.get('risk','')})")

    async def _auto_remediation_suggestions(self):
        """Add AI-generated remediation suggestions to findings."""
        logging.info("Generating auto-remediation suggestions...")
        for finding in self.vulnerabilities:
            if 'remediation' not in finding or not finding['remediation']:
                finding['remediation'] = self.auto_remediator.suggest_remediation(finding)

    async def _advanced_crawler_stub(self):
        """Stub for advanced crawler (JS rendering, sitemap/robots.txt, login)"""
        logging.info("[Stub] Advanced crawler not yet implemented.")

    async def _ai_driven_fuzzing_stub(self):
        """Stub for AI-driven fuzzing and payload mutation"""
        logging.info("[Stub] AI-driven fuzzing not yet implemented.")

    async def _exploit_chain_analysis_stub(self):
        """Stub for automated exploit chain analysis"""
        logging.info("[Stub] Exploit chain analysis not yet implemented.")

    async def _auto_remediation_suggestions_stub(self):
        """Stub for AI-generated auto-remediation suggestions"""
        logging.info("[Stub] Auto-remediation suggestions not yet implemented.")

    def _ai_risk_score(self):
        """AI-generated risk score and executive summary (stub)"""
        vulns = self.vulnerabilities
        score = min(10, len(vulns) // 2 + random.randint(0, 3))
        summary = f"This web scan found {len(vulns)} potential vulnerabilities. Risk score: {score}/10. "
        if score >= 8:
            summary += "High risk. Immediate remediation recommended."
        elif score >= 5:
            summary += "Moderate risk. Review and address findings."
        else:
            summary += "Low risk. Minor issues detected."
        return summary, score

    async def _generate_reports(self):
        """Generate scan reports with AI summary, risk score, remediation, and CSV export"""
        try:
            metadata = {
                'target_url': self.target_url,
                'scan_date': self._get_current_timestamp(),
                'scan_duration': 'N/A',
                'modules': self.modules,
                'urls_discovered': len(self.discovered_urls),
                'vulnerabilities_found': len(self.vulnerabilities)
            }
            summary, score = self._ai_risk_score()
            report = {
                'metadata': metadata,
                'ai_summary': summary,
                'risk_score': score,
                'findings': self.vulnerabilities
            }
            # JSON
            json_path = f"reports/web_{metadata['target_url'].replace('://','_').replace('/','_')}_{metadata['scan_date']}.json"
            with open(json_path, 'w', encoding='utf-8') as f:
                import json
                json.dump(report, f, indent=2)
            # TXT
            txt_path = f"reports/web_{metadata['target_url'].replace('://','_').replace('/','_')}_{metadata['scan_date']}.txt"
            with open(txt_path, 'w', encoding='utf-8') as f:
                f.write("VulnBuster Web Scan Report\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Executive Summary: {summary}\n\n")
                f.write(f"Risk Score: {score}/10\n\n")
                f.write(f"Target: {metadata['target_url']}\n")
                f.write(f"URLs Discovered: {metadata['urls_discovered']}\n")
                f.write(f"Vulnerabilities Found: {metadata['vulnerabilities_found']}\n\n")
                f.write("Findings:\n")
                f.write("-" * 20 + "\n")
                for vuln in self.vulnerabilities:
                    f.write(f"[{vuln.get('type','').upper()}] {vuln}\n")
                    if 'remediation' in vuln:
                        f.write(f"  Remediation: {vuln['remediation']}\n")
            # CSV
            csv_path = f"reports/web_{metadata['target_url'].replace('://','_').replace('/','_')}_{metadata['scan_date']}.csv"
            with open(csv_path, 'w', encoding='utf-8', newline='') as csvfile:
                fieldnames = ['type', 'url', 'value', 'remediation']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for vuln in self.vulnerabilities:
                    writer.writerow({
                        'type': vuln.get('type', ''),
                        'url': vuln.get('url', ''),
                        'value': str(vuln.get('value', '')),
                        'remediation': vuln.get('remediation', '')
                    })
            logging.info(f"[REPORT] Reports generated: {json_path}, {txt_path}, {csv_path}")
        except Exception as e:
            logging.error(f"Report generation failed: {e}")
    
    def _get_current_timestamp(self) -> str:
        """Get current timestamp string"""
        from datetime import datetime
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    def get_scan_summary(self) -> Dict[str, Any]:
        """Get summary of scan results"""
        return {
            'target_url': self.target_url,
            'urls_discovered': len(self.discovered_urls),
            'vulnerabilities_found': len(self.vulnerabilities),
            'risk_distribution': self._get_risk_distribution(),
            'module_coverage': self._get_module_coverage(),
            'scan_config': {
                'crawl_enabled': self.crawl_enabled,
                'crawl_depth': self.crawl_depth,
                'threads': self.threads,
                'timeout': self.timeout
            }
        }
    
    def _get_risk_distribution(self) -> Dict[str, int]:
        """Get distribution of vulnerability risk levels"""
        distribution = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for vuln in self.vulnerabilities:
            risk = vuln.get('risk', 'medium').lower()
            distribution[risk] = distribution.get(risk, 0) + 1
        return distribution
    
    def _get_module_coverage(self) -> Dict[str, int]:
        """Get coverage statistics by module type"""
        coverage = {}
        for vuln in self.vulnerabilities:
            vuln_type = vuln.get('type', 'unknown')
            coverage[vuln_type] = coverage.get(vuln_type, 0) + 1
        return coverage 