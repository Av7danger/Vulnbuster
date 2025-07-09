#!/usr/bin/env python3
"""
VulnBuster - Red Team Offensive Exploitation Framework
Multi-surface vulnerability scanning with AI-assisted advisory
"""

import asyncio
import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime

# Import core components
from core.utils import setup_logging, print_banner, color_print
from core.scanner import Scanner
from modes.web.crawler import Crawler
from core.payloads import PayloadEngine
from core.wordlistgen import WordlistGenerator
from core.chain import ExploitChain
from ai.via_engine import VIAEngine

class VulnBuster:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.mode = config.get('mode', 'web')
        self.target = config.get('target')
        self.modules = config.get('modules', [])
        self.verbose = config.get('verbose', False)
        self.advisor_enabled = config.get('advisor', False)
        self.chain_enabled = config.get('chain', False)
        self.mutate_enabled = config.get('mutate', False)
        self.oob_enabled = config.get('oob', False)
        
        # Advanced features
        self.auto_exploit = config.get('auto_exploit')
        self.auto_poc = config.get('auto_poc', False)
        self.payload_learn = config.get('payload_learn', False)
        self.load_plugin = config.get('load_plugin')
        self.repl_mode = config.get('repl', False)
        
        # Initialize components
        self.payload_engine = PayloadEngine()
        self.wordlist_gen = WordlistGenerator()
        self.via_engine = VIAEngine() if self.advisor_enabled else None
        self.exploit_chain = ExploitChain() if self.chain_enabled else None
        
        # Advanced components
        self.auto_shell_uploader = None
        self.poc_builder = None
        self.payload_learning = None
        self.plugin_loader = None
        self.repl_interface = None
        
        # Mode-specific components
        self.mode_scanner = None
        self.mode_modules = []
        
    async def initialize_mode(self):
        """Initialize mode-specific scanner and modules"""
        mode_path = Path(f"modes/{self.mode}")
        
        if not mode_path.exists():
            raise ValueError(f"Mode '{self.mode}' not supported")
        
        # Import mode-specific scanner
        try:
            if self.mode == 'web':
                from modes.web.scanner import WebScanner
                self.mode_scanner = WebScanner(self.config)
            elif self.mode == 'android':
                from modes.android.scanner import AndroidScanner
                self.mode_scanner = AndroidScanner(self.config)
            # Other modes can be added as they are implemented
            else:
                color_print(f"Mode '{self.mode}' not yet implemented", 'warning')
                return
            
            color_print(f"Initialized {self.mode.upper()} mode scanner", 'info')
            
        except ImportError as e:
            color_print(f"Failed to load {self.mode} mode: {e}", 'error')
            raise
    
    async def load_modules(self):
        """Load specified vulnerability modules"""
        if not self.modules or 'all' in self.modules:
            # Load all modules for the mode
            modules_path = Path(f"modes/{self.mode}/modules")
            if modules_path.exists():
                for module_file in modules_path.glob("*.py"):
                    if module_file.name != "__init__.py":
                        module_name = module_file.stem
                        self.mode_modules.append(module_name)
        else:
            self.mode_modules = self.modules
        
        color_print(f"Loaded {len(self.mode_modules)} modules: {', '.join(self.mode_modules)}", 'info')
    
    async def start_oob_listeners(self):
        """Start out-of-band listeners if enabled"""
        if not self.oob_enabled:
            return
        
        try:
            from oob.dns_listener import DNSListener
            
            # Start DNS listener if domain provided
            if self.config.get('dns_domain'):
                dns_listener = DNSListener(domain=self.config['dns_domain'])
                await dns_listener.start()
            
            color_print("OOB listeners started", 'info')
            
        except Exception as e:
            color_print(f"Failed to start OOB listeners: {e}", 'warning')
    
    async def initialize_advanced_components(self):
        """Initialize advanced components based on configuration"""
        try:
            # Auto shell uploader
            if self.auto_exploit == 'upload':
                from post_exploitation.auto_shell_uploader import AutoShellUploader
                self.auto_shell_uploader = AutoShellUploader(self.config)
                color_print("Auto-shell uploader initialized", 'info')
            
            # PoC builder
            if self.auto_poc:
                from core.poc_builder import POCBuilder
                self.poc_builder = POCBuilder(self.config)
                color_print("PoC builder initialized", 'info')
            
            # Payload learning engine
            if self.payload_learn:
                from core.payload_learning import PayloadLearningEngine
                self.payload_learning = PayloadLearningEngine(self.config)
                color_print("Payload learning engine initialized", 'info')
            
            # Plugin loader
            if self.load_plugin or self.config.get('plugins_enabled', False):
                from core.plugin_loader import PluginLoader
                self.plugin_loader = PluginLoader(self.config)
                
                if self.load_plugin:
                    plugin_data = self.plugin_loader.load_plugin(self.load_plugin)
                    if plugin_data:
                        color_print(f"Plugin loaded: {self.load_plugin}", 'info')
                    else:
                        color_print(f"Failed to load plugin: {self.load_plugin}", 'warning')
                else:
                    # Load all available plugins
                    plugins = self.plugin_loader.scan_plugins()
                    for plugin in plugins:
                        self.plugin_loader.load_plugin(plugin)
                    color_print(f"Loaded {len(plugins)} plugins", 'info')
            
            # REPL interface
            if self.repl_mode:
                from core.repl_interface import REPLInterface
                self.repl_interface = REPLInterface(self.config, self.mode_scanner, None)
                color_print("REPL interface initialized", 'info')
                
        except Exception as e:
            color_print(f"Failed to initialize advanced components: {e}", 'warning')
    
    async def run_scan(self):
        """Execute the main scanning workflow"""
        try:
            # Handle REPL mode
            if self.repl_mode:
                await self.initialize_advanced_components()
                if self.repl_interface:
                    await self.repl_interface.start()
                return []
            
            # Initialize mode
            await self.initialize_mode()
            
            # Load modules
            await self.load_modules()
            
            # Initialize advanced components
            await self.initialize_advanced_components()
            
            # Start OOB listeners
            await self.start_oob_listeners()
            
            # Run mode-specific scan
            if self.mode_scanner and self.target:
                if self.mode == 'android':
                    # Android mode uses a different interface
                    # Create a mock args object with the Android-specific flags
                    class MockArgs:
                        def __init__(self, config):
                            self.scan_apis = config.get('scan_apis', False)
                            self.scan_keys = config.get('scan_keys', False)
                            self.list_components = config.get('list_components', False)
                            self.scan_manifest = config.get('scan_manifest', False)
                            self.build_wordlist = config.get('build_wordlist', False)
                            self.verbose = config.get('verbose', False)
                    
                    mock_args = MockArgs(self.config)
                    results = await self.mode_scanner.run(self.target, mock_args)
                else:
                    # Web mode and other modes
                    results = await self.mode_scanner.scan(
                        target=self.target,
                        modules=self.mode_modules,
                        payload_engine=self.payload_engine,
                        via_engine=self.via_engine,
                        exploit_chain=self.exploit_chain
                    )
                
                # Handle post-scan actions
                await self._handle_post_scan_actions(results)
                
                # Generate reports
                await self.generate_reports(results)
                
                return results
            else:
                if not self.target:
                    color_print("No target specified", 'error')
                else:
                    color_print("No scanner available for this mode", 'error')
                return []
                
        except Exception as e:
            color_print(f"Scan failed: {e}", 'error')
            if self.verbose:
                logging.exception("Scan error details:")
            return []
    
    async def _handle_post_scan_actions(self, results: List[Dict[str, Any]]):
        """Handle post-scan actions like auto-exploitation and PoC generation"""
        try:
            # Auto-exploitation
            if self.auto_exploit and results:
                await self._handle_auto_exploitation(results)
            
            # Auto PoC generation
            if self.auto_poc and results:
                await self._handle_auto_poc_generation(results)
            
            # Payload learning
            if self.payload_learning:
                await self._handle_payload_learning()
            
            # Plugin execution
            if self.plugin_loader and results:
                await self._handle_plugin_execution(results)
                
        except Exception as e:
            color_print(f"Post-scan actions failed: {e}", 'warning')
    
    async def _handle_auto_exploitation(self, results: List[Dict[str, Any]]):
        """Handle automatic exploitation based on findings"""
        try:
            if self.auto_exploit == 'upload':
                upload_findings = [r for r in results if r.get('type') == 'upload']
                for finding in upload_findings:
                    if self.auto_shell_uploader:
                        upload_results = await self.auto_shell_uploader.handle_upload_vulnerability(finding)
                        if upload_results:
                            color_print(f"Auto-shell upload completed for {finding.get('url')}", 'success')
            
            # Add other exploitation types as needed
            
        except Exception as e:
            color_print(f"Auto-exploitation failed: {e}", 'warning')
    
    async def _handle_auto_poc_generation(self, results: List[Dict[str, Any]]):
        """Handle automatic PoC generation"""
        try:
            if self.poc_builder:
                poc_results = await self.poc_builder.generate_batch_pocs(results)
                if poc_results:
                    color_print(f"Generated {len(poc_results)} PoCs", 'success')
                    
                    # Generate summary report
                    summary_file = await self.poc_builder.generate_summary_report(results)
                    if summary_file:
                        color_print(f"PoC summary: {summary_file}", 'info')
            
        except Exception as e:
            color_print(f"Auto PoC generation failed: {e}", 'warning')
    
    async def _handle_payload_learning(self):
        """Handle payload learning analysis"""
        try:
            if self.payload_learning:
                stats = self.payload_learning.get_statistics()
                color_print(f"Payload learning stats: {stats['total_payloads']} payloads tested", 'info')
                
                # Generate AI analysis
                analysis = await self.payload_learning.analyze_payload_performance()
                if analysis.get('ai_analysis'):
                    color_print("AI payload analysis completed", 'info')
                
                # End session
                self.payload_learning.end_session()
            
        except Exception as e:
            color_print(f"Payload learning failed: {e}", 'warning')
    
    async def _handle_plugin_execution(self, results: List[Dict[str, Any]]):
        """Handle plugin execution"""
        try:
            if self.plugin_loader:
                loaded_plugins = self.plugin_loader.get_loaded_plugins()
                for plugin in loaded_plugins:
                    plugin_result = await self.plugin_loader.execute_plugin(
                        plugin['name'], 
                        self.target or "unknown", 
                        self.config.get('headers', {})
                    )
                    if plugin_result:
                        color_print(f"Plugin {plugin['name']} executed successfully", 'info')
            
        except Exception as e:
            color_print(f"Plugin execution failed: {e}", 'warning')
    
    async def generate_reports(self, results: List[Dict[str, Any]]):
        """Generate reports using the selected template and client name"""
        from core.reporter import Reporter
        mode = self.mode if hasattr(self, 'mode') else 'web'
        reporter = Reporter(self.config.get('output', 'reports'), mode=mode)
        
        formats = self.config.get('format', ['all'])
        if 'all' in formats:
            formats = ['html', 'json', 'markdown']
        
        # Add findings to reporter
        for result in results:
            reporter.add_finding(result)
        
        # Set metadata
        reporter.set_metadata({
            'target_url': self.target,
            'mode': self.mode,
            'modules': self.mode_modules,
            'advisor_enabled': self.advisor_enabled,
            'chain_enabled': self.chain_enabled,
            'scan_date': datetime.now().isoformat()
        })
        
        # Generate reports
        try:
            report_files = await reporter.generate_reports(
                formats=formats,
                use_ai=self.config.get('ai_reports', False),
                template=self.config.get('report_template'),
                client_name=self.config.get('client_name')
            )
            
            for fmt, report_path in report_files.items():
                color_print(f"Generated {fmt.upper()} report: {report_path}", 'info')
                
        except Exception as e:
            color_print(f"Failed to generate reports: {e}", 'warning')

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="VulnBuster - Red Team Offensive Exploitation Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --mode web -u https://target.com --vulns xss,sqli --advisor --chain
  python main.py --mode android --apk app.apk --scan-apis --wordlist custom.txt
  python main.py --mode ai --url https://llm.example.com/api/chat --payloads ai_prompts.json
  python main.py --mode cloud --provider aws --scan iam,s3 --oob-listener
  python main.py --mode web -u https://target.com --ai-mode full --autopilot --auto-poc
        """
    )
    
    # Mode selection
    parser.add_argument('--mode', choices=['web', 'android', 'ios', 'windows', 'cloud', 'ai', 'iot', 'edge'],
                       default='web', help='Scanning mode (default: web)')
    
    # Target specification
    parser.add_argument('-u', '--url', help='Target URL (web/ai modes)')
    parser.add_argument('--apk', help='APK file path (android mode)')
    parser.add_argument('--ipa', help='IPA file path (ios mode)')
    parser.add_argument('--binary', help='Binary file path (windows mode)')
    parser.add_argument('--provider', choices=['aws', 'gcp', 'azure'], help='Cloud provider (cloud mode)')
    parser.add_argument('--firmware', help='Firmware file path (iot mode)')
    parser.add_argument('--device', help='Device IP/hostname (edge mode)')
    
    # Vulnerability modules
    parser.add_argument('--vulns', '--modules', help='Comma-separated list of vulnerability modules')
    parser.add_argument('--scan', help='Comma-separated list of scan types (cloud mode)')
    
    # AI and automation features
    parser.add_argument('--advisor', action='store_true', help='Enable AI vulnerability intelligence advisor')
    parser.add_argument('--advisor-mode', choices=['ai', 'local'], default='ai',
                       help='Advisor mode (default: ai)')
    parser.add_argument('--ai-mode', choices=['none', 'basic', 'full'], default='none',
                       help='AI integration level (default: none)')
    parser.add_argument('--autopilot', action='store_true', help='Enable autonomous exploitation engine')
    parser.add_argument('--auto-poc', action='store_true', help='Automatically generate PoCs for findings')
    parser.add_argument('--auto-exploit', choices=['upload', 'sqli', 'xss', 'cmdinj'], 
                       help='Enable automatic exploitation for specific vulnerability type')
    parser.add_argument('--auto-pilot', action='store_true', help='Enable Auto-Pilot AI mode (full automation)')
    
    # Advanced features
    parser.add_argument('--payload-learn', action='store_true', help='Enable payload learning engine')
    parser.add_argument('--load-plugin', type=str, help='Load specific plugin file')
    parser.add_argument('--repl', action='store_true', help='Start interactive REPL mode')
    
    # Exploit chaining and mutation
    parser.add_argument('--chain', action='store_true', help='Enable exploit chaining')
    parser.add_argument('--mutate', action='store_true', help='Enable payload mutation')
    parser.add_argument('--mutate-mode', choices=['static', 'ai'], default='static',
                       help='Mutation mode (default: static)')
    
    # Payloads and wordlists
    parser.add_argument('--payloads', help='Custom payload file path')
    parser.add_argument('--cewl', help='Generate wordlist from URL (CeWL-like)')
    parser.add_argument('--cewl-depth', type=int, default=3, help='CeWL crawl depth (default: 3)')
    parser.add_argument('--wordlist', help='Custom wordlist file path')
    
    # Out-of-band detection
    parser.add_argument('--oob-listener', action='store_true', help='Enable out-of-band listeners')
    parser.add_argument('--dns-domain', help='DNS domain for OOB detection')
    parser.add_argument('--webhook-port', type=int, default=8000, help='Webhook listener port (default: 8000)')
    
    # Output and reporting
    parser.add_argument('-o', '--output', default='reports', help='Output directory (default: reports)')
    parser.add_argument('--format', choices=['html', 'json', 'markdown', 'all'], default='all',
                       help='Report format (default: all)')
    parser.add_argument('--ai-reports', action='store_true', help='Enable AI-enhanced reports')
    parser.add_argument('--report-template', default='pentest', help='Jinja2 report template (default: pentest)')
    parser.add_argument('--client', default=None, help='Client name for report branding')
    
    # Network and authentication
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--proxy-auth', help='Proxy authentication (user:pass)')
    parser.add_argument('--headers', help='Additional headers (JSON format)')
    parser.add_argument('--cookies', help='Additional cookies (JSON format)')
    parser.add_argument('--user-agent', help='Custom User-Agent string')
    
    # Configuration and logging
    parser.add_argument('--config', default='config/config.json', help='Configuration file (default: config/config.json)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--interactive', action='store_true', help='Launch interactive REPL')
    
    # Android-specific arguments
    parser.add_argument('--scan-apis', action='store_true', help='Scan for API endpoints (android mode)')
    parser.add_argument('--scan-keys', action='store_true', help='Scan for API keys and secrets (android mode)')
    parser.add_argument('--list-components', action='store_true', help='List exported components (android mode)')
    parser.add_argument('--scan-manifest', action='store_true', help='Analyze AndroidManifest.xml (android mode)')
    parser.add_argument('--build-wordlist', action='store_true', help='Build wordlist from APK resources (android mode)')
    
    # Advanced offensive features
    parser.add_argument('--portscan', action='store_true', help='Enable port and service enumeration')
    parser.add_argument('--exploit-chain', action='store_true', help='Enable vulnerability chaining auto-exploiter')
    parser.add_argument('--oracle-mode', action='store_true', help='Enable AI payload oracle')
    parser.add_argument('--record', action='store_true', help='Record recon/exploit steps')
    parser.add_argument('--replay', help='Replay recorded steps on new target')
    parser.add_argument('--ai-tune', action='store_true', help='Enable AI prompt tuning')
    
    # Dynamic analysis features
    parser.add_argument('--android-dynamic', action='store_true', help='Enable dynamic Android analysis')
    parser.add_argument('--frida', action='store_true', help='Enable Frida hooks')
    parser.add_argument('--emulator', action='store_true', help='Use Android emulator')
    
    # WAF bypass features
    parser.add_argument('--waf-bypass', action='store_true', help='Enable advanced WAF bypass')
    parser.add_argument('--bypass-technique', choices=['casing', 'encoding', 'splitting', 'comments', 'auto'], 
                       default='auto', help='WAF bypass technique')
    
    # API integration features
    parser.add_argument('--shodan-key', help='Shodan API key for host enrichment')
    parser.add_argument('--censys-creds', help='Censys credentials (api_id:api_secret)')
    parser.add_argument('--dnsdb-key', help='DNSDB API key for DNS history')
    parser.add_argument('--api-enrich', action='store_true', help='Enable API enrichment')
    
    # AI memory features
    parser.add_argument('--ai-memory', action='store_true', help='Enable AI memory and context recall')
    parser.add_argument('--memory-file', default='memory/logs.json', help='AI memory file path')
    
    # Post-exploitation features
    parser.add_argument('--jwt-analyze', help='Analyze JWT token for vulnerabilities')
    parser.add_argument('--upload-brute', action='store_true', help='Bruteforce uploaded file paths')
    parser.add_argument('--lfi-exploit', action='store_true', help='Auto-exploit LFI vulnerabilities')
    parser.add_argument('--shell-verify', action='store_true', help='Verify shell execution')
    
    # Recon features
    parser.add_argument('--subdomain-brute', action='store_true', help='Bruteforce subdomains')
    parser.add_argument('--fingerprint', action='store_true', help='Fingerprint target (screenshot, cert, etc.)')
    parser.add_argument('--mole-integration', action='store_true', help='Integrate with Mole for subdomain enum')
    
    # UX and productivity features
    parser.add_argument('--flow-render', action='store_true', help='Render visual scan flow')
    parser.add_argument('--payload-diff', action='store_true', help='Show payload diff viewer')
    parser.add_argument('--vuln-replay', action='store_true', help='Replay vulns on new targets')
    parser.add_argument('--profile', choices=['recon', 'exploit', 'bounty-hardcore', 'ctf'], 
                       help='Use predefined scan profile')
    parser.add_argument('--offline', action='store_true', help='Offline mode (local-only)')
    parser.add_argument('--ci-cd', action='store_true', help='CI/CD mode (clean JSON output)')
    
    return parser.parse_args()

def load_config(config_path: str) -> Dict[str, Any]:
    """Load configuration from file"""
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        logging.warning(f"Failed to load config from {config_path}: {e}")
        return {}

def build_config_from_args(args) -> Dict[str, Any]:
    """Build configuration from command line arguments"""
    config = {
        'mode': args.mode,
        'verbose': args.verbose,
        'debug': args.debug,
        'output': args.output,
        'format': args.format.split(',') if args.format else ['all'],
        'modules': args.vulns.split(',') if args.vulns else [],
        'advisor': args.advisor or args.ai_mode != 'none',
        'advisor_mode': args.advisor_mode,
        'ai_mode': args.ai_mode,
        'autopilot': args.autopilot,
        'auto_poc': args.auto_poc,
        'auto_exploit': args.auto_exploit,
        'chain': args.chain,
        'mutate': args.mutate,
        'mutate_mode': args.mutate_mode,
        'oob': args.oob_listener,
        'dns_domain': args.dns_domain,
        'webhook_port': args.webhook_port,
        'ai_reports': args.ai_reports,
        'interactive': args.interactive,
        'report_template': args.report_template,
        'client_name': args.client
    }
    
    # Mode-specific targets
    if args.mode == 'web' and args.url:
        config['target'] = args.url
    elif args.mode == 'android' and args.apk:
        config['target'] = args.apk
    elif args.mode == 'ios' and args.ipa:
        config['target'] = args.ipa
    elif args.mode == 'windows' and args.binary:
        config['target'] = args.binary
    elif args.mode == 'cloud' and args.provider:
        config['target'] = args.provider
    elif args.mode == 'ai' and args.url:
        config['target'] = args.url
    elif args.mode == 'iot' and args.firmware:
        config['target'] = args.firmware
    elif args.mode == 'edge' and args.device:
        config['target'] = args.device
    
    # Network configuration
    if args.proxy:
        config['proxy'] = args.proxy
    if args.proxy_auth:
        config['proxy_auth'] = args.proxy_auth
    if args.headers:
        try:
            config['headers'] = json.loads(args.headers)
        except:
            config['headers'] = {}
    if args.cookies:
        try:
            config['cookies'] = json.loads(args.cookies)
        except:
            config['cookies'] = {}
    if args.user_agent:
        config['user_agent'] = args.user_agent
    
    # Wordlist generation
    if args.cewl:
        config['cewl'] = args.cewl
        config['cewl_depth'] = args.cewl_depth
    if args.wordlist:
        config['wordlist'] = args.wordlist
    
    # Payloads
    if args.payloads:
        config['payloads'] = args.payloads
    
    # Cloud-specific
    if args.mode == 'cloud' and args.scan:
        config['scan_types'] = args.scan.split(',')
    
    # Android-specific
    if args.mode == 'android':
        config['scan_apis'] = args.scan_apis
        config['scan_keys'] = args.scan_keys
        config['list_components'] = args.list_components
        config['scan_manifest'] = args.scan_manifest
        config['build_wordlist'] = args.build_wordlist
    
    config['auto_pilot'] = args.auto_pilot
    
    # Advanced offensive features
    config['portscan'] = args.portscan
    config['exploit_chain'] = args.exploit_chain
    config['oracle_mode'] = args.oracle_mode
    config['record'] = args.record
    config['replay'] = args.replay
    config['ai_tune'] = args.ai_tune
    
    # Dynamic analysis features
    config['android_dynamic'] = args.android_dynamic
    config['frida'] = args.frida
    config['emulator'] = args.emulator
    
    # WAF bypass features
    config['waf_bypass'] = args.waf_bypass
    config['bypass_technique'] = args.bypass_technique
    
    # API integration features
    config['shodan_key'] = args.shodan_key
    config['censys_creds'] = args.censys_creds
    config['dnsdb_key'] = args.dnsdb_key
    config['api_enrich'] = args.api_enrich
    
    # AI memory features
    config['ai_memory'] = args.ai_memory
    config['memory_file'] = args.memory_file
    
    # Post-exploitation features
    config['jwt_analyze'] = args.jwt_analyze
    config['upload_brute'] = args.upload_brute
    config['lfi_exploit'] = args.lfi_exploit
    config['shell_verify'] = args.shell_verify
    
    # Recon features
    config['subdomain_brute'] = args.subdomain_brute
    config['fingerprint'] = args.fingerprint
    config['mole_integration'] = args.mole_integration
    
    # UX and productivity features
    config['flow_render'] = args.flow_render
    config['payload_diff'] = args.payload_diff
    config['vuln_replay'] = args.vuln_replay
    config['profile'] = args.profile
    config['offline'] = args.offline
    config['ci_cd'] = args.ci_cd
    
    return config

async def main():
    """Main entry point"""
    # Parse arguments
    args = parse_arguments()
    
    # Setup logging
    setup_logging(args.verbose)
    
    # Print banner
    print_banner()
    
    # Load configuration
    base_config = load_config(args.config)
    config = build_config_from_args(args)
    config.update(base_config)
    
    # Validate configuration
    if not config.get('target') and not args.repl and not args.interactive:
        color_print("Error: No target specified for the selected mode", 'error')
        sys.exit(1)
    
    # Handle special modes
    if args.cewl:
        # Generate wordlist from URL
        from core.wordlistgen import WordlistGenerator
        wg = WordlistGenerator()
        wordlist = await wg.generate_wordlist_from_url(args.cewl, depth=args.cewl_depth)
        wg.save_wordlist(wordlist, f"cewl_{args.cewl.replace('://', '_').replace('/', '_')}.txt")
        color_print(f"Generated wordlist with {len(wordlist)} words", 'info')
        return
    
    if args.interactive:
        # Launch interactive mode
        from core.repl_interface import REPLInterface
        repl = REPLInterface(config)
        await repl.start()
        return
    
    if config.get('auto_pilot'):
        from core import ai as mixtral_ai
        color_print('[Auto-Pilot] Starting AI-driven scan, exploit, and report loop', 'info')
        vuln_buster = VulnBuster(config)
        results = await vuln_buster.run_scan()
        # AI summarize
        summary = await mixtral_ai.summarize_scan(results)
        color_print(f'[Auto-Pilot] AI Summary: {summary}', 'info')
        # AI decide next action
        decision = await mixtral_ai.chat_repl([
            {'role': 'user', 'content': 'Given these scan results, what should VulnBuster do next?'}
        ], {'scan_results': results})
        color_print(f'[Auto-Pilot] AI Decision: {decision}', 'info')
        # (Stub) Exploit and report steps would be called here
        await vuln_buster.generate_reports(results)
        color_print('[Auto-Pilot] Report generated', 'success')
        return
    
    # Create and run VulnBuster
    vulnbuster = VulnBuster(config)
    results = await vulnbuster.run_scan()
    
    # Print summary
    if results:
        color_print(f"Scan completed! Found {len(results)} vulnerabilities", 'success')
        for result in results:
            color_print(f"[{result.get('risk', 'unknown').upper()}] {result.get('type', 'unknown')} - {result.get('url', 'unknown')}", 
                       result.get('risk', 'info'))
    else:
        color_print("Scan completed. No vulnerabilities found.", 'info')

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        color_print("\nScan interrupted by user", 'warning')
        sys.exit(1)
    except Exception as e:
        color_print(f"Fatal error: {e}", 'error')
        sys.exit(1) 