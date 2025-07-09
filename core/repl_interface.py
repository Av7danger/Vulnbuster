"""
Chat-Style AI REPL Interface
Interactive command-line interface for VulnBuster
"""

import asyncio
import logging
import json
import readline
from typing import Dict, Any, List, Optional
from pathlib import Path
from datetime import datetime
import shlex

from core import ai as mixtral_ai

class REPLInterface:
    def __init__(self, config: Dict[str, Any], scanner=None, session=None):
        self.config = config
        self.scanner = scanner
        self.session = session
        self.running = False
        self.command_history = []
        self.scan_state = {
            'target': None,
            'findings': [],
            'modules_loaded': [],
            'scan_progress': 0.0,
            'start_time': None
        }
        
        # Available commands
        self.commands = {
            'help': self._cmd_help,
            'scan': self._cmd_scan,
            'status': self._cmd_status,
            'findings': self._cmd_findings,
            'exploit': self._cmd_exploit,
            'poc': self._cmd_poc,
            'clear': self._cmd_clear,
            'quit': self._cmd_quit,
            'exit': self._cmd_quit,
            'history': self._cmd_history,
            'config': self._cmd_config,
            'plugins': self._cmd_plugins,
            'ai': self._cmd_ai
        }
        
        # AI conversation context
        self.conversation_context = []
        
    async def start(self):
        """Start the REPL interface"""
        self.running = True
        self.scan_state['start_time'] = datetime.now().isoformat()
        
        print("\n" + "="*60)
        print("🔥 VulnBuster AI REPL Interface")
        print("="*60)
        print("Type 'help' for available commands")
        print("Type 'quit' to exit")
        print("Ask me anything about security testing!")
        print("="*60 + "\n")
        
        # Show initial status
        await self._show_status()
        
        while self.running:
            try:
                # Get user input
                user_input = input("\n🤖 VulnBuster> ").strip()
                
                if not user_input:
                    continue
                
                # Add to history
                self.command_history.append(user_input)
                
                # Process input
                await self._process_input(user_input)
                
            except KeyboardInterrupt:
                print("\n\n⚠️  Use 'quit' to exit properly")
            except EOFError:
                break
            except Exception as e:
                logging.error(f"REPL error: {e}")
                print(f"❌ Error: {e}")
        
        print("\n👋 Goodbye! Happy hacking!")
    
    async def _process_input(self, user_input: str):
        """Process user input"""
        try:
            # Check if it's a direct command
            if user_input.startswith('/'):
                await self._execute_command(user_input[1:])
                return
            
            # Check if it's a natural language query
            if any(keyword in user_input.lower() for keyword in ['what', 'how', 'why', 'when', 'where', 'explain', 'help', 'suggest']):
                await self._handle_natural_language(user_input)
                return
            
            # Check if it looks like a command
            if user_input.split()[0].lower() in self.commands:
                await self._execute_command(user_input)
                return
            
            # Default to AI query
            await self._handle_natural_language(user_input)
            
        except Exception as e:
            logging.error(f"Failed to process input: {e}")
            print(f"❌ Error processing input: {e}")
    
    async def _execute_command(self, command: str):
        """Execute a command"""
        try:
            parts = shlex.split(command)
            cmd_name = parts[0].lower()
            args = parts[1:] if len(parts) > 1 else []
            
            if cmd_name in self.commands:
                await self.commands[cmd_name](args)
            else:
                print(f"❌ Unknown command: {cmd_name}")
                print("Type 'help' for available commands")
                
        except Exception as e:
            logging.error(f"Command execution failed: {e}")
            print(f"❌ Command failed: {e}")
    
    async def _handle_natural_language(self, query: str):
        """Handle natural language queries using AI"""
        try:
            print("🤔 Thinking...")
            # Build context-aware prompt
            context = self._build_context()
            # Use conversation history for context
            history = [
                {'role': 'user', 'content': c['user']} if 'user' in c else {'role': 'user', 'content': c.get('query', '')}
                for c in self.conversation_context
            ]
            # Add current query
            history.append({'role': 'user', 'content': query})
            # Call Mixtral chat_repl
            response = await mixtral_ai.chat_repl(history, {'context': context})
            # Add to conversation context
            self.conversation_context.append({
                'user': query,
                'assistant': response,
                'timestamp': datetime.now().isoformat()
            })
            # Keep context manageable
            if len(self.conversation_context) > 10:
                self.conversation_context = self.conversation_context[-10:]
            print(f"\n🤖 {response}")
        except Exception as e:
            logging.error(f"AI query failed: {e}")
            print(f"❌ AI query failed: {e}")
    
    def _build_context(self) -> str:
        """Build context for AI queries"""
        context_parts = []
        
        if self.scan_state['target']:
            context_parts.append(f"Target: {self.scan_state['target']}")
        
        if self.scan_state['findings']:
            context_parts.append(f"Findings: {len(self.scan_state['findings'])} vulnerabilities detected")
            for finding in self.scan_state['findings'][-3:]:  # Last 3 findings
                context_parts.append(f"- {finding.get('type', 'unknown')}: {finding.get('url', 'unknown')}")
        
        if self.scan_state['modules_loaded']:
            context_parts.append(f"Loaded modules: {', '.join(self.scan_state['modules_loaded'])}")
        
        if self.scan_state['scan_progress'] > 0:
            context_parts.append(f"Scan progress: {self.scan_state['scan_progress']:.1f}%")
        
        return "\n".join(context_parts) if context_parts else "No active scan"
    
    async def _cmd_help(self, args: List[str]):
        """Show help information"""
        print("\n📚 VulnBuster REPL Commands:")
        print("="*40)
        print("/help                    - Show this help")
        print("/scan <target>           - Start a new scan")
        print("/status                  - Show current scan status")
        print("/findings                - Show detected vulnerabilities")
        print("/exploit <vuln_type>     - Run exploitation modules")
        print("/poc <vuln_type>         - Generate PoC for findings")
        print("/plugins                 - List loaded plugins")
        print("/config                  - Show current configuration")
        print("/history                 - Show command history")
        print("/clear                   - Clear screen")
        print("/quit                    - Exit REPL")
        print("\n💡 Natural Language Queries:")
        print("You can also ask questions in natural language:")
        print("- 'What should I do after finding XSS?'")
        print("- 'How do I exploit SQL injection?'")
        print("- 'Generate a payload for file upload'")
        print("- 'Explain IDOR vulnerability'")
    
    async def _cmd_scan(self, args: List[str]):
        """Start a new scan"""
        if not args:
            print("❌ Usage: /scan <target_url>")
            return
        
        target = args[0]
        print(f"🔍 Starting scan of {target}...")
        
        try:
            # Update scan state
            self.scan_state['target'] = target
            self.scan_state['findings'] = []
            self.scan_state['scan_progress'] = 0.0
            
            # Start scan (if scanner is available)
            if self.scanner:
                # This would integrate with the actual scanner
                print("⚠️  Scanner integration not fully implemented in REPL")
            else:
                print("⚠️  Scanner not available")
            
            print(f"✅ Scan initiated for {target}")
            
        except Exception as e:
            logging.error(f"Scan failed: {e}")
            print(f"❌ Scan failed: {e}")
    
    async def _cmd_status(self, args: List[str]):
        """Show current status"""
        await self._show_status()
    
    async def _cmd_findings(self, args: List[str]):
        """Show detected vulnerabilities"""
        if not self.scan_state['findings']:
            print("📭 No findings yet. Run a scan first!")
            return
        
        print(f"\n🔍 Found {len(self.scan_state['findings'])} vulnerabilities:")
        print("="*50)
        
        for i, finding in enumerate(self.scan_state['findings'], 1):
            print(f"{i}. {finding.get('type', 'unknown').upper()}")
            print(f"   URL: {finding.get('url', 'unknown')}")
            print(f"   Parameter: {finding.get('parameter', 'unknown')}")
            print(f"   Severity: {finding.get('severity', 'unknown')}")
            print(f"   Evidence: {finding.get('evidence', 'No evidence')[:100]}...")
            print()
    
    async def _cmd_exploit(self, args: List[str]):
        """Run exploitation modules"""
        if not args:
            print("❌ Usage: /exploit <vuln_type>")
            return
        
        vuln_type = args[0].lower()
        print(f"💥 Running exploitation for {vuln_type}...")
        
        # This would integrate with exploitation modules
        print(f"⚠️  Exploitation for {vuln_type} not fully implemented in REPL")
    
    async def _cmd_poc(self, args: List[str]):
        """Generate PoC for findings"""
        if not args:
            print("❌ Usage: /poc <vuln_type>")
            return
        
        vuln_type = args[0].lower()
        print(f"📝 Generating PoC for {vuln_type}...")
        
        # This would integrate with PoC builder
        print(f"⚠️  PoC generation for {vuln_type} not fully implemented in REPL")
    
    async def _cmd_plugins(self, args: List[str]):
        """List loaded plugins"""
        print("\n🔌 Loaded Plugins:")
        print("="*30)
        
        # This would show actual loaded plugins
        print("⚠️  Plugin listing not fully implemented in REPL")
    
    async def _cmd_config(self, args: List[str]):
        """Show current configuration"""
        print("\n⚙️  Current Configuration:")
        print("="*30)
        
        for key, value in self.config.items():
            if isinstance(value, dict):
                print(f"{key}:")
                for k, v in value.items():
                    print(f"  {k}: {v}")
            else:
                print(f"{key}: {value}")
    
    async def _cmd_history(self, args: List[str]):
        """Show command history"""
        print("\n📜 Command History:")
        print("="*30)
        
        for i, cmd in enumerate(self.command_history[-10:], 1):
            print(f"{i}. {cmd}")
    
    async def _cmd_clear(self, args: List[str]):
        """Clear screen"""
        print("\n" * 50)
    
    async def _cmd_quit(self, args: List[str]):
        """Exit REPL"""
        print("\n👋 Exiting VulnBuster REPL...")
        self.running = False
    
    async def _cmd_ai(self, args: List[str]):
        """AI-powered commands: explain rule, summary, poc, exploit_chain"""
        try:
            if not args:
                print("Usage: /ai [explain|summary|poc|exploit_chain] ...")
                return
            subcmd = args[0].lower()
            if subcmd == 'explain' and len(args) > 2 and args[1] == 'rule':
                rule = ' '.join(args[2:])
                explanation = await mixtral_ai.explain_rule(rule)
                print(f"[AI] Rule explanation: {explanation}")
            elif subcmd == 'summary':
                summary = await mixtral_ai.summarize_scan({'findings': self.scan_state.get('findings', [])})
                print(f"[AI] Scan summary: {summary}")
            elif subcmd == 'poc' and len(args) > 1:
                finding_type = args[1]
                finding = next((f for f in self.scan_state.get('findings', []) if f.get('type') == finding_type), None)
                if finding:
                    poc = await mixtral_ai.build_poc(finding)
                    print(f"[AI] PoC: {poc}")
                else:
                    print(f"No finding of type '{finding_type}' found.")
            elif subcmd == 'exploit_chain':
                findings = self.scan_state.get('findings', [])
                chain = await mixtral_ai.generate_exploit_chain(findings)
                print(f"[AI] Exploit chain: {chain}")
            else:
                print("Unknown /ai command or missing arguments.")
        except Exception as e:
            print(f"❌ AI command failed: {e}")
    
    async def _show_status(self):
        """Show current status"""
        print("\n📊 Current Status:")
        print("="*30)
        
        if self.scan_state['target']:
            print(f"🎯 Target: {self.scan_state['target']}")
            print(f"📈 Progress: {self.scan_state['scan_progress']:.1f}%")
            print(f"🔍 Findings: {len(self.scan_state['findings'])}")
            
            if self.scan_state['start_time']:
                start_time = datetime.fromisoformat(self.scan_state['start_time'])
                duration = datetime.now() - start_time
                print(f"⏱️  Duration: {duration}")
        else:
            print("🎯 No active target")
            print("💡 Use /scan <target> to start scanning")
        
        if self.scan_state['modules_loaded']:
            print(f"🔌 Modules: {', '.join(self.scan_state['modules_loaded'])}")
    
    def update_scan_state(self, **kwargs):
        """Update scan state from external sources"""
        self.scan_state.update(kwargs)
    
    def get_conversation_history(self) -> List[Dict[str, Any]]:
        """Get conversation history"""
        return self.conversation_context.copy()
    
    def clear_conversation_history(self):
        """Clear conversation history"""
        self.conversation_context.clear() 