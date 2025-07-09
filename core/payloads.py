import os
import json
import random
import string
import urllib.parse
import configparser
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path

from ai.ai_bridge import ask_mixtral

class PayloadMutator:
    def __init__(self, config=None):
        self.config = config or {
            'enable_unicode': True,
            'enable_rot13': True,
            'enable_html_entity': True,
            'enable_comment_injection': True,
            'enable_case_alternation': True,
            'enable_urlencode': True,
            'enable_whitespace': True,
            'enable_keyword_obfuscation': True,
            'enable_fuzz': True,
            'enable_ai_mutation': True,
        }

    def mutate(self, payload: str, context: str = '', waf_level: str = '', fuzz: bool = False) -> List[str]:
        variants = [payload]
        if self.config.get('enable_urlencode'):
            variants.append(urllib.parse.quote(payload))
        if self.config.get('enable_html_entity'):
            variants.append(self.html_entity(payload))
        if self.config.get('enable_unicode'):
            variants.append(self.unicode_injection(payload))
        if self.config.get('enable_comment_injection'):
            variants.append(self.comment_injection(payload))
        if self.config.get('enable_case_alternation'):
            variants.append(self.case_alternation(payload))
        if self.config.get('enable_rot13'):
            variants.append(self.rot13(payload))
        if self.config.get('enable_whitespace'):
            variants.append(self.whitespace_injection(payload))
        if self.config.get('enable_keyword_obfuscation'):
            variants.append(self.keyword_obfuscation(payload))
        if self.config.get('enable_fuzz') or fuzz:
            variants.append(self.fuzz(payload))
        
        # AI-powered mutation
        if self.config.get('enable_ai_mutation'):
            ai_variants = self.mutate_with_ai(payload, context, waf_level)
            variants.extend(ai_variants)
        
        # Remove duplicates
        return list(dict.fromkeys(variants))

    def mutate_with_ai(self, payload: str, context: str = '', waf_level: str = '') -> List[str]:
        """
        Use AI to generate payload mutations
        """
        try:
            prompt = f"""
You are an expert offensive security specialist. Generate 3-5 mutated versions of this payload to bypass WAFs and filters:

ORIGINAL PAYLOAD: {payload}
CONTEXT: {context or 'general'}
WAF LEVEL: {waf_level or 'unknown'}

Generate mutations using:
- Encoding techniques (URL, HTML entities, Unicode)
- Case manipulation
- Comment injection
- Whitespace manipulation
- Alternative syntax
- WAF bypass techniques

Return only the mutated payloads, one per line, without explanations.
"""
            
            ai_response = ask_mixtral(prompt)
            
            # Parse AI response into individual payloads
            ai_payloads = []
            for line in ai_response.strip().split('\n'):
                line = line.strip()
                if line and not line.startswith('#') and not line.startswith('//'):
                    ai_payloads.append(line)
            
            return ai_payloads[:5]  # Limit to 5 AI-generated payloads
            
        except Exception as e:
            logging.warning(f"AI payload mutation failed: {e}")
            return []

    def html_entity(self, payload):
        return payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')

    def unicode_injection(self, payload):
        # Replace first alpha char with unicode escape
        for i, c in enumerate(payload):
            if c.isalpha():
                return payload[:i] + '\\u{:04x}'.format(ord(c)) + payload[i+1:]
        return payload

    def comment_injection(self, payload):
        return payload.replace('=', '=/*bypass*/')

    def case_alternation(self, payload):
        return ''.join([c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload)])

    def rot13(self, payload):
        return payload.translate(str.maketrans(
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
            'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'))

    def whitespace_injection(self, payload):
        return payload.replace('=', ' = ').replace('onerror', 'onerror ').replace('alert', ' alert ')

    def keyword_obfuscation(self, payload):
        return payload.replace('script', 'scr<script>ipt')

    def fuzz(self, payload):
        # Insert a random string at a random position
        pos = random.randint(0, len(payload))
        rand_str = ''.join(random.choices(string.ascii_letters + string.digits, k=3))
        return payload[:pos] + rand_str + payload[pos:]

    def context_adapt(self, payload: str, context: str) -> str:
        # Adapt payload for context (html, json, url, header, js)
        if context == 'json':
            return payload.replace('"', '\\"')
        elif context == 'url':
            return urllib.parse.quote(payload)
        elif context == 'header':
            return payload.replace('\n', '').replace('\r', '')
        elif context == 'js':
            return payload.replace('"', '\\"').replace("'", "\'")
        return payload

class PayloadEngine:
    def __init__(self, payloads_dir: str = "payloads"):
        self.payloads_dir = Path(payloads_dir)
        self.payloads = {}
        self.mutation_rules = {
            'case_swap': self._case_swap,
            'url_encode': self._url_encode,
            'double_encode': self._double_encode,
            'hex_encode': self._hex_encode,
            'unicode_encode': self._unicode_encode,
            'add_random': self._add_random,
            'null_byte': self._null_byte
        }
        self.mutator = PayloadMutator()
        self.load_payloads()
    
    def load_payloads(self):
        """Load all payload files from payloads directory"""
        if not self.payloads_dir.exists():
            logging.warning(f"Payloads directory {self.payloads_dir} not found")
            return
        
        for payload_file in self.payloads_dir.glob("*.json"):
            try:
                with open(payload_file, 'r', encoding='utf-8') as f:
                    payload_data = json.load(f)
                
                payload_type = payload_file.stem
                self.payloads[payload_type] = payload_data
                
                # Handle different JSON structures
                if 'payloads' in payload_data:
                    payload_count = len(payload_data.get('payloads', []))
                elif payload_type in payload_data:
                    payload_count = len(payload_data.get(payload_type, []))
                else:
                    payload_count = len(payload_data)
                
                logging.info(f"Loaded {payload_count} payloads from {payload_type}")
                
            except Exception as e:
                logging.error(f"Failed to load payloads from {payload_file}: {e}")
    
    def get_payloads(self, payload_type: str) -> List[str]:
        """Get payloads of specific type"""
        if payload_type not in self.payloads:
            return []
        
        payload_data = self.payloads[payload_type]
        
        # Handle different JSON structures
        if 'payloads' in payload_data:
            return payload_data.get('payloads', [])
        elif payload_type in payload_data:
            # Extract payload strings from our structure
            payload_list = payload_data.get(payload_type, [])
            return [p.get('payload', '') for p in payload_list if isinstance(p, dict) and 'payload' in p]
        else:
            return payload_data
    
    def get_payload_info(self, payload_type: str) -> Dict[str, Any]:
        """Get payload information including metadata"""
        if payload_type not in self.payloads:
            return {}
        
        return self.payloads[payload_type]
    
    def generate_payload_ai(self, payload_type: str, context: Optional[Dict[str, Any]] = None) -> List[str]:
        """
        Generate payloads using AI based on context
        """
        try:
            context_str = self._format_context(context) if context else "general"
            
            prompt = f"""
You are an expert offensive security specialist. Generate 5 high-quality payloads for {payload_type} vulnerability testing.

CONTEXT: {context_str}

Generate payloads that are:
- Effective for {payload_type} testing
- Context-appropriate
- WAF-bypass capable
- Real-world applicable

Return only the payloads, one per line, without explanations or numbering.
"""
            
            ai_response = ask_mixtral(prompt)
            
            # Parse AI response
            ai_payloads = []
            for line in ai_response.strip().split('\n'):
                line = line.strip()
                if line and not line.startswith('#') and not line.startswith('//'):
                    ai_payloads.append(line)
            
            return ai_payloads[:5]  # Limit to 5 AI-generated payloads
            
        except Exception as e:
            logging.warning(f"AI payload generation failed: {e}")
            return []
    
    def _format_context(self, context: Optional[Dict[str, Any]]) -> str:
        """Format context for AI prompt"""
        if not context:
            return "general"
        
        context_parts = []
        if 'parameter' in context:
            context_parts.append(f"parameter: {context['parameter']}")
        if 'reflection_context' in context:
            context_parts.append(f"reflection: {context['reflection_context']}")
        if 'waf_detected' in context:
            context_parts.append(f"waf: {context['waf_detected']}")
        if 'tech_stack' in context:
            context_parts.append(f"tech: {context['tech_stack']}")
        
        return ", ".join(context_parts) if context_parts else "general"
    
    def suggest_payloads_ai(self, finding: Dict[str, Any]) -> List[str]:
        """
        Suggest payloads based on a vulnerability finding
        """
        try:
            vuln_type = finding.get('type', 'unknown')
            parameter = finding.get('parameter', 'unknown')
            evidence = finding.get('evidence', '')
            
            prompt = f"""
Based on this vulnerability finding, suggest 3-5 follow-up payloads:

VULNERABILITY: {vuln_type}
PARAMETER: {parameter}
EVIDENCE: {evidence}

Suggest payloads that would:
1. Confirm the vulnerability
2. Exploit it further
3. Bypass any filters
4. Chain with other attacks

Return only the payloads, one per line.
"""
            
            ai_response = ask_mixtral(prompt)
            
            # Parse AI response
            suggested_payloads = []
            for line in ai_response.strip().split('\n'):
                line = line.strip()
                if line and not line.startswith('#') and not line.startswith('//'):
                    suggested_payloads.append(line)
            
            return suggested_payloads[:5]
            
        except Exception as e:
            logging.warning(f"AI payload suggestion failed: {e}")
            return []
    
    def mutate_payload(self, payload: str, mutation_type: str = "") -> str:
        """Apply mutation to payload"""
        if not mutation_type:
            mutation_type = random.choice(list(self.mutation_rules.keys()))
        
        if mutation_type in self.mutation_rules:
            return self.mutation_rules[mutation_type](payload)
        
        return payload
    
    def mutate_payloads(self, payloads: List[str], mutation_types: Optional[List[str]] = None) -> List[str]:
        """Apply mutations to multiple payloads"""
        if mutation_types is None:
            mutation_types = list(self.mutation_rules.keys())
        
        mutated_payloads = []
        for payload in payloads:
            for mutation_type in mutation_types:
                mutated = self.mutate_payload(payload, mutation_type)
                mutated_payloads.append(mutated)
        
        return mutated_payloads
    
    def generate_payloads(self, payload_type: str, count: int = 10, 
                         mutate: bool = True, mutation_types: Optional[List[str]] = None,
                         use_ai: bool = False, context: Optional[Dict[str, Any]] = None) -> List[str]:
        """Generate payloads of specific type with optional mutations and AI enhancement"""
        base_payloads = self.get_payloads(payload_type)
        
        # Add AI-generated payloads if requested
        if use_ai:
            ai_payloads = self.generate_payload_ai(payload_type, context)
            base_payloads.extend(ai_payloads)
        
        if not base_payloads:
            return []
        
        # Select random payloads up to count
        selected_payloads = random.sample(base_payloads, min(count, len(base_payloads)))
        
        if mutate:
            return self.mutate_payloads(selected_payloads, mutation_types)
        
        return selected_payloads
    
    def get_all_payload_types(self) -> List[str]:
        """Get list of all available payload types"""
        return list(self.payloads.keys())
    
    def add_custom_payload(self, payload_type: str, payload: str, metadata: Optional[Dict[str, Any]] = None):
        """Add custom payload"""
        if payload_type not in self.payloads:
            self.payloads[payload_type] = {
                'payloads': [],
                'metadata': metadata or {}
            }
        
        self.payloads[payload_type]['payloads'].append(payload)
        logging.info(f"Added custom payload to {payload_type}")
    
    def save_payloads(self, payload_type: str):
        """Save payloads back to file"""
        if payload_type not in self.payloads:
            return
        
        payload_file = self.payloads_dir / f"{payload_type}.json"
        try:
            with open(payload_file, 'w', encoding='utf-8') as f:
                json.dump(self.payloads[payload_type], f, indent=2)
            logging.info(f"Saved payloads to {payload_file}")
        except Exception as e:
            logging.error(f"Failed to save payloads: {e}")
    
    def _case_swap(self, payload: str) -> str:
        """Swap case of characters"""
        return payload.swapcase()
    
    def _url_encode(self, payload: str) -> str:
        """URL encode payload"""
        return urllib.parse.quote(payload)
    
    def _double_encode(self, payload: str) -> str:
        """Double URL encode payload"""
        return urllib.parse.quote(urllib.parse.quote(payload))
    
    def _hex_encode(self, payload: str) -> str:
        """Hex encode payload"""
        return ''.join([f'%{ord(c):02x}' for c in payload])
    
    def _unicode_encode(self, payload: str) -> str:
        """Unicode encode payload"""
        return ''.join([f'\\u{ord(c):04x}' for c in payload])
    
    def _add_random(self, payload: str) -> str:
        """Add random characters to payload"""
        pos = random.randint(0, len(payload))
        rand_str = ''.join(random.choices(string.ascii_letters, k=3))
        return payload[:pos] + rand_str + payload[pos:]
    
    def _null_byte(self, payload: str) -> str:
        """Add null byte to payload"""
        return payload + '\x00'
    
    def get_mutation_types(self) -> List[str]:
        """Get available mutation types"""
        return list(self.mutation_rules.keys())
    
    def create_contextual_payload(self, payload: str, context: Dict[str, Any]) -> str:
        """Create context-aware payload"""
        context_type = context.get('type', 'general')
        
        if context_type == 'html':
            return payload.replace('"', '&quot;').replace("'", '&#39;')
        elif context_type == 'javascript':
            return payload.replace('"', '\\"').replace("'", "\\'")
        elif context_type == 'url':
            return urllib.parse.quote(payload)
        elif context_type == 'json':
            return payload.replace('"', '\\"')
        elif context_type == 'sql':
            return payload.replace("'", "''")
        
        return payload
    
    def get_payload_statistics(self) -> Dict[str, Any]:
        """Get payload statistics"""
        stats = {
            'total_types': len(self.payloads),
            'payload_types': list(self.payloads.keys()),
            'total_payloads': 0
        }
        
        for payload_type, payload_data in self.payloads.items():
            if 'payloads' in payload_data:
                stats['total_payloads'] += len(payload_data['payloads'])
            elif payload_type in payload_data:
                stats['total_payloads'] += len(payload_data[payload_type])
        
        return stats 