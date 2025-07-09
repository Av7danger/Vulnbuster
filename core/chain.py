"""
Exploit Chain Engine - Chain multiple vulnerabilities for advanced exploitation
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime

class ExploitChain:
    def __init__(self):
        self.chains = []
        self.vulnerabilities = []
        self.chain_templates = self._load_chain_templates()
        
    def _load_chain_templates(self) -> Dict[str, List[str]]:
        """Load predefined exploit chain templates"""
        return {
            'web_to_shell': [
                'idor', 'file_upload', 'command_injection'
            ],
            'xss_to_session': [
                'xss', 'csrf', 'session_management'
            ],
            'sqli_to_rce': [
                'sqli', 'file_read', 'command_injection'
            ],
            'upload_to_shell': [
                'file_upload', 'lfi', 'command_injection'
            ],
            'idor_to_admin': [
                'idor', 'privilege_escalation', 'admin_access'
            ],
            'ssrf_to_internal': [
                'ssrf', 'internal_access', 'data_exfiltration'
            ]
        }
    
    def add_vulnerability(self, vuln: Dict[str, Any]):
        """Add a vulnerability to the chain analysis"""
        self.vulnerabilities.append(vuln)
        logging.info(f"Added vulnerability to chain: {vuln.get('type', 'unknown')}")
    
    def find_chains(self) -> List[Dict[str, Any]]:
        """Find potential exploit chains from current vulnerabilities"""
        chains = []
        
        # Get vulnerability types
        vuln_types = [v.get('type', '').lower() for v in self.vulnerabilities]
        
        # Check against templates
        for chain_name, template in self.chain_templates.items():
            if self._can_build_chain(template, vuln_types):
                chain = self._build_chain(chain_name, template)
                chains.append(chain)
        
        # Find custom chains
        custom_chains = self._find_custom_chains()
        chains.extend(custom_chains)
        
        self.chains = chains
        return chains
    
    def _can_build_chain(self, template: List[str], vuln_types: List[str]) -> bool:
        """Check if we can build a chain from the template"""
        required_vulns = set(template)
        available_vulns = set(vuln_types)
        
        # Check if we have at least 2 required vulnerabilities
        return len(required_vulns.intersection(available_vulns)) >= 2
    
    def _build_chain(self, chain_name: str, template: List[str]) -> Dict[str, Any]:
        """Build an exploit chain from template"""
        chain_vulns = []
        vuln_types = [v.get('type', '').lower() for v in self.vulnerabilities]
        
        for step in template:
            # Find matching vulnerability
            for vuln in self.vulnerabilities:
                if vuln.get('type', '').lower() == step:
                    chain_vulns.append({
                        'step': step,
                        'vulnerability': vuln,
                        'url': vuln.get('url', ''),
                        'parameter': vuln.get('parameter', ''),
                        'payload': vuln.get('payload', '')
                    })
                    break
        
        return {
            'name': chain_name,
            'steps': chain_vulns,
            'risk_level': self._assess_chain_risk(chain_vulns),
            'exploitability': self._assess_exploitability(chain_vulns),
            'impact': self._assess_impact(chain_vulns),
            'prerequisites': self._get_prerequisites(chain_vulns),
            'execution_path': self._generate_execution_path(chain_vulns)
        }
    
    def _find_custom_chains(self) -> List[Dict[str, Any]]:
        """Find custom chains based on vulnerability relationships"""
        custom_chains = []
        vuln_types = [v.get('type', '').lower() for v in self.vulnerabilities]
        
        # Look for common chain patterns
        if 'sqli' in vuln_types and 'file_upload' in vuln_types:
            custom_chains.append(self._build_custom_chain('sqli_upload_chain', ['sqli', 'file_upload']))
        
        if 'xss' in vuln_types and 'idor' in vuln_types:
            custom_chains.append(self._build_custom_chain('xss_idor_chain', ['xss', 'idor']))
        
        if 'lfi' in vuln_types and 'command_injection' in vuln_types:
            custom_chains.append(self._build_custom_chain('lfi_rce_chain', ['lfi', 'command_injection']))
        
        return custom_chains
    
    def _build_custom_chain(self, name: str, steps: List[str]) -> Dict[str, Any]:
        """Build a custom exploit chain"""
        chain_vulns = []
        
        for step in steps:
            for vuln in self.vulnerabilities:
                if vuln.get('type', '').lower() == step:
                    chain_vulns.append({
                        'step': step,
                        'vulnerability': vuln,
                        'url': vuln.get('url', ''),
                        'parameter': vuln.get('parameter', ''),
                        'payload': vuln.get('payload', '')
                    })
                    break
        
        return {
            'name': name,
            'steps': chain_vulns,
            'risk_level': self._assess_chain_risk(chain_vulns),
            'exploitability': self._assess_exploitability(chain_vulns),
            'impact': self._assess_impact(chain_vulns),
            'prerequisites': self._get_prerequisites(chain_vulns),
            'execution_path': self._generate_execution_path(chain_vulns)
        }
    
    def _assess_chain_risk(self, chain_vulns: List[Dict[str, Any]]) -> str:
        """Assess the risk level of an exploit chain"""
        high_risk_steps = ['rce', 'command_injection', 'file_upload', 'sqli']
        medium_risk_steps = ['xss', 'idor', 'lfi', 'ssrf']
        
        high_count = sum(1 for step in chain_vulns if any(risk in step['step'] for risk in high_risk_steps))
        medium_count = sum(1 for step in chain_vulns if any(risk in step['step'] for risk in medium_risk_steps))
        
        if high_count >= 2:
            return 'critical'
        elif high_count >= 1 or medium_count >= 2:
            return 'high'
        elif medium_count >= 1:
            return 'medium'
        else:
            return 'low'
    
    def _assess_exploitability(self, chain_vulns: List[Dict[str, Any]]) -> str:
        """Assess the exploitability of a chain"""
        # Check for common exploitability factors
        has_reflected = any('xss' in step['step'] for step in chain_vulns)
        has_file_access = any('lfi' in step['step'] or 'file_upload' in step['step'] for step in chain_vulns)
        has_command_exec = any('command_injection' in step['step'] or 'rce' in step['step'] for step in chain_vulns)
        
        if has_command_exec:
            return 'high'
        elif has_file_access and has_reflected:
            return 'medium'
        elif has_reflected or has_file_access:
            return 'low'
        else:
            return 'very_low'
    
    def _assess_impact(self, chain_vulns: List[Dict[str, Any]]) -> str:
        """Assess the potential impact of a chain"""
        impact_keywords = {
            'critical': ['rce', 'command_injection', 'admin_access'],
            'high': ['sqli', 'file_upload', 'data_exfiltration'],
            'medium': ['xss', 'idor', 'session_theft'],
            'low': ['info_disclosure', 'open_redirect']
        }
        
        max_impact = 'low'
        for step in chain_vulns:
            for impact_level, keywords in impact_keywords.items():
                if any(keyword in step['step'] for keyword in keywords):
                    if impact_level == 'critical':
                        return 'critical'
                    elif impact_level == 'high' and max_impact in ['low', 'medium']:
                        max_impact = 'high'
                    elif impact_level == 'medium' and max_impact == 'low':
                        max_impact = 'medium'
        
        return max_impact
    
    def _get_prerequisites(self, chain_vulns: List[Dict[str, Any]]) -> List[str]:
        """Get prerequisites for executing the chain"""
        prerequisites = []
        
        for step in chain_vulns:
            vuln_type = step['step']
            
            if vuln_type == 'xss':
                prerequisites.append("Victim must visit the XSS payload")
            elif vuln_type == 'csrf':
                prerequisites.append("Victim must be authenticated")
            elif vuln_type == 'file_upload':
                prerequisites.append("File upload functionality must be accessible")
            elif vuln_type == 'sqli':
                prerequisites.append("Database must be accessible")
            elif vuln_type == 'lfi':
                prerequisites.append("File system access must be available")
            elif vuln_type == 'command_injection':
                prerequisites.append("Command execution must be enabled")
        
        return list(set(prerequisites))  # Remove duplicates
    
    def _generate_execution_path(self, chain_vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate step-by-step execution path"""
        execution_path = []
        
        for i, step in enumerate(chain_vulns, 1):
            execution_step = {
                'step_number': i,
                'vulnerability_type': step['step'],
                'url': step['url'],
                'parameter': step['parameter'],
                'payload': step['payload'],
                'description': self._get_step_description(step['step']),
                'expected_result': self._get_expected_result(step['step'])
            }
            execution_path.append(execution_step)
        
        return execution_path
    
    def _get_step_description(self, vuln_type: str) -> str:
        """Get description for a chain step"""
        descriptions = {
            'xss': 'Execute reflected XSS payload to steal session cookies',
            'csrf': 'Perform CSRF attack to change user settings',
            'idor': 'Access unauthorized resources by manipulating IDs',
            'sqli': 'Extract database information using SQL injection',
            'file_upload': 'Upload malicious file to gain code execution',
            'lfi': 'Read sensitive files from the server',
            'command_injection': 'Execute system commands on the server',
            'rce': 'Achieve remote code execution',
            'session_theft': 'Steal user session tokens',
            'data_exfiltration': 'Extract sensitive data from the system'
        }
        
        return descriptions.get(vuln_type, f'Execute {vuln_type} attack')
    
    def _get_expected_result(self, vuln_type: str) -> str:
        """Get expected result for a chain step"""
        results = {
            'xss': 'Session cookies or sensitive data stolen',
            'csrf': 'User settings or actions modified',
            'idor': 'Unauthorized access to resources',
            'sqli': 'Database information extracted',
            'file_upload': 'Malicious file uploaded successfully',
            'lfi': 'Sensitive files read from server',
            'command_injection': 'System commands executed',
            'rce': 'Remote code execution achieved',
            'session_theft': 'User session compromised',
            'data_exfiltration': 'Sensitive data extracted'
        }
        
        return results.get(vuln_type, f'{vuln_type} attack successful')
    
    async def execute_chain(self, chain: Dict[str, Any]) -> Dict[str, Any]:
        """Execute an exploit chain (simulation)"""
        results = {
            'chain_name': chain['name'],
            'steps_executed': [],
            'successful_steps': 0,
            'failed_steps': 0,
            'final_result': 'unknown'
        }
        
        for step in chain['steps']:
            step_result = await self._execute_step(step)
            results['steps_executed'].append(step_result)
            
            if step_result['success']:
                results['successful_steps'] += 1
            else:
                results['failed_steps'] += 1
        
        # Determine final result
        if results['successful_steps'] == len(chain['steps']):
            results['final_result'] = 'success'
        elif results['successful_steps'] > 0:
            results['final_result'] = 'partial'
        else:
            results['final_result'] = 'failed'
        
        return results
    
    async def _execute_step(self, step: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a single chain step (simulation)"""
        # This is a simulation - in a real implementation, you would
        # actually execute the vulnerability exploitation
        
        return {
            'step': step['step'],
            'url': step['url'],
            'parameter': step['parameter'],
            'payload': step['payload'],
            'success': True,  # Simulated success
            'result': f"Successfully executed {step['step']}",
            'timestamp': datetime.now().isoformat()
        }
    
    def get_chain_summary(self) -> Dict[str, Any]:
        """Get summary of all chains"""
        return {
            'total_chains': len(self.chains),
            'total_vulnerabilities': len(self.vulnerabilities),
            'risk_distribution': self._get_risk_distribution(),
            'impact_distribution': self._get_impact_distribution(),
            'exploitability_distribution': self._get_exploitability_distribution()
        }
    
    def _get_risk_distribution(self) -> Dict[str, int]:
        """Get distribution of chain risk levels"""
        distribution = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for chain in self.chains:
            risk = chain.get('risk_level', 'low')
            distribution[risk] = distribution.get(risk, 0) + 1
        return distribution
    
    def _get_impact_distribution(self) -> Dict[str, int]:
        """Get distribution of chain impact levels"""
        distribution = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for chain in self.chains:
            impact = chain.get('impact', 'low')
            distribution[impact] = distribution.get(impact, 0) + 1
        return distribution
    
    def _get_exploitability_distribution(self) -> Dict[str, int]:
        """Get distribution of chain exploitability levels"""
        distribution = {'high': 0, 'medium': 0, 'low': 0, 'very_low': 0}
        for chain in self.chains:
            exploitability = chain.get('exploitability', 'low')
            distribution[exploitability] = distribution.get(exploitability, 0) + 1
        return distribution 