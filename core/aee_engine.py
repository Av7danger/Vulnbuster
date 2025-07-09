"""
Autonomous Exploitation Engine (AEE)
Automatically decides next steps after vulnerability findings using AI
"""

import asyncio
import logging
import json
from typing import Dict, Any, List, Optional
from pathlib import Path
from datetime import datetime

from ai.ai_bridge import ask_mixtral

class AEEngine:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.ai_enabled = config.get('ai_enabled', True)
        self.autopilot_enabled = config.get('autopilot_enabled', False)
        self.auto_poc = config.get('auto_poc', False)
        self.auto_exploit = config.get('auto_exploit', False)
        self.decision_log = []
        self.triggered_actions = []
        
    async def process_finding(self, finding: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Process a vulnerability finding and decide next actions
        """
        logging.info(f"AEE processing finding: {finding.get('type', 'unknown')}")
        
        # Log the finding
        self.decision_log.append({
            'timestamp': datetime.now().isoformat(),
            'finding': finding,
            'context': context
        })
        
        # Get AI advice if enabled
        if self.ai_enabled:
            ai_advice = await self._get_ai_advice(finding, context)
            finding['ai_advice'] = ai_advice
            
            # Execute AI-suggested actions
            if self.autopilot_enabled:
                actions = await self._execute_ai_actions(finding, ai_advice)
                self.triggered_actions.extend(actions)
        
        # Apply rule-based logic
        rule_actions = await self._apply_rule_based_logic(finding, context)
        self.triggered_actions.extend(rule_actions)
        
        return self.triggered_actions
    
    async def _get_ai_advice(self, finding: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Get AI advice for a finding using Mixtral
        """
        try:
            # Build context-aware prompt
            prompt = self._build_ai_prompt(finding, context)
            
            # Get AI response
            ai_response = ask_mixtral(prompt)
            
            # Parse AI response
            advice = self._parse_ai_response(ai_response)
            
            logging.info(f"AI advice received: {advice.get('summary', 'No summary')}")
            return advice
            
        except Exception as e:
            logging.error(f"Failed to get AI advice: {e}")
            return {'error': str(e)}
    
    def _build_ai_prompt(self, finding: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> str:
        """
        Build a context-aware prompt for Mixtral
        """
        finding_type = finding.get('type', 'unknown')
        url = finding.get('url', 'unknown')
        parameter = finding.get('parameter', 'unknown')
        payload = finding.get('payload', 'unknown')
        severity = finding.get('severity', 'unknown')
        
        prompt = f"""
You are an expert offensive security analyst. Analyze this vulnerability finding and suggest the next steps:

FINDING:
- Type: {finding_type}
- URL: {url}
- Parameter: {parameter}
- Payload: {payload}
- Severity: {severity}
- Evidence: {finding.get('evidence', 'N/A')}

CONTEXT: {context or 'No additional context'}

Based on this finding, suggest:
1. What follow-up tests should be run?
2. What payloads should be tried next?
3. What exploit chains are possible?
4. What post-exploitation steps should be taken?

Respond in JSON format:
{{
    "summary": "Brief analysis",
    "next_tests": ["test1", "test2"],
    "next_payloads": ["payload1", "payload2"],
    "exploit_chains": ["chain1", "chain2"],
    "post_exploitation": ["step1", "step2"],
    "risk_assessment": "high/medium/low",
    "recommendations": ["rec1", "rec2"]
}}
"""
        return prompt
    
    def _parse_ai_response(self, ai_response: str) -> Dict[str, Any]:
        """
        Parse AI response and extract structured advice
        """
        try:
            # Try to extract JSON from response
            if '{' in ai_response and '}' in ai_response:
                start = ai_response.find('{')
                end = ai_response.rfind('}') + 1
                json_str = ai_response[start:end]
                return json.loads(json_str)
            else:
                # Fallback to simple parsing
                return {
                    'summary': ai_response[:200],
                    'raw_response': ai_response
                }
        except Exception as e:
            logging.warning(f"Failed to parse AI response: {e}")
            return {
                'summary': 'AI response parsing failed',
                'raw_response': ai_response
            }
    
    async def _execute_ai_actions(self, finding: Dict[str, Any], ai_advice: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Execute actions suggested by AI
        """
        actions = []
        
        try:
            # Execute next tests
            next_tests = ai_advice.get('next_tests', [])
            for test in next_tests:
                action = await self._trigger_test(finding, test)
                if action:
                    actions.append(action)
            
            # Execute next payloads
            next_payloads = ai_advice.get('next_payloads', [])
            for payload in next_payloads:
                action = await self._trigger_payload(finding, payload)
                if action:
                    actions.append(action)
            
            # Execute exploit chains
            exploit_chains = ai_advice.get('exploit_chains', [])
            for chain in exploit_chains:
                action = await self._trigger_chain(finding, chain)
                if action:
                    actions.append(action)
            
            # Execute post-exploitation
            if self.auto_exploit:
                post_ex_steps = ai_advice.get('post_exploitation', [])
                for step in post_ex_steps:
                    action = await self._trigger_post_exploitation(finding, step)
                    if action:
                        actions.append(action)
            
        except Exception as e:
            logging.error(f"Failed to execute AI actions: {e}")
        
        return actions
    
    async def _apply_rule_based_logic(self, finding: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Apply rule-based logic for common vulnerability patterns
        """
        actions = []
        finding_type = finding.get('type', '')
        
        # Rule-based actions based on vulnerability type
        if 'xss' in finding_type.lower():
            actions.extend(await self._handle_xss_finding(finding))
        elif 'sqli' in finding_type.lower():
            actions.extend(await self._handle_sqli_finding(finding))
        elif 'upload' in finding_type.lower():
            actions.extend(await self._handle_upload_finding(finding))
        elif 'idor' in finding_type.lower():
            actions.extend(await self._handle_idor_finding(finding))
        elif 'csrf' in finding_type.lower():
            actions.extend(await self._handle_csrf_finding(finding))
        
        return actions
    
    async def _handle_xss_finding(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Handle XSS findings with automatic follow-up
        """
        actions = []
        
        # If reflected XSS found, try DOM XSS
        if 'reflected' in finding.get('type', ''):
            actions.append({
                'type': 'trigger_module',
                'module': 'dom_xss',
                'target': finding.get('url'),
                'parameter': finding.get('parameter'),
                'reason': 'Follow-up DOM XSS test after reflected XSS detection'
            })
        
        # Try blind XSS if not already tested
        actions.append({
            'type': 'trigger_payload',
            'payload_type': 'blind_xss',
            'target': finding.get('url'),
            'parameter': finding.get('parameter'),
            'reason': 'Blind XSS follow-up test'
        })
        
        return actions
    
    async def _handle_sqli_finding(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Handle SQL injection findings with automatic follow-up
        """
        actions = []
        
        # If time-based SQLi found, try union-based
        if 'time' in finding.get('type', ''):
            actions.append({
                'type': 'trigger_payload',
                'payload_type': 'union_sqli',
                'target': finding.get('url'),
                'parameter': finding.get('parameter'),
                'reason': 'Union-based SQLi follow-up after time-based detection'
            })
        
        # Try stacked queries
        actions.append({
            'type': 'trigger_payload',
            'payload_type': 'stacked_sqli',
            'target': finding.get('url'),
            'parameter': finding.get('parameter'),
            'reason': 'Stacked queries SQLi test'
        })
        
        return actions
    
    async def _handle_upload_finding(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Handle file upload findings with automatic follow-up
        """
        actions = []
        
        # Try to access uploaded file
        actions.append({
            'type': 'trigger_post_exploitation',
            'module': 'upload_access',
            'target': finding.get('url'),
            'reason': 'Attempt to access uploaded file'
        })
        
        # Try different upload bypasses
        actions.append({
            'type': 'trigger_payload',
            'payload_type': 'upload_bypass',
            'target': finding.get('url'),
            'reason': 'Upload bypass techniques'
        })
        
        return actions
    
    async def _handle_idor_finding(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Handle IDOR findings with automatic follow-up
        """
        actions = []
        
        # Fuzz surrounding IDs
        actions.append({
            'type': 'trigger_payload',
            'payload_type': 'idor_fuzz',
            'target': finding.get('url'),
            'parameter': finding.get('parameter'),
            'reason': 'IDOR ID fuzzing'
        })
        
        # Try to access admin endpoints
        actions.append({
            'type': 'trigger_module',
            'module': 'bac',
            'target': finding.get('url'),
            'reason': 'Broken access control test after IDOR'
        })
        
        return actions
    
    async def _handle_csrf_finding(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Handle CSRF findings with automatic follow-up
        """
        actions = []
        
        # Try to chain with XSS
        actions.append({
            'type': 'trigger_module',
            'module': 'xss',
            'target': finding.get('url'),
            'reason': 'XSS test for CSRF chaining'
        })
        
        return actions
    
    async def _trigger_test(self, finding: Dict[str, Any], test: str) -> Optional[Dict[str, Any]]:
        """
        Trigger a specific test
        """
        return {
            'type': 'trigger_test',
            'test': test,
            'target': finding.get('url'),
            'timestamp': datetime.now().isoformat()
        }
    
    async def _trigger_payload(self, finding: Dict[str, Any], payload: str) -> Optional[Dict[str, Any]]:
        """
        Trigger a specific payload
        """
        return {
            'type': 'trigger_payload',
            'payload': payload,
            'target': finding.get('url'),
            'parameter': finding.get('parameter'),
            'timestamp': datetime.now().isoformat()
        }
    
    async def _trigger_chain(self, finding: Dict[str, Any], chain: str) -> Optional[Dict[str, Any]]:
        """
        Trigger an exploit chain
        """
        return {
            'type': 'trigger_chain',
            'chain': chain,
            'target': finding.get('url'),
            'timestamp': datetime.now().isoformat()
        }
    
    async def _trigger_post_exploitation(self, finding: Dict[str, Any], step: str) -> Optional[Dict[str, Any]]:
        """
        Trigger post-exploitation step
        """
        return {
            'type': 'trigger_post_exploitation',
            'step': step,
            'target': finding.get('url'),
            'timestamp': datetime.now().isoformat()
        }
    
    def get_decision_log(self) -> List[Dict[str, Any]]:
        """
        Get the decision log
        """
        return self.decision_log
    
    def get_triggered_actions(self) -> List[Dict[str, Any]]:
        """
        Get all triggered actions
        """
        return self.triggered_actions
    
    def save_logs(self, output_dir: str = "logs"):
        """
        Save decision logs to file
        """
        try:
            output_path = Path(output_dir)
            output_path.mkdir(exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Save decision log
            decision_file = output_path / f"aee_decisions_{timestamp}.json"
            with open(decision_file, 'w') as f:
                json.dump(self.decision_log, f, indent=2)
            
            # Save triggered actions
            actions_file = output_path / f"aee_actions_{timestamp}.json"
            with open(actions_file, 'w') as f:
                json.dump(self.triggered_actions, f, indent=2)
            
            logging.info(f"AEE logs saved to {output_path}")
            
        except Exception as e:
            logging.error(f"Failed to save AEE logs: {e}") 