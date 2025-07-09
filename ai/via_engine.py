"""
VIA (Vulnerability Intelligence Advisor) Engine
Processes security signals and provides AI-powered vulnerability intelligence
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
import json

from ai.ai_bridge import ask_mixtral

class VIAEngine:
    def __init__(self):
        self.signal_history = []
        self.advice_cache = {}
        self.exploit_chains = []
        
    async def process_signal(self, signal: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process a security signal and get AI advice"""
        # Add timestamp to signal
        signal['timestamp'] = datetime.now().isoformat()
        
        # Store in history
        self.signal_history.append(signal)
        
        # Check cache first
        signal_key = self._generate_signal_key(signal)
        if signal_key in self.advice_cache:
            logging.info("Using cached advice for signal")
            return self.advice_cache[signal_key]
        
        # Get AI analysis
        analysis = await self._analyze_vulnerability_signal(signal)
        if analysis:
            # Cache the advice
            self.advice_cache[signal_key] = analysis
            
            # Log the advice
            logging.info(f"VIA Advice for {signal.get('type', 'unknown')}: {analysis.get('analysis', '')[:100]}...")
            
            return analysis
        
        return None
    
    async def _analyze_vulnerability_signal(self, signal: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Analyze vulnerability signal using AI"""
        try:
            signal_type = signal.get('type', 'unknown')
            url = signal.get('url', 'unknown')
            parameter = signal.get('parameter', 'unknown')
            evidence = signal.get('evidence', '')
            
            prompt = f"""
You are an expert offensive security analyst. Analyze this vulnerability signal:

SIGNAL TYPE: {signal_type}
URL: {url}
PARAMETER: {parameter}
EVIDENCE: {evidence[:500]}

Provide analysis in JSON format:
{{
    "analysis": "Brief analysis of the signal",
    "confidence": "high/medium/low",
    "recommended_actions": ["action1", "action2"],
    "payload_suggestions": ["payload1", "payload2"],
    "risk_level": "critical/high/medium/low",
    "exploitation_potential": "high/medium/low"
}}
"""
            
            ai_response = ask_mixtral(prompt)
            
            # Parse AI response
            try:
                if '{' in ai_response and '}' in ai_response:
                    start = ai_response.find('{')
                    end = ai_response.rfind('}') + 1
                    json_str = ai_response[start:end]
                    return json.loads(json_str)
                else:
                    return {
                        'analysis': ai_response[:500],
                        'confidence': 'medium',
                        'recommended_actions': [],
                        'payload_suggestions': [],
                        'risk_level': 'medium',
                        'exploitation_potential': 'medium'
                    }
            except Exception as e:
                logging.warning(f"Failed to parse AI analysis: {e}")
                return {
                    'analysis': ai_response[:500],
                    'confidence': 'medium',
                    'recommended_actions': [],
                    'payload_suggestions': [],
                    'risk_level': 'medium',
                    'exploitation_potential': 'medium'
                }
                
        except Exception as e:
            logging.error(f"Failed to analyze vulnerability signal: {e}")
            return None
    
    async def suggest_payloads(self, vuln_type: str, context: Dict[str, Any]) -> List[str]:
        """Suggest payloads for a specific vulnerability type"""
        try:
            context_str = str(context)[:200]  # Limit context size
            
            prompt = f"""
Suggest 5 high-quality payloads for {vuln_type} vulnerability testing.

CONTEXT: {context_str}

Return only the payloads, one per line, without explanations.
"""
            
            ai_response = ask_mixtral(prompt)
            
            # Parse AI response
            payloads = []
            for line in ai_response.strip().split('\n'):
                line = line.strip()
                if line and not line.startswith('#') and not line.startswith('//'):
                    payloads.append(line)
            
            logging.info(f"VIA suggested {len(payloads)} payloads for {vuln_type}")
            return payloads[:5]  # Limit to 5 payloads
            
        except Exception as e:
            logging.error(f"Failed to suggest payloads: {e}")
            return []
    
    async def suggest_next_modules(self, current_results: List[Dict[str, Any]], target: str) -> List[str]:
        """Suggest which modules to run next"""
        try:
            results_summary = []
            for result in current_results[:5]:  # Limit to first 5 results
                results_summary.append({
                    'type': result.get('type', 'unknown'),
                    'severity': result.get('severity', 'unknown')
                })
            
            prompt = f"""
Based on these scan results, suggest which vulnerability modules to run next:

TARGET: {target}
CURRENT RESULTS: {results_summary}

Suggest modules that would:
1. Complement existing findings
2. Explore related attack vectors
3. Chain with discovered vulnerabilities

Return only module names, one per line.
"""
            
            ai_response = ask_mixtral(prompt)
            
            # Parse AI response
            modules = []
            for line in ai_response.strip().split('\n'):
                line = line.strip().lower()
                if line and not line.startswith('#') and not line.startswith('//'):
                    modules.append(line)
            
            logging.info(f"VIA suggested modules: {', '.join(modules)}")
            return modules[:10]  # Limit to 10 modules
            
        except Exception as e:
            logging.error(f"Failed to suggest modules: {e}")
            return []
    
    async def analyze_exploit_chain(self, vulnerabilities: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Analyze potential exploit chains"""
        try:
            vuln_summary = []
            for vuln in vulnerabilities[:5]:  # Limit to first 5 vulnerabilities
                vuln_summary.append({
                    'type': vuln.get('type', 'unknown'),
                    'severity': vuln.get('severity', 'unknown'),
                    'url': vuln.get('url', 'unknown')
                })
            
            prompt = f"""
Analyze these vulnerabilities and identify potential exploit chains:

VULNERABILITIES: {vuln_summary}

Provide analysis in JSON format:
{{
    "exploit_chains": [
        {{
            "name": "Chain name",
            "steps": ["step1", "step2"],
            "difficulty": "easy/medium/hard",
            "impact": "low/medium/high/critical"
        }}
    ],
    "recommendations": ["rec1", "rec2"]
}}
"""
            
            ai_response = ask_mixtral(prompt)
            
            # Parse AI response
            try:
                if '{' in ai_response and '}' in ai_response:
                    start = ai_response.find('{')
                    end = ai_response.rfind('}') + 1
                    json_str = ai_response[start:end]
                    chain_analysis = json.loads(json_str)
                    self.exploit_chains.append(chain_analysis)
                    logging.info(f"VIA identified exploit chain with {len(chain_analysis.get('exploit_chains', []))} chains")
                    return chain_analysis
                else:
                    return {
                        'exploit_chains': [],
                        'recommendations': [ai_response[:200]]
                    }
            except Exception as e:
                logging.warning(f"Failed to parse exploit chain analysis: {e}")
                return {
                    'exploit_chains': [],
                    'recommendations': [ai_response[:200]]
                }
                
        except Exception as e:
            logging.error(f"Failed to analyze exploit chain: {e}")
            return None
    
    async def get_contextual_advice(self, current_state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Get contextual advice based on current scan state"""
        try:
            # Build context from signal history and current state
            context = {
                'target': current_state.get('target'),
                'mode': current_state.get('mode'),
                'modules_run': current_state.get('modules_run', []),
                'vulnerabilities_found': current_state.get('vulnerabilities_found', []),
                'recent_signals': self.signal_history[-5:] if self.signal_history else [],
                'exploit_chains': self.exploit_chains
            }
            
            prompt = f"""
Based on the current scan state, provide strategic advice:

Target: {context['target']}
Mode: {context['mode']}
Modules Run: {', '.join(context['modules_run'])}
Vulnerabilities Found: {len(context['vulnerabilities_found'])}
Recent Signals: {len(context['recent_signals'])}
Exploit Chains Identified: {len(context['exploit_chains'])}

What should be the next strategic steps?
1. Which modules should be prioritized?
2. What attack vectors should be explored?
3. Are there any high-value targets to focus on?
4. What post-exploitation opportunities exist?
"""
            
            response = ask_mixtral(prompt)
            if response:
                return {
                    'strategic_advice': response,
                    'context': context,
                    'timestamp': datetime.now().isoformat()
                }
            
        except Exception as e:
            logging.error(f"Failed to get contextual advice: {e}")
        
        return None
    
    async def assess_attack_surface(self, target: str, discovered_endpoints: List[str], 
                                  found_vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess the overall attack surface"""
        try:
            context = {
                'target': target,
                'endpoints': discovered_endpoints,
                'vulnerabilities': found_vulnerabilities,
                'signal_history': self.signal_history
            }
            
            prompt = f"""
Assess the attack surface for {target}:

Discovered Endpoints: {len(discovered_endpoints)}
Vulnerabilities Found: {len(found_vulnerabilities)}
Security Signals: {len(self.signal_history)}

Provide:
1. Attack surface assessment (low/medium/high/critical)
2. Most promising attack vectors
3. Recommended focus areas
4. Potential impact assessment
5. Exploitation difficulty rating
"""
            
            response = ask_mixtral(prompt)
            if response:
                return {
                    'assessment': response,
                    'target': target,
                    'endpoint_count': len(discovered_endpoints),
                    'vulnerability_count': len(found_vulnerabilities),
                    'signal_count': len(self.signal_history),
                    'timestamp': datetime.now().isoformat()
                }
            
        except Exception as e:
            logging.error(f"Failed to assess attack surface: {e}")
        
        return {}
    
    async def optimize_scan_strategy(self, current_results: List[Dict[str, Any]], 
                                   available_modules: List[str]) -> Dict[str, Any]:
        """Optimize scan strategy based on current results"""
        try:
            context = {
                'current_results': current_results,
                'available_modules': available_modules,
                'signal_history': self.signal_history
            }
            
            prompt = f"""
Optimize the scan strategy based on current results:

Current Results: {len(current_results)} findings
Available Modules: {', '.join(available_modules)}
Signals Processed: {len(self.signal_history)}

Recommend:
1. Which modules to run next (prioritized)
2. Which modules to skip (low value)
3. Custom payloads to try
4. Parameter focus areas
5. Timing and rate limiting strategy
"""
            
            response = ask_mixtral(prompt)
            if response:
                return {
                    'optimization_advice': response,
                    'recommended_modules': self._extract_module_recommendations(response, available_modules),
                    'timestamp': datetime.now().isoformat()
                }
            
        except Exception as e:
            logging.error(f"Failed to optimize scan strategy: {e}")
        
        return {}
    
    def _generate_signal_key(self, signal: Dict[str, Any]) -> str:
        """Generate a unique key for signal caching"""
        return f"{signal.get('type', '')}_{signal.get('url', '')}_{signal.get('parameter', '')}"
    
    def _extract_module_recommendations(self, response: str, available_modules: List[str]) -> List[str]:
        """Extract module recommendations from AI response"""
        recommendations = []
        response_lower = response.lower()
        
        for module in available_modules:
            if module.lower() in response_lower:
                recommendations.append(module)
        
        return recommendations[:5]  # Limit to 5 recommendations
    
    def get_signal_summary(self) -> Dict[str, Any]:
        """Get summary of processed signals"""
        return {
            'total_signals': len(self.signal_history),
            'cached_advice': len(self.advice_cache),
            'exploit_chains': len(self.exploit_chains),
            'recent_signals': self.signal_history[-10:] if self.signal_history else [],
            'signal_types': list(set(s.get('type', 'unknown') for s in self.signal_history))
        }
    
    def clear_cache(self):
        """Clear the advice cache"""
        self.advice_cache.clear()
        logging.info("VIA advice cache cleared")
    
    def export_advice_history(self) -> Dict[str, Any]:
        """Export advice history for analysis"""
        return {
            'signal_history': self.signal_history,
            'advice_cache': self.advice_cache,
            'exploit_chains': self.exploit_chains,
            'summary': self.get_signal_summary()
        } 