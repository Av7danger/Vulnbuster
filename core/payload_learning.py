"""
Payload Learning Engine
Tracks payload performance and uses AI to optimize payload selection
"""

import asyncio
import logging
import json
from typing import Dict, Any, List, Optional
from pathlib import Path
from datetime import datetime
from collections import defaultdict

from ai.ai_bridge import ask_mixtral

class PayloadLearningEngine:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.stats_file = Path("logs/payload_stats.json")
        self.stats_file.parent.mkdir(exist_ok=True)
        self.payload_stats = self._load_stats()
        self.current_session = {
            'start_time': datetime.now().isoformat(),
            'payloads_tested': 0,
            'successful_payloads': 0,
            'failed_payloads': 0,
            'reflected_payloads': 0
        }
        
    def _load_stats(self) -> Dict[str, Any]:
        """Load payload statistics from file"""
        try:
            if self.stats_file.exists():
                with open(self.stats_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logging.warning(f"Failed to load payload stats: {e}")
        
        return {
            'payloads': {},
            'vulnerability_types': {},
            'targets': {},
            'session_history': [],
            'ai_recommendations': []
        }
    
    def _save_stats(self):
        """Save payload statistics to file"""
        try:
            with open(self.stats_file, 'w') as f:
                json.dump(self.payload_stats, f, indent=2)
        except Exception as e:
            logging.error(f"Failed to save payload stats: {e}")
    
    def record_payload_result(self, payload: str, vuln_type: str, target: str, 
                            result: str, response_code: int = None, 
                            response_time: float = None, evidence: str = None):
        """Record the result of a payload test"""
        
        # Update current session
        self.current_session['payloads_tested'] += 1
        
        if result == 'success':
            self.current_session['successful_payloads'] += 1
        elif result == 'fail':
            self.current_session['failed_payloads'] += 1
        elif result == 'reflect':
            self.current_session['reflected_payloads'] += 1
        
        # Create payload key
        payload_key = f"{vuln_type}:{payload}"
        
        # Initialize payload stats if not exists
        if payload_key not in self.payload_stats['payloads']:
            self.payload_stats['payloads'][payload_key] = {
                'payload': payload,
                'vuln_type': vuln_type,
                'total_tests': 0,
                'successes': 0,
                'failures': 0,
                'reflections': 0,
                'success_rate': 0.0,
                'avg_response_time': 0.0,
                'last_used': None,
                'targets_tested': set(),
                'evidence_samples': []
            }
        
        # Update payload stats
        stats = self.payload_stats['payloads'][payload_key]
        stats['total_tests'] += 1
        stats['last_used'] = datetime.now().isoformat()
        stats['targets_tested'].add(target)
        
        if result == 'success':
            stats['successes'] += 1
        elif result == 'fail':
            stats['failures'] += 1
        elif result == 'reflect':
            stats['reflections'] += 1
        
        # Calculate success rate
        stats['success_rate'] = stats['successes'] / stats['total_tests']
        
        # Update average response time
        if response_time:
            if stats['avg_response_time'] == 0:
                stats['avg_response_time'] = response_time
            else:
                stats['avg_response_time'] = (stats['avg_response_time'] + response_time) / 2
        
        # Store evidence sample
        if evidence and len(stats['evidence_samples']) < 5:
            stats['evidence_samples'].append(evidence[:200])
        
        # Update vulnerability type stats
        if vuln_type not in self.payload_stats['vulnerability_types']:
            self.payload_stats['vulnerability_types'][vuln_type] = {
                'total_payloads': 0,
                'successful_payloads': 0,
                'best_payloads': []
            }
        
        vuln_stats = self.payload_stats['vulnerability_types'][vuln_type]
        vuln_stats['total_payloads'] += 1
        if result == 'success':
            vuln_stats['successful_payloads'] += 1
        
        # Update target stats
        if target not in self.payload_stats['targets']:
            self.payload_stats['targets'][target] = {
                'total_tests': 0,
                'vulnerabilities_found': 0,
                'payloads_used': set()
            }
        
        target_stats = self.payload_stats['targets'][target]
        target_stats['total_tests'] += 1
        target_stats['payloads_used'].add(payload_key)
        if result == 'success':
            target_stats['vulnerabilities_found'] += 1
        
        # Save stats periodically
        if self.current_session['payloads_tested'] % 10 == 0:
            self._save_stats()
    
    def get_best_payloads(self, vuln_type: str, count: int = 5) -> List[str]:
        """Get the best performing payloads for a vulnerability type"""
        payloads = []
        
        for payload_key, stats in self.payload_stats['payloads'].items():
            if stats['vuln_type'] == vuln_type and stats['total_tests'] >= 3:
                payloads.append({
                    'payload': stats['payload'],
                    'success_rate': stats['success_rate'],
                    'total_tests': stats['total_tests'],
                    'avg_response_time': stats['avg_response_time']
                })
        
        # Sort by success rate and total tests
        payloads.sort(key=lambda x: (x['success_rate'], x['total_tests']), reverse=True)
        
        return [p['payload'] for p in payloads[:count]]
    
    def get_payload_recommendations(self, vuln_type: str, target: str, context: Dict[str, Any] = None) -> List[str]:
        """Get AI-powered payload recommendations"""
        try:
            # Get historical data for this vulnerability type
            vuln_payloads = []
            for payload_key, stats in self.payload_stats['payloads'].items():
                if stats['vuln_type'] == vuln_type:
                    vuln_payloads.append({
                        'payload': stats['payload'],
                        'success_rate': stats['success_rate'],
                        'total_tests': stats['total_tests']
                    })
            
            # Build AI prompt
            prompt = f"""
You are an expert offensive security specialist. Recommend payloads for {vuln_type} vulnerability testing.

TARGET: {target}
CONTEXT: {context or 'No additional context'}

HISTORICAL PERFORMANCE:
{json.dumps(vuln_payloads[:10], indent=2)}

Based on the historical data and target context, recommend 5 high-probability payloads.
Consider:
1. Success rates from historical data
2. Target-specific context
3. Modern bypass techniques
4. WAF evasion strategies

Return only the payloads, one per line, without explanations.
"""
            
            ai_response = ask_mixtral(prompt)
            
            # Parse AI response
            recommendations = []
            for line in ai_response.strip().split('\n'):
                line = line.strip()
                if line and not line.startswith('#') and not line.startswith('//'):
                    recommendations.append(line)
            
            # Log recommendation
            self.payload_stats['ai_recommendations'].append({
                'timestamp': datetime.now().isoformat(),
                'vuln_type': vuln_type,
                'target': target,
                'recommendations': recommendations[:5]
            })
            
            return recommendations[:5]
            
        except Exception as e:
            logging.error(f"Failed to get AI payload recommendations: {e}")
            return []
    
    async def analyze_payload_performance(self) -> Dict[str, Any]:
        """Analyze overall payload performance using AI"""
        try:
            # Prepare performance data
            performance_data = {
                'total_payloads': len(self.payload_stats['payloads']),
                'vulnerability_types': len(self.payload_stats['vulnerability_types']),
                'targets_tested': len(self.payload_stats['targets']),
                'top_performers': [],
                'underperformers': [],
                'session_summary': self.current_session
            }
            
            # Find top performers
            all_payloads = []
            for payload_key, stats in self.payload_stats['payloads'].items():
                if stats['total_tests'] >= 5:  # Only consider well-tested payloads
                    all_payloads.append({
                        'payload': stats['payload'],
                        'vuln_type': stats['vuln_type'],
                        'success_rate': stats['success_rate'],
                        'total_tests': stats['total_tests']
                    })
            
            # Sort by success rate
            all_payloads.sort(key=lambda x: x['success_rate'], reverse=True)
            performance_data['top_performers'] = all_payloads[:10]
            performance_data['underperformers'] = all_payloads[-10:]
            
            # Generate AI analysis
            prompt = f"""
Analyze this payload performance data and provide insights:

PERFORMANCE DATA: {json.dumps(performance_data, indent=2)}

Provide analysis in JSON format:
{{
    "summary": "Brief performance summary",
    "insights": ["insight1", "insight2"],
    "recommendations": ["rec1", "rec2"],
    "optimization_suggestions": ["suggestion1", "suggestion2"]
}}
"""
            
            ai_response = ask_mixtral(prompt)
            
            # Parse AI response
            try:
                if '{' in ai_response and '}' in ai_response:
                    start = ai_response.find('{')
                    end = ai_response.rfind('}') + 1
                    json_str = ai_response[start:end]
                    analysis = json.loads(json_str)
                else:
                    analysis = {
                        'summary': ai_response[:500],
                        'insights': [],
                        'recommendations': [],
                        'optimization_suggestions': []
                    }
            except Exception as e:
                logging.warning(f"Failed to parse AI analysis: {e}")
                analysis = {
                    'summary': ai_response[:500],
                    'insights': [],
                    'recommendations': [],
                    'optimization_suggestions': []
                }
            
            performance_data['ai_analysis'] = analysis
            return performance_data
            
        except Exception as e:
            logging.error(f"Failed to analyze payload performance: {e}")
            return {}
    
    def end_session(self):
        """End current session and save statistics"""
        self.current_session['end_time'] = datetime.now().isoformat()
        self.payload_stats['session_history'].append(self.current_session)
        
        # Save stats
        self._save_stats()
        
        logging.info(f"Session ended. Tested {self.current_session['payloads_tested']} payloads")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics"""
        return {
            'total_payloads': len(self.payload_stats['payloads']),
            'vulnerability_types': len(self.payload_stats['vulnerability_types']),
            'targets_tested': len(self.payload_stats['targets']),
            'sessions_completed': len(self.payload_stats['session_history']),
            'ai_recommendations': len(self.payload_stats['ai_recommendations']),
            'current_session': self.current_session,
            'top_performers': self._get_top_performers(),
            'vulnerability_breakdown': self._get_vulnerability_breakdown()
        }
    
    def _get_top_performers(self) -> List[Dict[str, Any]]:
        """Get top performing payloads"""
        performers = []
        for payload_key, stats in self.payload_stats['payloads'].items():
            if stats['total_tests'] >= 3:
                performers.append({
                    'payload': stats['payload'],
                    'vuln_type': stats['vuln_type'],
                    'success_rate': stats['success_rate'],
                    'total_tests': stats['total_tests']
                })
        
        performers.sort(key=lambda x: x['success_rate'], reverse=True)
        return performers[:10]
    
    def _get_vulnerability_breakdown(self) -> Dict[str, Any]:
        """Get breakdown by vulnerability type"""
        breakdown = {}
        for vuln_type, stats in self.payload_stats['vulnerability_types'].items():
            breakdown[vuln_type] = {
                'total_payloads': stats['total_payloads'],
                'successful_payloads': stats['successful_payloads'],
                'success_rate': stats['successful_payloads'] / stats['total_payloads'] if stats['total_payloads'] > 0 else 0
            }
        
        return breakdown
    
    def clear_stats(self):
        """Clear all statistics"""
        self.payload_stats = {
            'payloads': {},
            'vulnerability_types': {},
            'targets': {},
            'session_history': [],
            'ai_recommendations': []
        }
        self._save_stats()
        logging.info("Payload statistics cleared") 