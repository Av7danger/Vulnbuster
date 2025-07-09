import asyncio
from typing import Dict, Any, List
import difflib

# --- Payload Diff Viewer ---
async def show_payload_diff(baseline_response: str, trigger_response: str, trigger_payload: str) -> Dict[str, Any]:
    """Show difference between baseline and trigger responses"""
    try:
        diff = list(difflib.unified_diff(
            baseline_response.splitlines(keepends=True),
            trigger_response.splitlines(keepends=True),
            fromfile='baseline',
            tofile='trigger'
        ))
        
        return {
            'trigger_payload': trigger_payload,
            'diff': ''.join(diff),
            'baseline_length': len(baseline_response),
            'trigger_length': len(trigger_response),
            'difference_size': len(trigger_response) - len(baseline_response)
        }
    except Exception as e:
        return {'error': str(e)}

async def analyze_payload_effectiveness(payloads: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze which payloads were most effective"""
    effective = []
    for payload_data in payloads:
        if payload_data.get('triggered', False):
            effective.append({
                'payload': payload_data.get('payload', ''),
                'response_diff': payload_data.get('response_diff', 0),
                'vuln_type': payload_data.get('vuln_type', 'unknown')
            })
    
    return {
        'total_payloads': len(payloads),
        'effective_payloads': len(effective),
        'most_effective': sorted(effective, key=lambda x: x.get('response_diff', 0), reverse=True)[:5]
    } 