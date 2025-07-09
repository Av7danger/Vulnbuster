import asyncio
from typing import List, Dict, Any
import json

# --- Visual Scan Flow Renderer ---
async def render_scan_flow(steps: List[Dict[str, Any]]) -> str:
    """Render scan flow as visual representation"""
    flow = []
    for i, step in enumerate(steps, 1):
        step_type = step.get('type', 'unknown')
        if step_type == 'crawl':
            flow.append(f"🕷️  Step {i}: Crawled {step.get('url', 'unknown')}")
        elif step_type == 'fuzz':
            flow.append(f"🔍 Step {i}: Fuzzed {step.get('param', 'unknown')}")
        elif step_type == 'vuln':
            flow.append(f"💥 Step {i}: Found {step.get('vuln_type', 'unknown')}")
        elif step_type == 'exploit':
            flow.append(f"⚔️  Step {i}: Exploited {step.get('target', 'unknown')}")
        else:
            flow.append(f"📝 Step {i}: {step.get('description', 'unknown')}")
    
    return "\n".join(flow)

async def generate_flow_diagram(steps: List[Dict[str, Any]]) -> str:
    """Generate ASCII flow diagram"""
    diagram = []
    diagram.append("Scan Flow Diagram:")
    diagram.append("=" * 50)
    
    for i, step in enumerate(steps):
        if i > 0:
            diagram.append("    ↓")
        diagram.append(f"  {step.get('type', 'step').upper()}")
    
    return "\n".join(diagram)

async def export_flow_json(steps: List[Dict[str, Any]]) -> str:
    """Export flow as JSON for external tools"""
    return json.dumps({
        'scan_flow': steps,
        'total_steps': len(steps),
        'vuln_count': len([s for s in steps if s.get('type') == 'vuln'])
    }, indent=2) 