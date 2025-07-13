import asyncio
from typing import List, Dict, Any
import json
import sys
import graphviz

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

"""
Attack Replay Graph Generator
Generates DAG of scan → vuln → exploit → result. Outputs .png/.html via Graphviz.
Usage: --graph-scan-flow
"""
def render_flow_graph(scan_flow, output='scan_flow.png'):
    dot = graphviz.Digraph(comment='Scan Flow')
    for node in scan_flow['nodes']:
        dot.node(node['id'], node['label'])
    for edge in scan_flow['edges']:
        dot.edge(edge['from'], edge['to'], label=edge.get('label', ''))
    dot.render(output, view=False, format='png')
    print(f"[+] Graph rendered to {output}")

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Attack Replay Graph Generator")
    parser.add_argument('--graph-scan-flow', action='store_true', help='Render scan flow graph')
    parser.add_argument('--input', default='scan_flow.json', help='Path to scan flow JSON')
    parser.add_argument('--output', default='scan_flow.png', help='Output file (.png or .html)')
    args = parser.parse_args()
    if args.graph_scan_flow:
        with open(args.input) as f:
            scan_flow = json.load(f)
        render_flow_graph(scan_flow, args.output)

if __name__ == "__main__":
    main() 