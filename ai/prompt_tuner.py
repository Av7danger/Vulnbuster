import asyncio
from typing import Dict, Any, Optional, List
from pathlib import Path
import json

# --- Advanced Prompt Tuning System ---
PROMPT_TEMPLATES = {
    'poc': {
        'base': "You are an expert exploit developer. Generate a working PoC for {vuln_type}.",
        'enhanced': "You are an expert exploit developer specializing in {vuln_type}. Target: {target_url}, Tech: {tech_stack}. Generate {output_format} PoC with WAF bypass considerations."
    },
    'oracle': {
        'base': "Suggest payload for parameter {param_name}.",
        'enhanced': "Given parameter '{param_name}' on {tech_stack} with history {payload_history}, suggest optimal payload for {vuln_type}."
    },
    'jwt': {
        'base': "Analyze JWT token for vulnerabilities.",
        'enhanced': "Analyze JWT token from {target_url} with {tech_stack}. Check for alg:none, weak secrets, and signature bypasses."
    },
    'shellgen': {
        'base': "Generate {lang} reverse shell.",
        'enhanced': "Generate {lang} reverse shell for {target_os} with {firewall_context}. Include WAF bypass if needed."
    },
    'rule_engine': {
        'base': "Suggest detection rule for {vuln_type}.",
        'enhanced': "Based on confirmed {vuln_type} with payload {payload} and response {response}, suggest improved detection rule."
    }
}

async def tune_prompt(module: str, base_prompt: str, context: Dict[str, Any] = None) -> str:
    """Tune prompt with context and module-specific enhancements"""
    if module not in PROMPT_TEMPLATES:
        return base_prompt
    
    template = PROMPT_TEMPLATES[module]['enhanced']
    try:
        return template.format(**context) if context else template
    except KeyError:
        return PROMPT_TEMPLATES[module]['base']

async def load_template_prompt(template_path: str, context: Dict[str, Any]) -> str:
    """Load and render Jinja2 template prompt"""
    try:
        from jinja2 import Template
        with open(template_path, 'r') as f:
            template = Template(f.read())
        return template.render(**context)
    except Exception as e:
        return f"[error] Template loading failed: {e}"

async def enhance_with_history(prompt: str, scan_history: List[Dict[str, Any]]) -> str:
    """Enhance prompt with scan history context"""
    if not scan_history:
        return prompt
    
    recent_findings = [f for f in scan_history[-5:] if f.get('type')]
    if recent_findings:
        history_context = f"Recent findings: {', '.join([f['type'] for f in recent_findings])}"
        return f"{prompt}\n\nContext: {history_context}"
    
    return prompt 