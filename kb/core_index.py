import asyncio
from typing import List, Dict, Any
import json
from pathlib import Path

KB_PATH = Path('kb/findings.jsonl')

# --- Store finding in KB (append to JSONL) ---
async def store_finding(finding: Dict[str, Any]) -> bool:
    try:
        KB_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(KB_PATH, 'a', encoding='utf-8') as f:
            f.write(json.dumps(finding) + '\n')
        return True
    except Exception as e:
        return False

# --- Cross-reference with previous scans/known bypasses ---
async def cross_reference(finding: Dict[str, Any]) -> List[str]:
    matches = []
    try:
        if not KB_PATH.exists():
            return matches
        with open(KB_PATH, 'r', encoding='utf-8') as f:
            for line in f:
                prev = json.loads(line)
                if finding.get('type') == prev.get('type') or finding.get('description') in prev.get('description', ''):
                    matches.append(prev.get('description', ''))
    except Exception:
        pass
    return matches

# --- AI Recall Prompt (prompt in ai_memory.py) ---
async def ai_recall(query: str) -> str:
    await asyncio.sleep(0.1)
    return '[AI] Yes, similar pattern seen before (stub)' 