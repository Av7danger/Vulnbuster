import asyncio
from typing import List, Dict, Any
import json
from pathlib import Path

RECORD_PATH = Path('audit/recording.jsonl')

# --- Record step (append to JSONL) ---
async def record_step(step: Dict[str, Any]) -> bool:
    try:
        RECORD_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(RECORD_PATH, 'a', encoding='utf-8') as f:
            f.write(json.dumps(step) + '\n')
        return True
    except Exception:
        return False

# --- Export as Markdown/HTML ---
async def export_recording(format: str = 'md') -> str:
    if not RECORD_PATH.exists():
        return '[error] No recording found'
    try:
        with open(RECORD_PATH, 'r', encoding='utf-8') as f:
            steps = [json.loads(line) for line in f]
        if format == 'md':
            out = '# Recon/Exploit Recording\n\n'
            for i, step in enumerate(steps, 1):
                out += f"## Step {i}\n```
{json.dumps(step, indent=2)}\n```
"
            return out
        elif format == 'html':
            out = '<h1>Recon/Exploit Recording</h1>'
            for i, step in enumerate(steps, 1):
                out += f'<h2>Step {i}</h2><pre>{json.dumps(step, indent=2)}</pre>'
            return out
        else:
            return '[error] Unsupported format'
    except Exception as e:
        return f'[error] {e}'

# --- Replay flow (stub, to be expanded) ---
async def replay_recording(recording: List[Dict[str, Any]], new_host: str) -> bool:
    # In real use, this would re-run each step against new_host
    await asyncio.sleep(0.1)
    return True 