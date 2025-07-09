import asyncio
from typing import List, Dict, Any

# --- Replay recorded steps (simulate execution, substitute new host) ---
async def replay_steps(steps: List[Dict[str, Any]], new_host: str) -> bool:
    try:
        for i, step in enumerate(steps, 1):
            # Substitute host in step if present
            step_str = str(step)
            if 'host' in step:
                step['host'] = new_host
            elif 'target' in step:
                step['target'] = new_host
            print(f"[REPLAY] Step {i}: {step}")
            await asyncio.sleep(0.05)  # Simulate execution delay
        return True
    except Exception as e:
        print(f"[REPLAY ERROR] {e}")
        return False 