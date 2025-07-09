import asyncio
from typing import Dict, Any
import os
import re

# --- Detect ELF/PE ---
async def detect_binary_type(path: str) -> str:
    try:
        with open(path, 'rb') as f:
            magic = f.read(4)
            if magic.startswith(b'\x7fELF'):
                return 'ELF'
            elif magic[:2] == b'MZ':
                return 'PE'
            else:
                return 'Unknown'
    except Exception as e:
        return f'Error: {e}'

# --- Find Vulns: Buffer Overflows, SUID/SGID, Dangerous Functions ---
DANGEROUS_FUNCS = [b'strcpy', b'strcat', b'gets', b'sprintf', b'scanf', b'gets_s', b'getwd']

async def find_vulns(path: str) -> Dict[str, Any]:
    vulns = {'buffer_overflow': False, 'suid': False, 'sgid': False, 'dangerous_funcs': []}
    try:
        # SUID/SGID
        st = os.stat(path)
        vulns['suid'] = bool(st.st_mode & 0o4000)
        vulns['sgid'] = bool(st.st_mode & 0o2000)
        # Dangerous functions
        with open(path, 'rb') as f:
            data = f.read()
            for func in DANGEROUS_FUNCS:
                if func in data:
                    vulns['dangerous_funcs'].append(func.decode())
                    vulns['buffer_overflow'] = True
    except Exception as e:
        vulns['error'] = str(e)
    return vulns

# --- AI ROP Chain Suggestion remains as stub (prompt in ai_gadget_suggester.py) ---
async def ai_rop_chain(path: str) -> str:
    await asyncio.sleep(0.1)
    return '[AI] ROP chain for binary (stub)' 