import asyncio
from typing import Dict, Any
import base64
import json

# --- JWT Analyzer + Forger ---
async def parse_jwt(token: str) -> Dict[str, Any]:
    """Parse JWT token and return header, payload, signature"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return {'error': 'Invalid JWT format'}
        
        header = json.loads(base64.urlsafe_b64decode(parts[0] + '==').decode())
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + '==').decode())
        
        return {
            'header': header,
            'payload': payload,
            'signature': parts[2]
        }
    except Exception as e:
        return {'error': str(e)}

async def detect_alg_none(token: str) -> bool:
    """Detect if JWT uses 'alg: none' (vulnerable)"""
    try:
        parsed = await parse_jwt(token)
        if 'error' in parsed:
            return False
        return parsed['header'].get('alg') == 'none'
    except Exception:
        return False

async def forge_jwt(header: Dict[str, Any], payload: Dict[str, Any], secret: str = '') -> str:
    """Forge a new JWT token"""
    try:
        # TODO: Implement real JWT signing
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        signature = 'forged_signature'  # TODO: Real signature
        return f"{header_b64}.{payload_b64}.{signature}"
    except Exception as e:
        return f"[error] {e}"

async def modify_jwt_payload(token: str, new_payload: Dict[str, Any]) -> str:
    """Modify JWT payload (requires re-signing)"""
    try:
        parsed = await parse_jwt(token)
        if 'error' in parsed:
            return parsed['error']
        
        # Merge new payload with existing
        merged_payload = {**parsed['payload'], **new_payload}
        return await forge_jwt(parsed['header'], merged_payload)
    except Exception as e:
        return f"[error] {e}" 