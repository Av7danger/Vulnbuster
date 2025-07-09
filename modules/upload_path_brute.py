import asyncio
from typing import List, Dict, Any
import aiohttp

# --- File Upload Path Bruteforcer ---
COMMON_UPLOAD_PATHS = [
    '/uploads/', '/files/', '/images/', '/media/', '/tmp/', '/cache/',
    '/public/', '/static/', '/assets/', '/userfiles/', '/attachments/'
]

async def find_upload_path(base_url: str, filename: str) -> List[str]:
    """Find where uploaded files are accessible"""
    found_paths = []
    try:
        async with aiohttp.ClientSession() as session:
            for path in COMMON_UPLOAD_PATHS:
                test_url = f"{base_url.rstrip('/')}{path}{filename}"
                try:
                    async with session.get(test_url, timeout=5) as resp:
                        if resp.status == 200:
                            found_paths.append(test_url)
                except Exception:
                    continue
    except Exception as e:
        return [f"[error] {e}"]
    return found_paths

async def verify_file_access(url: str) -> Dict[str, Any]:
    """Verify if uploaded file is accessible and executable"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=5) as resp:
                return {
                    'accessible': resp.status == 200,
                    'status': resp.status,
                    'content_type': resp.headers.get('content-type', ''),
                    'size': len(await resp.read())
                }
    except Exception as e:
        return {'error': str(e)}

async def test_file_execution(url: str) -> bool:
    """Test if uploaded file executes (returns uname/id)"""
    # TODO: Implement real execution test
    await asyncio.sleep(0.1)
    return True  # stub 