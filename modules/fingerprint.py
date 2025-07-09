import asyncio
from typing import Dict, Any
import aiohttp
import hashlib
import ssl
import socket

# --- Screenshot + Fingerprint Module ---
async def take_html_screenshot(url: str) -> Dict[str, Any]:
    """Take HTML screenshot of target"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=10) as resp:
                html = await resp.text()
                return {
                    'url': url,
                    'html_length': len(html),
                    'title': _extract_title(html),
                    'status': resp.status
                }
    except Exception as e:
        return {'error': str(e)}

def _extract_title(html: str) -> str:
    """Extract title from HTML"""
    import re
    match = re.search(r'<title>(.*?)</title>', html, re.I)
    return match.group(1) if match else 'No title'

async def get_favicon_hash(url: str) -> str:
    """Get favicon hash for fingerprinting"""
    try:
        favicon_url = f"{url.rstrip('/')}/favicon.ico"
        async with aiohttp.ClientSession() as session:
            async with session.get(favicon_url, timeout=5) as resp:
                if resp.status == 200:
                    content = await resp.read()
                    return hashlib.md5(content).hexdigest()
        return 'no_favicon'
    except Exception:
        return 'error'

async def dump_tls_cert(host: str, port: int = 443) -> Dict[str, Any]:
    """Dump TLS certificate information"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return {
                    'subject': dict(x[0] for x in cert['subject']),
                    'issuer': dict(x[0] for x in cert['issuer']),
                    'version': cert['version'],
                    'serial_number': cert['serialNumber'],
                    'not_before': cert['notBefore'],
                    'not_after': cert['notAfter']
                }
    except Exception as e:
        return {'error': str(e)}

async def fingerprint_target(url: str) -> Dict[str, Any]:
    """Complete fingerprint of target"""
    host = url.split('://')[1].split('/')[0]
    return {
        'screenshot': await take_html_screenshot(url),
        'favicon_hash': await get_favicon_hash(url),
        'tls_cert': await dump_tls_cert(host)
    } 