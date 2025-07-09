import asyncio
import socket
from typing import List, Dict, Any

# Passive detection: parse headers for common service info
async def passive_service_detect(headers: Dict[str, str]) -> List[str]:
    services = []
    server = headers.get('Server')
    if server:
        services.append(server)
    powered_by = headers.get('X-Powered-By')
    if powered_by:
        services.append(powered_by)
    via = headers.get('Via')
    if via:
        services.append(via)
    return services if services else ['unknown']

# Active port scan with async TCP connect and banner grab
def _grab_banner(host: str, port: int, timeout: float = 2.0) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                banner = sock.recv(1024)
                return banner.decode(errors='ignore').strip()
            except Exception:
                return ''
    except Exception:
        return ''

async def active_port_scan(host: str, ports: List[int]) -> List[Dict[str, Any]]:
    loop = asyncio.get_event_loop()
    tasks = []
    for port in ports:
        tasks.append(loop.run_in_executor(None, _grab_banner, host, port))
    banners = await asyncio.gather(*tasks)
    results = []
    for port, banner in zip(ports, banners):
        results.append({'port': port, 'banner': banner or 'no banner'})
    return results

# AI CVE suggestion stub remains (to be improved in ai prompt tuning step)
async def ai_cve_suggest(service: str, version: str) -> List[str]:
    await asyncio.sleep(0.1)
    return [f"[AI] Likely CVEs for {service} {version} (stub)"] 