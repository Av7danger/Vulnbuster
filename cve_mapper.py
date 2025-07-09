import asyncio
import re
import json
from typing import List, Dict, Any
from pathlib import Path

# --- Real CPE Extraction ---
CPE_REGEXES = [
    (r'Apache/?([\d.]+)?', 'cpe:/a:apache:http_server:{}'),
    (r'PHP/?([\d.]+)?', 'cpe:/a:php:php:{}'),
    (r'OpenSSL/?([\d.]+)?', 'cpe:/a:openssl:openssl:{}'),
    (r'nginx/?([\d.]+)?', 'cpe:/a:nginx:nginx:{}'),
    (r'Ubuntu/?([\d.]+)?', 'cpe:/o:canonical:ubuntu_linux:{}'),
    # Add more as needed
]

def _extract_cpes_from_header(header_val: str) -> List[str]:
    cpes = []
    for regex, cpe_fmt in CPE_REGEXES:
        m = re.search(regex, header_val, re.I)
        if m:
            version = m.group(1) or 'any'
            cpes.append(cpe_fmt.format(version))
    return cpes

async def extract_cpes(headers: Dict[str, str]) -> List[str]:
    cpes = []
    for k, v in headers.items():
        cpes.extend(_extract_cpes_from_header(v))
    return list(set(cpes))

# --- Real CVE Matching ---
NVD_PATH = Path('nvd_data/nvdcve-1.1-recent.json')

async def match_cves(cpes: List[str]) -> List[str]:
    cves = []
    if not NVD_PATH.exists():
        return ['[error] NVD database not found']
    try:
        with open(NVD_PATH, 'r', encoding='utf-8') as f:
            nvd = json.load(f)
        for item in nvd.get('CVE_Items', []):
            nodes = item.get('configurations', {}).get('nodes', [])
            for node in nodes:
                for cpe_match in node.get('cpe_match', []):
                    for cpe in cpes:
                        if cpe in cpe_match.get('cpe23Uri', ''):
                            cves.append(item['cve']['CVE_data_meta']['ID'])
        return list(set(cves))
    except Exception as e:
        return [f'[error] {e}']

# --- AI PoC Prompt ---
AI_POC_PROMPT = (
    "You are an expert exploit developer. Given a CVE ID, generate a working proof-of-concept (PoC) exploit. "
    "If possible, output the exploit as Python, Bash, or cURL. "
    "If the CVE is not exploitable, explain why. Output only the code or explanation.\n"
    "Example: CVE-2019-11043 (PHP-FPM RCE) => output a Python exploit script."
)

async def ai_generate_poc(cve: str) -> str:
    # TODO: Integrate with Mixtral or LLM for PoC generation
    # Use AI_POC_PROMPT as the system/user prompt
    await asyncio.sleep(0.1)
    return f"[AI] PoC for {cve} (prompt: {AI_POC_PROMPT[:60]}...)" 