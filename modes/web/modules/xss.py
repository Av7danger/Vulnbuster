import httpx
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
        # Test for XSS in URL parameters
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        for param in params:
            await self.test_parameter(param, params[param][0])
        return self.findings

    async def test_parameter(self, param, original_value):
        payloads = self.payload_engine.get_payloads('xss')
        for payload_data in payloads:
            payload = payload_data['payload']
            # Test reflected XSS
            if await self.test_reflected_xss(param, payload):
                self.findings.append({
                    'type': 'Reflected XSS',
                    'url': self.url,
                    'parameter': param,
                    'payload': payload,
                    'risk': payload_data.get('risk', 'high'),
                    'cwe': payload_data.get('cwe', 'CWE-79'),
                    'description': f'Reflected XSS in parameter {param}'
                })
            # Test stored XSS (basic check)
            if await self.test_stored_xss(param, payload):
                self.findings.append({
                    'type': 'Stored XSS',
                    'url': self.url,
                    'parameter': param,
                    'payload': payload,
                    'risk': payload_data.get('risk', 'high'),
                    'cwe': payload_data.get('cwe', 'CWE-79'),
                    'description': f'Potential stored XSS in parameter {param}'
                })

    async def test_reflected_xss(self, param, payload):
        # Test for reflected XSS
        test_url = self.url.replace(f'{param}={parse_qs(urlparse(self.url).query)[param][0]}', f'{param}={payload}')
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(test_url)
                # Check if payload is reflected in response
                if payload in resp.text:
                    return True
        except Exception:
            pass
        return False

    async def test_stored_xss(self, param, payload):
        # Basic stored XSS test (would need more sophisticated logic in real implementation)
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                # POST the payload to see if it gets stored
                data = {param: payload}
                resp = await client.post(self.url, data=data)
                # Check if payload appears in subsequent GET request
                get_resp = await client.get(self.url)
                if payload in get_resp.text:
                    return True
        except Exception:
            pass
        return False 