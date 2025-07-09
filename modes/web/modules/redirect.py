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
        # Test for open redirects in URL parameters
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        for param in params:
            await self.test_parameter(param, params[param][0])
        return self.findings

    async def test_parameter(self, param, original_value):
        # Test redirect payloads
        redirect_payloads = [
            'https://evil.com',
            'http://evil.com',
            '//evil.com',
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            'https://google.com',
            'https://bing.com',
            'https://yahoo.com'
        ]
        
        for payload in redirect_payloads:
            if await self.test_redirect(param, payload):
                self.findings.append({
                    'type': 'Open Redirect',
                    'url': self.url,
                    'parameter': param,
                    'payload': payload,
                    'risk': 'medium',
                    'cwe': 'CWE-601',
                    'description': f'Open redirect in parameter {param}'
                })

    async def test_redirect(self, param, payload):
        # Test for open redirect
        test_url = self.url.replace(f'{param}={parse_qs(urlparse(self.url).query)[param][0]}', f'{param}={payload}')
        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
                resp = await client.get(test_url)
                # Check for redirect status codes
                if resp.status_code in [301, 302, 303, 307, 308]:
                    # Check if Location header contains our payload
                    location = resp.headers.get('Location', '')
                    if payload in location:
                        return True
                # Also check for meta refresh redirects
                if 'refresh' in resp.text.lower() and payload in resp.text:
                    return True
        except Exception:
            pass
        return False 