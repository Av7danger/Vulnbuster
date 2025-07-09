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
        # Test for DOM XSS in URL parameters
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        for param in params:
            await self.test_parameter(param, params[param][0])
        return self.findings

    async def test_parameter(self, param, original_value):
        # Test DOM XSS payloads
        dom_xss_payloads = [
            # DOM sinks
            '<script>alert(1)</script>',
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            # DOM manipulation
            '"><script>alert(1)</script>',
            '\'><script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
            # JavaScript injection
            '";alert(1);//',
            '\';alert(1);//',
            '`+alert(1)+`',
            # Event handlers
            'onload=alert(1)',
            'onerror=alert(1)',
            'onclick=alert(1)',
            'onmouseover=alert(1)'
        ]
        
        for payload in dom_xss_payloads:
            if await self.test_dom_xss(param, payload):
                self.findings.append({
                    'type': 'DOM-based XSS',
                    'url': self.url,
                    'parameter': param,
                    'payload': payload,
                    'risk': 'high',
                    'cwe': 'CWE-79',
                    'description': f'DOM XSS in parameter {param}'
                })

    async def test_dom_xss(self, param, payload):
        # Test for DOM XSS
        test_url = self.url.replace(f'{param}={parse_qs(urlparse(self.url).query)[param][0]}', f'{param}={payload}')
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(test_url)
                
                # Check for DOM XSS indicators
                dom_indicators = [
                    'document.write',
                    'innerhtml',
                    'outerhtml',
                    'eval(',
                    'settimeout',
                    'setinterval',
                    'location.href',
                    'location.hash',
                    'location.search',
                    'window.open',
                    'document.cookie',
                    'localstorage',
                    'sessionstorage'
                ]
                
                # Check if payload is in JavaScript context
                if payload in resp.text:
                    for indicator in dom_indicators:
                        if indicator in resp.text.lower():
                            return True
                
                # Check for URL-based DOM XSS
                if 'location.hash' in resp.text or 'location.search' in resp.text:
                    if param in resp.text:
                        return True
        except Exception:
            pass
        return False 