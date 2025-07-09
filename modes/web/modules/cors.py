import httpx
import logging

class Module:
    def __init__(self, url, payload_engine, analyzer, verbose=False):
        self.url = url
        self.payload_engine = payload_engine
        self.analyzer = analyzer
        self.verbose = verbose
        self.findings = []

    async def run(self):
        # Test for CORS misconfigurations
        await self.test_cors_misconfig()
        return self.findings

    async def test_cors_misconfig(self):
        # Test various CORS misconfigurations
        test_origins = [
            'https://evil.com',
            'http://evil.com',
            'null',
            'https://attacker.com',
            'https://malicious.com'
        ]
        
        for origin in test_origins:
            headers = {'Origin': origin}
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    resp = await client.get(self.url, headers=headers)
                    
                    # Check Access-Control-Allow-Origin header
                    acao = resp.headers.get('Access-Control-Allow-Origin', '')
                    acac = resp.headers.get('Access-Control-Allow-Credentials', '')
                    
                    # Test for wildcard CORS
                    if acao == '*':
                        self.findings.append({
                            'type': 'CORS Misconfiguration - Wildcard',
                            'url': self.url,
                            'origin': origin,
                            'acao': acao,
                            'risk': 'high',
                            'cwe': 'CWE-942',
                            'description': 'Wildcard CORS policy allows any origin'
                        })
                    
                    # Test for null origin with credentials
                    elif acao == 'null' and acac == 'true':
                        self.findings.append({
                            'type': 'CORS Misconfiguration - Null Origin with Credentials',
                            'url': self.url,
                            'origin': origin,
                            'acao': acao,
                            'acac': acac,
                            'risk': 'high',
                            'cwe': 'CWE-942',
                            'description': 'Null origin allowed with credentials'
                        })
                    
                    # Test for reflected origin
                    elif acao == origin:
                        self.findings.append({
                            'type': 'CORS Misconfiguration - Reflected Origin',
                            'url': self.url,
                            'origin': origin,
                            'acao': acao,
                            'risk': 'medium',
                            'cwe': 'CWE-942',
                            'description': 'Origin is reflected in CORS policy'
                        })
                    
                    # Test for missing CORS headers (potential issue)
                    elif not acao and origin != 'null':
                        # Only flag if we get a 200 response (API endpoint)
                        if resp.status_code == 200:
                            self.findings.append({
                                'type': 'CORS Missing',
                                'url': self.url,
                                'origin': origin,
                                'risk': 'low',
                                'cwe': 'CWE-942',
                                'description': 'No CORS headers found'
                            })
            except Exception:
                pass 