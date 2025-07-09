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
        # Test for Host header injection
        await self.test_host_header_injection()
        await self.test_x_forwarded_host_injection()
        return self.findings

    async def test_host_header_injection(self):
        # Test Host header injection
        malicious_hosts = [
            'evil.com',
            'attacker.com',
            'malicious.com',
            'localhost',
            '127.0.0.1',
            '0.0.0.0',
            'internal-service.local',
            'admin.internal'
        ]
        
        for host in malicious_hosts:
            headers = {'Host': host}
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    resp = await client.get(self.url, headers=headers)
                    
                    # Check if the malicious host is reflected in response
                    if host in resp.text:
                        self.findings.append({
                            'type': 'Host Header Injection',
                            'url': self.url,
                            'header': 'Host',
                            'value': host,
                            'risk': 'medium',
                            'cwe': 'CWE-113',
                            'description': f'Host header injection with {host}'
                        })
                    
                    # Check for cache poisoning indicators
                    if 'cache' in resp.headers or 'cdn' in resp.headers:
                        self.findings.append({
                            'type': 'Potential Cache Poisoning',
                            'url': self.url,
                            'header': 'Host',
                            'value': host,
                            'risk': 'high',
                            'cwe': 'CWE-113',
                            'description': f'Potential cache poisoning with {host}'
                        })
            except Exception:
                pass

    async def test_x_forwarded_host_injection(self):
        # Test X-Forwarded-Host header injection
        malicious_hosts = [
            'evil.com',
            'attacker.com',
            'malicious.com',
            'localhost',
            '127.0.0.1'
        ]
        
        for host in malicious_hosts:
            headers = {'X-Forwarded-Host': host}
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    resp = await client.get(self.url, headers=headers)
                    
                    # Check if the malicious host is reflected in response
                    if host in resp.text:
                        self.findings.append({
                            'type': 'X-Forwarded-Host Injection',
                            'url': self.url,
                            'header': 'X-Forwarded-Host',
                            'value': host,
                            'risk': 'medium',
                            'cwe': 'CWE-113',
                            'description': f'X-Forwarded-Host injection with {host}'
                        })
            except Exception:
                pass 