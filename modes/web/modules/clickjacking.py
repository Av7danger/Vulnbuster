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
        # Test for clickjacking vulnerabilities
        await self.test_clickjacking()
        return self.findings

    async def test_clickjacking(self):
        # Test for clickjacking vulnerabilities
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(self.url)
                
                # Check for X-Frame-Options header
                xfo = resp.headers.get('X-Frame-Options', '')
                csp = resp.headers.get('Content-Security-Policy', '')
                
                # Test for missing X-Frame-Options
                if not xfo:
                    self.findings.append({
                        'type': 'Clickjacking - Missing X-Frame-Options',
                        'url': self.url,
                        'risk': 'medium',
                        'cwe': 'CWE-1021',
                        'description': 'X-Frame-Options header is missing'
                    })
                
                # Test for weak X-Frame-Options
                elif xfo.lower() == 'allowall':
                    self.findings.append({
                        'type': 'Clickjacking - Weak X-Frame-Options',
                        'url': self.url,
                        'xfo': xfo,
                        'risk': 'high',
                        'cwe': 'CWE-1021',
                        'description': f'Weak X-Frame-Options value: {xfo}'
                    })
                
                # Test for missing CSP frame-ancestors
                if not csp or 'frame-ancestors' not in csp:
                    self.findings.append({
                        'type': 'Clickjacking - Missing CSP frame-ancestors',
                        'url': self.url,
                        'csp': csp,
                        'risk': 'medium',
                        'cwe': 'CWE-1021',
                        'description': 'Content-Security-Policy frame-ancestors directive missing'
                    })
                
                # Test for weak CSP frame-ancestors
                elif 'frame-ancestors *' in csp:
                    self.findings.append({
                        'type': 'Clickjacking - Weak CSP frame-ancestors',
                        'url': self.url,
                        'csp': csp,
                        'risk': 'high',
                        'cwe': 'CWE-1021',
                        'description': 'Weak CSP frame-ancestors allows all origins'
                    })
                
                # Check if page contains sensitive actions (forms, buttons)
                if 'form' in resp.text.lower() or 'button' in resp.text.lower():
                    if not xfo and not ('frame-ancestors' in csp):
                        self.findings.append({
                            'type': 'Clickjacking - High Risk',
                            'url': self.url,
                            'risk': 'high',
                            'cwe': 'CWE-1021',
                            'description': 'Page contains forms/buttons but lacks clickjacking protection'
                        })
        except Exception:
            pass 