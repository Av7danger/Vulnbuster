import httpx
import logging
import os

class Module:
    def __init__(self, url, payload_engine, analyzer, verbose=False):
        self.url = url
        self.payload_engine = payload_engine
        self.analyzer = analyzer
        self.verbose = verbose
        self.findings = []

    async def run(self):
        # Test for file upload vulnerabilities
        await self.test_extension_bypass()
        await self.test_mime_bypass()
        await self.test_null_byte_injection()
        return self.findings

    async def test_extension_bypass(self):
        # Test various extension bypass techniques
        bypass_payloads = [
            ('test.php', 'test.php.jpg'),
            ('shell.php', 'shell.php.png'),
            ('cmd.php', 'cmd.php.gif'),
            ('test.php', 'test.php%00.jpg'),
            ('shell.php', 'shell.php;.jpg'),
            ('cmd.php', 'cmd.php..jpg')
        ]
        
        for original, bypass in bypass_payloads:
            try:
                # Create a simple PHP payload
                php_content = '<?php echo "test"; ?>'
                files = {'file': (bypass, php_content, 'image/jpeg')}
                
                async with httpx.AsyncClient(timeout=10) as client:
                    resp = await client.post(self.url, files=files)
                    if resp.status_code == 200:
                        self.findings.append({
                            'type': 'File Upload - Extension Bypass',
                            'url': self.url,
                            'payload': bypass,
                            'risk': 'high',
                            'cwe': 'CWE-434',
                            'description': f'Extension bypass with {bypass}'
                        })
            except Exception:
                pass

    async def test_mime_bypass(self):
        # Test MIME type bypass
        mime_bypasses = [
            ('shell.php', 'image/jpeg'),
            ('cmd.php', 'image/png'),
            ('test.php', 'image/gif'),
            ('shell.php', 'text/plain')
        ]
        
        for filename, mime_type in mime_bypasses:
            try:
                php_content = '<?php echo "test"; ?>'
                files = {'file': (filename, php_content, mime_type)}
                
                async with httpx.AsyncClient(timeout=10) as client:
                    resp = await client.post(self.url, files=files)
                    if resp.status_code == 200:
                        self.findings.append({
                            'type': 'File Upload - MIME Bypass',
                            'url': self.url,
                            'payload': f'{filename} with {mime_type}',
                            'risk': 'high',
                            'cwe': 'CWE-434',
                            'description': f'MIME bypass with {filename} as {mime_type}'
                        })
            except Exception:
                pass

    async def test_null_byte_injection(self):
        # Test null byte injection in filenames
        null_byte_payloads = [
            'test.php%00.jpg',
            'shell.php%00.png',
            'cmd.php%00.gif'
        ]
        
        for payload in null_byte_payloads:
            try:
                php_content = '<?php echo "test"; ?>'
                files = {'file': (payload, php_content, 'image/jpeg')}
                
                async with httpx.AsyncClient(timeout=10) as client:
                    resp = await client.post(self.url, files=files)
                    if resp.status_code == 200:
                        self.findings.append({
                            'type': 'File Upload - Null Byte Injection',
                            'url': self.url,
                            'payload': payload,
                            'risk': 'high',
                            'cwe': 'CWE-434',
                            'description': f'Null byte injection with {payload}'
                        })
            except Exception:
                pass 