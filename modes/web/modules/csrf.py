import httpx
import logging
from bs4 import BeautifulSoup, Tag

class Module:
    def __init__(self, url, payload_engine, analyzer, verbose=False):
        self.url = url
        self.payload_engine = payload_engine
        self.analyzer = analyzer
        self.verbose = verbose
        self.findings = []

    async def run(self):
        # Test for CSRF vulnerabilities
        await self.test_csrf_token_absence()
        await self.test_csrf_token_weakness()
        return self.findings

    async def test_csrf_token_absence(self):
        # Test if CSRF token is missing from forms
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(self.url)
                soup = BeautifulSoup(resp.text, 'lxml')
                
                for form in soup.find_all('form'):
                    if isinstance(form, Tag):
                        method = form.get('method')
                        if isinstance(method, str) and method.lower() == 'post':
                            # Check if CSRF token is present
                            csrf_inputs = form.find_all('input', {'name': lambda x: bool(x and 'csrf' in x.lower())})
                            if not csrf_inputs:
                                self.findings.append({
                                    'type': 'CSRF',
                                    'url': self.url,
                                    'form_action': form.get('action'),
                                    'risk': 'high',
                                    'cwe': 'CWE-352',
                                    'description': 'CSRF token missing from form'
                                })
        except Exception:
            pass

    async def test_csrf_token_weakness(self):
        # Test for weak CSRF tokens
        weak_tokens = ['123456', 'admin', 'token', 'csrf', 'secret']
        
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(self.url)
                soup = BeautifulSoup(resp.text, 'lxml')
                
                for form in soup.find_all('form'):
                    if isinstance(form, Tag):
                        method = form.get('method')
                        if isinstance(method, str) and method.lower() == 'post':
                            for token in weak_tokens:
                                # Try to submit form with weak token
                                form_data = {}
                                for inp in form.find_all('input'):
                                    if isinstance(inp, Tag):
                                        name = inp.get('name')
                                        if isinstance(name, str) and 'csrf' in name.lower():
                                            form_data[name] = token
                                        elif isinstance(name, str):
                                            form_data[name] = inp.get('value', '')
                                
                                if form_data:
                                    try:
                                        action = form.get('action')
                                        post_url = str(action) if action else self.url
                                        post_resp = await client.post(post_url, data=form_data)
                                        if post_resp.status_code == 200:
                                            self.findings.append({
                                                'type': 'Weak CSRF Token',
                                                'url': self.url,
                                                'token_used': token,
                                                'risk': 'medium',
                                                'cwe': 'CWE-352',
                                                'description': f'Weak CSRF token accepted: {token}'
                                            })
                                    except Exception:
                                        pass
        except Exception:
            pass 