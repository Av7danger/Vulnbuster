import httpx
import logging
import re
from urllib.parse import urlencode, parse_qs, urlparse, quote_plus
from typing import Dict, List, Optional, Tuple, Any

class Module:
    def __init__(self, url, payload_engine, analyzer, verbose=False):
        self.url = url
        self.payload_engine = payload_engine
        self.analyzer = analyzer
        self.verbose = verbose
        self.findings = []

    async def run(self):
        # Test for XSS in URL parameters
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        
        # Test URL parameters
        for param in params:
            await self.test_parameter(param, params[param][0])
            
        # Test for DOM-based XSS in URL fragments
        if parsed.fragment:
            await self.test_dom_based_xss(parsed.fragment)
            
        return self.findings

    async def test_parameter(self, param, original_value):
        payloads = self.payload_engine.get_payloads('xss')
        for payload_data in payloads:
            payload = payload_data['payload']
            # Test reflected XSS
            if await self.test_reflected_xss(param, payload):
                self.findings.append({
                    'type': 'Reflected XSS',
                    'url': self.url,
                    'parameter': param,
                    'payload': payload,
                    'risk': payload_data.get('risk', 'high'),
                    'cwe': payload_data.get('cwe', 'CWE-79'),
                    'description': f'Reflected XSS in parameter {param}'
                })
            # Test stored XSS (basic check)
            if await self.test_stored_xss(param, payload):
                self.findings.append({
                    'type': 'Stored XSS',
                    'url': self.url,
                    'parameter': param,
                    'payload': payload,
                    'risk': payload_data.get('risk', 'high'),
                    'cwe': payload_data.get('cwe', 'CWE-79'),
                    'description': f'Potential stored XSS in parameter {param}'
                })

    async def test_reflected_xss(self, param: str, payload: str) -> bool:
        """Test for reflected XSS vulnerabilities.
        
        Args:
            param: The parameter to test
            payload: The XSS payload to inject
            
        Returns:
            bool: True if reflected XSS is detected, False otherwise
        """
        parsed = urlparse(self.url)
        query = parse_qs(parsed.query, keep_blank_values=True)
        
        # Encode the payload for URL safety
        encoded_payload = quote_plus(payload)
        
        # Update the parameter with our payload
        query[param] = [payload]
        
        # Rebuild the URL with the modified query
        new_query = urlencode(query, doseq=True)
        test_url = parsed._replace(query=new_query).geturl()
        
        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
                # First, test with the original method (direct reflection)
                resp = await client.get(test_url)
                response_text = resp.text
                
                # Check for direct reflection
                if payload in response_text:
                    return True
                    
                # Check for DOM-based XSS patterns
                if self._check_dom_xss_patterns(response_text, payload):
                    return True
                    
        except Exception as e:
            if self.verbose:
                logging.error(f"Error testing reflected XSS on {param}: {str(e)}")
                
        return False

    async def test_stored_xss(self, param: str, payload: str) -> bool:
        """Test for stored XSS vulnerabilities.
        
        Args:
            param: The parameter to test
            payload: The XSS payload to inject
            
        Returns:
            bool: True if stored XSS is detected, False otherwise
        """
        try:
            async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
                # Test with different content types
                for content_type in [
                    None,  # Default form data
                    'application/json',
                    'application/x-www-form-urlencoded',
                    'multipart/form-data'
                ]:
                    headers = {}
                    if content_type:
                        headers['Content-Type'] = content_type
                    
                    # Test with different HTTP methods
                    for method in ['POST', 'PUT', 'PATCH']:
                        try:
                            # Test with the current method and content type
                            data = {param: payload}
                            if content_type == 'application/json':
                                response = await client.request(
                                    method, 
                                    self.url,
                                    json=data,
                                    headers=headers
                                )
                            else:
                                response = await client.request(
                                    method,
                                    self.url,
                                    data=data,
                                    headers=headers
                                )
                            
                            # Check if the payload was stored
                            get_response = await client.get(self.url)
                            if payload in get_response.text or self._check_dom_xss_patterns(get_response.text, payload):
                                return True
                                
                        except Exception as e:
                            if self.verbose:
                                logging.warning(f"Error with {method} {content_type}: {str(e)}")
                                
        except Exception as e:
            if self.verbose:
                logging.error(f"Error in stored XSS test: {str(e)}")
                
        return False
        
    async def test_dom_based_xss(self, fragment: str) -> None:
        """Test for DOM-based XSS vulnerabilities in URL fragments.
        
        Args:
            fragment: The URL fragment to test
        """
        dom_payloads = self.payload_engine.get_payloads('dom_xss')
        
        for payload_data in dom_payloads:
            payload = payload_data['payload']
            test_url = f"{self.url.split('#')[0]}#{fragment}{payload}"
            
            try:
                async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
                    response = await client.get(test_url)
                    
                    # Check for DOM XSS indicators
                    if self._check_dom_xss_patterns(response.text, payload):
                        self.findings.append({
                            'type': 'DOM-based XSS',
                            'url': test_url,
                            'payload': payload,
                            'risk': payload_data.get('risk', 'high'),
                            'cwe': payload_data.get('cwe', 'CWE-79'),
                            'description': f'DOM-based XSS in URL fragment with payload: {payload}'
                        })
                        
            except Exception as e:
                if self.verbose:
                    logging.error(f"Error testing DOM XSS: {str(e)}")
    
    def _check_dom_xss_patterns(self, response_text: str, payload: str) -> bool:
        """Check for common DOM XSS patterns in the response.
        
        Args:
            response_text: The response text to analyze
            payload: The payload that was injected
            
        Returns:
            bool: True if DOM XSS patterns are found, False otherwise
        """
        # Check for common DOM XSS sinks
        dom_sinks = [
            r'document\.write\s*\('
            r'document\.writeln\s*\('
            r'document\.open\s*\('
            r'window\.location\s*='
            r'document\.location\s*='
            r'window\.open\s*\('
            r'eval\s*\('
            r'setTimeout\s*\('
            r'setInterval\s*\('
            r'Function\s*\('
            r'innerHTML\s*='
            r'outerHTML\s*='
            r'insertAdjacentHTML\s*\('
            r'createContextualFragment\s*\('
        ]
        
        # Check if any sink is used with our payload
        for pattern in dom_sinks:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
                
        # Check for direct script injection
        script_pattern = fr'<script[^>]*>.*{re.escape(payload)}.*</script>'
        if re.search(script_pattern, response_text, re.IGNORECASE | re.DOTALL):
            return True
            
        # Check for event handlers
        event_handlers = [
            'onload', 'onerror', 'onclick', 'onmouseover', 'onmouseout',
            'onmousedown', 'onmouseup', 'onkeydown', 'onkeyup', 'onkeypress',
            'onchange', 'onsubmit', 'onreset', 'onselect', 'onblur',
            'onfocus', 'onabort', 'ondblclick', 'onmousemove', 'onmouseenter',
            'onmouseleave', 'onmousewheel', 'onwheel', 'oncopy', 'oncut',
            'onpaste', 'oncontextmenu'
        ]
        
        for handler in event_handlers:
            if f"{handler}=\"" in response_text and payload in response_text:
                return True
                
        return False