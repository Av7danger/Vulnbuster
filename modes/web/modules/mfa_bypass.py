import asyncio
import re
import time
from typing import Dict, List, Optional, Tuple, Any, Set
import httpx
from urllib.parse import urlparse, urljoin, parse_qs, urlencode

class MFAFingerprinter:
    """
    MFA Bypass Fingerprinting Module
    
    This module identifies MFA implementations and attempts to find potential bypasses.
    """
    
    def __init__(self, url: str, session: Optional[httpx.AsyncClient] = None, verbose: bool = False):
        """
        Initialize the MFA Fingerprinter.
        
        Args:
            url: The target URL to test
            session: Optional HTTP client session
            verbose: Enable verbose output
        """
        self.url = url
        self.base_url = self._get_base_url(url)
        self.session = session or httpx.AsyncClient(follow_redirects=True, timeout=30.0)
        self.verbose = verbose
        self.findings: List[Dict[str, Any]] = []
        self.mfa_endpoints: Set[str] = set()
        self.otp_patterns = [
            r'otp',
            r'mfa',
            r'2fa',
            r'two.?factor',
            r'verification',
            r'code',
            r'token',
            r'one.?time',
            r'authenticator',
            r'google.?auth',
            r'microsoft.?authenticator',
            r'authy'
        ]
        
    def _get_base_url(self, url: str) -> str:
        """Extract the base URL from a given URL."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    async def detect_mfa_flow(self) -> Dict[str, Any]:
        """
        Detect and analyze the MFA flow.
        
        Returns:
            Dict containing MFA flow analysis
        """
        result = {
            'mfa_detected': False,
            'mfa_type': None,
            'endpoints': [],
            'vulnerabilities': []
        }
        
        try:
            # First, check the login page for MFA indicators
            login_response = await self._check_login_page()
            
            if login_response and self._contains_mfa_indicators(login_response.text):
                result['mfa_detected'] = True
                result['endpoints'].append({
                    'url': self.url,
                    'type': 'login_page',
                    'indicators': self._extract_mfa_indicators(login_response.text)
                })
                
                # Look for MFA submission endpoints
                mfa_endpoints = self._find_mfa_endpoints(login_response.text)
                if mfa_endpoints:
                    result['endpoints'].extend(mfa_endpoints)
                    
                    # Test each MFA endpoint
                    for endpoint in mfa_endpoints:
                        endpoint_url = endpoint['url']
                        endpoint_analysis = await self._analyze_mfa_endpoint(endpoint_url)
                        if endpoint_analysis:
                            result['vulnerabilities'].extend(endpoint_analysis.get('vulnerabilities', []))
                            
                            if endpoint_analysis.get('mfa_type'):
                                result['mfa_type'] = endpoint_analysis['mfa_type']
                
                # Check for MFA bypass opportunities
                bypass_attempts = await self._test_bypass_techniques()
                if bypass_attempts:
                    result['vulnerabilities'].extend(bypass_attempts)
        
        except Exception as e:
            if self.verbose:
                print(f"Error during MFA detection: {str(e)}")
        
        return result
    
    async def _check_login_page(self) -> Optional[httpx.Response]:
        """Check the login page for MFA indicators."""
        try:
            response = await self.session.get(self.url)
            return response
        except Exception as e:
            if self.verbose:
                print(f"Error checking login page: {str(e)}")
            return None
    
    def _contains_mfa_indicators(self, text: str) -> bool:
        """Check if the text contains MFA indicators."""
        text_lower = text.lower()
        return any(re.search(pattern, text_lower) for pattern in self.otp_patterns)
    
    def _extract_mfa_indicators(self, text: str) -> List[str]:
        """Extract MFA indicators from text."""
        indicators = []
        for pattern in self.otp_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                indicators.append(pattern)
        return indicators
    
    def _find_mfa_endpoints(self, text: str) -> List[Dict[str, str]]:
        """Find potential MFA endpoints in the page."""
        endpoints = []
        
        # Look for forms
        form_matches = re.finditer(r'<form[^>]*action=["\']([^"\']+)["\']', text, re.IGNORECASE)
        for match in form_matches:
            action = match.group(1)
            if self._is_mfa_related(action):
                endpoints.append({
                    'url': self._resolve_url(action),
                    'type': 'form',
                    'method': self._extract_form_method(text, match.start())
                })
        
        # Look for API endpoints in JavaScript
        api_matches = re.finditer(r'["\'](?:/api/\w+|/auth/\w+|/verify/\w+)["\']', text, re.IGNORECASE)
        for match in api_matches:
            endpoint = match.group(1).strip('"\'')
            if self._is_mfa_related(endpoint):
                endpoints.append({
                    'url': self._resolve_url(endpoint),
                    'type': 'api',
                    'method': 'POST'  # Default, will be updated if found
                })
        
        return endpoints
    
    def _is_mfa_related(self, text: str) -> bool:
        """Check if text is related to MFA."""
        text_lower = text.lower()
        return any(
            any(word in text_lower for word in ['otp', 'mfa', '2fa', 'verify', 'code', 'token', 'authenticator'])
        )
    
    def _resolve_url(self, path: str) -> str:
        """Resolve a relative URL to an absolute URL."""
        if path.startswith(('http://', 'https://')):
            return path
        return urljoin(self.base_url, path)
    
    def _extract_form_method(self, text: str, form_start: int) -> str:
        """Extract the form method (defaults to POST)."""
        form_tag = text[form_start:form_start + 100]  # Look at first 100 chars of form
        method_match = re.search(r'method=["\'](\w+)["\']', form_tag, re.IGNORECASE)
        return method_match.group(1).upper() if method_match else 'POST'
    
    async def _analyze_mfa_endpoint(self, endpoint_url: str) -> Dict[str, Any]:
        """Analyze an MFA endpoint for vulnerabilities."""
        result = {
            'endpoint': endpoint_url,
            'mfa_type': None,
            'vulnerabilities': []
        }
        
        try:
            # Test with empty request
            response = await self.session.post(endpoint_url, data={})
            
            # Check for error messages that reveal MFA type
            response_text = response.text.lower()
            
            # Identify MFA type based on response
            if 'totp' in response_text or 'authenticator' in response_text:
                result['mfa_type'] = 'TOTP'
            elif 'sms' in response_text or 'text message' in response_text:
                result['mfa_type'] = 'SMS'
            elif 'push' in response_text or 'notification' in response_text:
                result['mfa_type'] = 'Push'
            else:
                result['mfa_type'] = 'Unknown'
            
            # Check for common vulnerabilities
            if response.status_code == 200 and 'invalid' not in response_text:
                result['vulnerabilities'].append({
                    'type': 'Missing Input Validation',
                    'severity': 'High',
                    'description': 'Endpoint accepts empty or malformed MFA tokens',
                    'evidence': f'Endpoint {endpoint_url} accepted an empty MFA token'
                })
                
            # Test for rate limiting
            rate_limit_result = await self._test_rate_limiting(endpoint_url)
            if rate_limit_result:
                result['vulnerabilities'].append(rate_limit_result)
                
        except Exception as e:
            if self.verbose:
                print(f"Error analyzing MFA endpoint {endpoint_url}: {str(e)}")
        
        return result
    
    async def _test_rate_limiting(self, endpoint_url: str) -> Optional[Dict[str, str]]:
        """Test for rate limiting on MFA endpoints."""
        try:
            # Send multiple rapid requests
            for _ in range(5):
                response = await self.session.post(endpoint_url, data={'code': '123456'})
                if response.status_code == 429:  # Too Many Requests
                    return None  # Rate limiting is working
                
                # Small delay between requests
                await asyncio.sleep(0.5)
            
            # If we get here, no rate limiting was detected
            return {
                'type': 'Missing Rate Limiting',
                'severity': 'Medium',
                'description': 'No rate limiting detected on MFA endpoint',
                'evidence': f'No rate limiting detected after 5 rapid requests to {endpoint_url}'
            }
            
        except Exception as e:
            if self.verbose:
                print(f"Error testing rate limiting: {str(e)}")
            return None
    
    async def _test_bypass_techniques(self) -> List[Dict[str, str]]:
        """Test various MFA bypass techniques."""
        bypass_attempts = []
        
        # Test 1: Skip MFA by directly accessing authenticated pages
        authenticated_pages = ['/dashboard', '/home', '/profile', '/account']
        for page in authenticated_pages:
            try:
                url = self._resolve_url(page)
                response = await self.session.get(url, allow_redirects=False)
                
                if response.status_code == 200:
                    bypass_attempts.append({
                        'type': 'Direct Access Bypass',
                        'severity': 'High',
                        'description': f'Able to access {url} without completing MFA',
                        'evidence': f'Successfully accessed {url} without MFA completion'
                    })
            except Exception:
                continue
        
        # Test 2: Check for MFA bypass via response manipulation
        bypass_attempts.extend(await self._test_response_manipulation())
        
        return bypass_attempts
    
    async def _test_response_manipulation(self) -> List[Dict[str, str]]:
        """Test for MFA bypass via response manipulation."""
        findings = []
        
        # Test with various modified responses
        modified_responses = [
            {'success': True},
            {'verified': True},
            {'status': 'success'},
            {'mfa_verified': True},
            {'two_factor_authenticated': True}
        ]
        
        for modified in modified_responses:
            try:
                # Try to find an MFA verification endpoint
                for endpoint in self.mfa_endpoints:
                    if endpoint['type'] == 'api':
                        # Try with modified response
                        response = await self.session.post(
                            endpoint['url'],
                            json=modified,
                            headers={'Content-Type': 'application/json'}
                        )
                        
                        # Check if the response indicates success
                        if response.status_code == 200 and 'success' in response.text.lower():
                            findings.append({
                                'type': 'Response Manipulation',
                                'severity': 'High',
                                'description': 'Possible MFA bypass via response manipulation',
                                'evidence': f'Modified response accepted by {endpoint["url"]} with {modified}'
                            })
            except Exception as e:
                if self.verbose:
                    print(f"Error testing response manipulation: {str(e)}")
        
        return findings
    
    async def close(self):
        """Clean up resources."""
        if self.session and not self.session.is_closed:
            await self.session.aclose()
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()


async def test_mfa_bypass(url: str, verbose: bool = False) -> Dict[str, Any]:
    ""
    Test for MFA bypass vulnerabilities.
    
    Args:
        url: The target URL to test
        verbose: Enable verbose output
        
    Returns:
        Dict containing test results
    """
    async with MFAFingerprinter(url, verbose=verbose) as fingerprinter:
        return await fingerprinter.detect_mfa_flow()


if __name__ == "__main__":
    import sys
    import json
    
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <url>")
        sys.exit(1)
    
    url = sys.argv[1]
    
    async def main():
        results = await test_mfa_bypass(url, verbose=True)
        print(json.dumps(results, indent=2))
    
    asyncio.run(main())
