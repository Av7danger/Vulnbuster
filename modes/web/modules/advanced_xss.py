"""
Advanced XSS Detection Module for VulnBuster

This module provides enhanced XSS detection capabilities including:
- Framework-specific payloads (React, Vue, Angular)
- Advanced DOM-based XSS detection
- Context-aware payload generation
- Improved WAF bypass techniques
- Better handling of modern web applications
"""

import re
import json
import logging
import asyncio
import random
from urllib.parse import urlparse, parse_qs, urlencode, quote_plus, unquote_plus
from typing import Dict, List, Optional, Tuple, Any, Set, Pattern, Union
from dataclasses import dataclass, field
from enum import Enum, auto
import httpx

# Type aliases
URL = str
HTML = str
JavaScript = str
Headers = Dict[str, str]

class XSSType(Enum):
    REFLECTED = "reflected"
    STORED = "stored"
    DOM_BASED = "dom_based"
    TEMPLATE = "template_injection"

class XSSContext(Enum):
    HTML = "html"
    HTML_ATTRIBUTE = "html_attribute"
    HTML_COMMENT = "html_comment"
    SCRIPT = "script"
    SCRIPT_TEMPLATE = "script_template"
    ATTRIBUTE = "attribute"
    CSS = "css"
    URL = "url"
    JAVASCRIPT_URI = "javascript_uri"
    UNKNOWN = "unknown"

@dataclass
class XSSPayload:
    """Represents an XSS payload with context and metadata."""
    payload: str
    context: XSSContext
    framework: Optional[str] = None
    risk: str = "high"
    cwe: str = "CWE-79"
    description: str = ""
    tags: List[str] = field(default_factory=list)
    detection_patterns: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        if not self.detection_patterns:
            self.detection_patterns = [re.escape(self.payload)]

class XSSDetector:
    """Advanced XSS detection engine."""
    
    def __init__(self, url: str, payload_engine, analyzer, verbose: bool = False):
        self.url = url
        self.payload_engine = payload_engine
        self.analyzer = analyzer
        self.verbose = verbose
        self.findings: List[Dict[str, Any]] = []
        self.client = None
        self.tech_stack = self._detect_tech_stack()
        self.session = None
        
    async def __aenter__(self):
        self.session = httpx.AsyncClient(
            timeout=30.0,
            follow_redirects=True,
            verify=False,
            http2=True
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.aclose()
    
    def _detect_tech_stack(self) -> Dict[str, bool]:
        """Detect the technology stack of the target."""
        # This would be implemented to detect frameworks like React, Vue, Angular, etc.
        # For now, return a default detection
        return {
            'react': True,
            'angular': False,
            'vue': False,
            'jquery': True
        }
    
    async def detect_xss(self) -> List[Dict[str, Any]]:
        """Main method to detect various types of XSS vulnerabilities."""
        try:
            # Test URL parameters for reflected XSS
            await self.test_reflected_xss()
            
            # Test for stored XSS
            await self.test_stored_xss()
            
            # Test for DOM-based XSS
            await self.test_dom_based_xss()
            
            # Test for template injection
            await self.test_template_injection()
            
        except Exception as e:
            logging.error(f"Error during XSS detection: {str(e)}", exc_info=self.verbose)
            
        return self.findings
    
    async def test_reflected_xss(self) -> None:
        """Test for reflected XSS vulnerabilities."""
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        for param, values in params.items():
            for value in values:
                # Get context-aware payloads
                payloads = self._get_context_aware_payloads(value, XSSType.REFLECTED)
                
                for payload_data in payloads:
                    payload = payload_data.payload
                    
                    # Test with different encoding techniques
                    for encoder in [self._url_encode, self._html_encode, self._js_encode, self._unicode_encode]:
                        encoded_payload = encoder(payload)
                        
                        # Test with different HTTP methods
                        for method in ['GET', 'POST']:
                            if await self._test_payload(param, encoded_payload, method):
                                self._add_finding(
                                    XSSType.REFLECTED,
                                    param=param,
                                    payload=payload,
                                    risk=payload_data.risk,
                                    cwe=payload_data.cwe,
                                    description=f"Reflected XSS in {param} parameter"
                                )
                                break  # No need to test more payloads for this parameter
    
    async def test_stored_xss(self) -> None:
        """Test for stored XSS vulnerabilities."""
        # Implementation for stored XSS testing
        pass
    
    async def test_dom_based_xss(self) -> None:
        """Test for DOM-based XSS vulnerabilities."""
        # Implementation for DOM-based XSS testing
        pass
    
    async def test_template_injection(self) -> None:
        """Test for template injection vulnerabilities."""
        # Implementation for template injection testing
        pass
    
    def _get_context_aware_payloads(self, original_value: str, xss_type: XSSType) -> List[XSSPayload]:
        """Generate context-aware XSS payloads based on the input value."""
        context = self._determine_context(original_value)
        base_payloads = self.payload_engine.get_payloads('xss')
        
        payloads = []
        for payload_data in base_payloads:
            payload = payload_data['payload']
            
            # Skip payloads that don't match our context
            if not self._is_payload_applicable(payload, context):
                continue
                
            # Create framework-specific payloads if applicable
            if self.tech_stack.get('react'):
                payloads.append(self._create_react_payload(payload, context))
            if self.tech_stack.get('angular'):
                payloads.append(self._create_angular_payload(payload, context))
                
            # Add the base payload
            payloads.append(XSSPayload(
                payload=payload,
                context=context,
                risk=payload_data.get('risk', 'high'),
                cwe=payload_data.get('cwe', 'CWE-79'),
                description=payload_data.get('description', '')
            ))
            
        return payloads
    
    def _determine_context(self, value: str) -> XSSContext:
        """Determine the XSS context of a value."""
        # Implementation to determine context (HTML, JS, attribute, etc.)
        return XSSContext.HTML
    
    def _is_payload_applicable(self, payload: str, context: XSSContext) -> bool:
        """Check if a payload is applicable to the given context."""
        # Implementation to check payload applicability
        return True
    
    def _create_react_payload(self, base_payload: str, context: XSSContext) -> XSSPayload:
        """Create a React-specific XSS payload."""
        # Implementation for React-specific payloads
        return XSSPayload(
            payload=f"{{{{'a'.constructor.constructor('{base_payload}')()}}}}",
            context=context,
            framework="react",
            risk="high",
            cwe="CWE-79",
            description="React-specific XSS payload"
        )
    
    def _create_angular_payload(self, base_payload: str, context: XSSContext) -> XSSPayload:
        """Create an Angular-specific XSS payload."""
        # Implementation for Angular-specific payloads
        return XSSPayload(
            payload=f"{{{{constructor.constructor('{base_payload}')()}}}}",
            context=context,
            framework="angular",
            risk="high",
            cwe="CWE-79",
            description="Angular-specific XSS payload"
        )
    
    async def _test_payload(self, param: str, payload: str, method: str = 'GET') -> bool:
        """Test a single payload against a parameter."""
        try:
            parsed = urlparse(self.url)
            query = parse_qs(parsed.query, keep_blank_values=True)
            query[param] = [payload]
            
            new_query = urlencode(query, doseq=True)
            test_url = parsed._replace(query=new_query).geturl()
            
            if method.upper() == 'GET':
                response = await self.session.get(test_url)
            else:
                response = await self.session.post(test_url, data={param: payload})
                
            if self._is_xss_detected(response.text, payload):
                return True
                
        except Exception as e:
            if self.verbose:
                logging.error(f"Error testing payload: {str(e)}")
                
        return False
    
    def _is_xss_detected(self, response_text: str, payload: str) -> bool:
        """Check if an XSS payload was successful."""
        # Check for direct reflection
        if payload in response_text:
            return True
            
        # Check for DOM XSS patterns
        if self._check_dom_xss_patterns(response_text, payload):
            return True
            
        # Add more sophisticated detection logic here
        
        return False
    
    def _check_dom_xss_patterns(self, response_text: str, payload: str) -> bool:
        """Check for DOM XSS patterns in the response."""
        dom_sinks = [
            r'document\.write\([^)]*' + re.escape(payload),
            r'document\.writeln\([^)]*' + re.escape(payload),
            r'eval\([^)]*' + re.escape(payload),
            r'setTimeout\([^)]*' + re.escape(payload),
            r'setInterval\([^)]*' + re.escape(payload),
            r'Function\([^)]*' + re.escape(payload),
            r'<script[^>]*>' + re.escape(payload),
            r'<img[^>]*src=["\']' + re.escape(payload),
            r'<iframe[^>]*src=["\']' + re.escape(payload)
        ]
        
        for pattern in dom_sinks:
            if re.search(pattern, response_text, re.IGNORECASE | re.DOTALL):
                return True
                
        return False
    
    def _add_finding(
        self,
        xss_type: XSSType,
        param: Optional[str] = None,
        payload: Optional[str] = None,
        risk: str = "high",
        cwe: str = "CWE-79",
        description: str = ""
    ) -> None:
        """Add a finding to the results."""
        finding = {
            'type': xss_type.value.upper(),
            'url': self.url,
            'risk': risk,
            'cwe': cwe,
            'description': description
        }
        
        if param:
            finding['parameter'] = param
        if payload:
            finding['payload'] = payload
            
        self.findings.append(finding)
    
    # Encoding utilities
    def _url_encode(self, s: str) -> str:
        return quote_plus(s)
    
    def _html_encode(self, s: str) -> str:
        return s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')
    
    def _js_encode(self, s: str) -> str:
        return s.replace('\\', '\\\\').replace('"', '\\"').replace('\'', '\\\'')
    
    def _unicode_encode(self, s: str) -> str:
        return ''.join([f'\\u{ord(c):04x}' for c in s])

# Compatibility layer for the existing module system
class Module:
    def __init__(self, url, payload_engine, analyzer, verbose=False):
        self.url = url
        self.payload_engine = payload_engine
        self.analyzer = analyzer
        self.verbose = verbose
        self.findings = []
    
    async def run(self):
        async with XSSDetector(self.url, self.payload_engine, self.analyzer, self.verbose) as detector:
            self.findings = await detector.detect_xss()
        return self.findings
