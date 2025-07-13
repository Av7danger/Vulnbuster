"""
Tests for the advanced_xss module.
"""

import pytest
import asyncio
from unittest.mock import MagicMock, patch, AsyncMock
from urllib.parse import urlencode, parse_qs

from modes.web.modules.advanced_xss import XSSDetector, XSSType, XSSContext, XSSPayload

@pytest.fixture
def mock_payload_engine():
    """Create a mock payload engine for testing."""
    engine = MagicMock()
    engine.get_payloads.return_value = [
        {
            'payload': '<script>alert(1)</script>',
            'risk': 'high',
            'cwe': 'CWE-79',
            'description': 'Basic XSS payload'
        },
        {
            'payload': 'javascript:alert(1)',
            'risk': 'high',
            'cwe': 'CWE-79',
            'description': 'JavaScript URI payload'
        }
    ]
    return engine

@pytest.fixture
def mock_analyzer():
    """Create a mock analyzer for testing."""
    return MagicMock()

@pytest.mark.asyncio
async def test_detect_reflected_xss(mock_payload_engine, mock_analyzer):
    """Test detection of reflected XSS vulnerabilities."""
    test_url = "http://example.com/test?param=value"
    
    # Create a mock response that reflects the payload
    mock_response = MagicMock()
    mock_response.text = "<html><body>Search results for: <script>alert(1)</script></body></html>"
    
    # Patch the session to return our mock response
    with patch('httpx.AsyncClient.get', new_callable=AsyncMock, return_value=mock_response):
        async with XSSDetector(test_url, mock_payload_engine, mock_analyzer, verbose=True) as detector:
            findings = await detector.detect_xss()
            
            # Verify that a finding was reported
            assert len(findings) > 0
            assert findings[0]['type'] == 'REFLECTED'
            assert 'param' in findings[0]

@pytest.mark.asyncio
async def test_dom_based_xss_detection(mock_payload_engine, mock_analyzer):
    """Test detection of DOM-based XSS vulnerabilities."""
    test_url = "http://example.com/test"
    
    # Create a mock response with DOM XSS patterns
    mock_response = MagicMock()
    mock_response.text = """
    <html>
        <body>
            <script>
                var userInput = document.location.hash.substring(1);
                document.write(userInput);
            </script>
        </body>
    </html>
    """
    
    with patch('httpx.AsyncClient.get', new_callable=AsyncMock, return_value=mock_response):
        async with XSSDetector(f"{test_url}#test", mock_payload_engine, mock_analyzer) as detector:
            findings = await detector.detect_xss()
            
            # Verify that a DOM-based XSS finding was reported
            assert any(finding['type'] == 'DOM_BASED' for finding in findings)

@pytest.mark.asyncio
async def test_context_aware_payloads(mock_payload_engine, mock_analyzer):
    """Test generation of context-aware payloads."""
    test_url = "http://example.com/test?param=value"
    
    async with XSSDetector(test_url, mock_payload_engine, mock_analyzer) as detector:
        # Test HTML context
        payloads = detector._get_context_aware_payloads("test", XSSType.REFLECTED)
        assert any(p.context == XSSContext.HTML for p in payloads)
        
        # Test script context
        script_context = "<script>var x = 'test';</script>"
        payloads = detector._get_context_aware_payloads(script_context, XSSType.REFLECTED)
        assert any(p.context == XSSContext.SCRIPT for p in payloads)

@pytest.mark.asyncio
async def test_react_payload_generation(mock_payload_engine, mock_analyzer):
    """Test generation of React-specific payloads."""
    test_url = "http://example.com/react"
    
    # Configure detector to detect React
    with patch.object(XSSDetector, '_detect_tech_stack', return_value={'react': True}):
        async with XSSDetector(test_url, mock_payload_engine, mock_analyzer) as detector:
            payloads = detector._get_context_aware_payloads("test", XSSType.REFLECTED)
            react_payloads = [p for p in payloads if p.framework == 'react']
            assert len(react_payloads) > 0
            assert 'constructor' in react_payloads[0].payload

@pytest.mark.asyncio
async def test_angular_payload_generation(mock_payload_engine, mock_analyzer):
    """Test generation of Angular-specific payloads."""
    test_url = "http://example.com/angular"
    
    # Configure detector to detect Angular
    with patch.object(XSSDetector, '_detect_tech_stack', return_value={'angular': True}):
        async with XSSDetector(test_url, mock_payload_engine, mock_analyzer) as detector:
            payloads = detector._get_context_aware_payloads("test", XSSType.REFLECTED)
            angular_payloads = [p for p in payloads if p.framework == 'angular']
            assert len(angular_payloads) > 0
            assert 'constructor' in angular_payloads[0].payload

@pytest.mark.parametrize("input_str,expected", [
    ("test", "test"),
    ("test&test", "test&amp;test"),
    ("<test>", "&lt;test&gt;"),
    ("'test'", "&#39;test&#39;"),
    ('"test"', "&quot;test&quot;"),
])
def test_html_encoding(mock_payload_engine, mock_analyzer, input_str, expected):
    """Test HTML encoding of payloads."""
    detector = XSSDetector("http://example.com", mock_payload_engine, mock_analyzer)
    assert detector._html_encode(input_str) == expected

@pytest.mark.parametrize("input_str,expected", [
    ("test", "test"),
    ("test'test", "test\\'test"),
    ("test\"test", "test\\\"test"),
    ("test\\test", "test\\\\test"),
])
def test_js_encoding(mock_payload_engine, mock_analyzer, input_str, expected):
    """Test JavaScript encoding of payloads."""
    detector = XSSDetector("http://example.com", mock_payload_engine, mock_analyzer)
    assert detector._js_encode(input_str) == expected

@pytest.mark.asyncio
async def test_stored_xss_detection(mock_payload_engine, mock_analyzer):
    """Test detection of stored XSS vulnerabilities."""
    test_url = "http://example.com/comment"
    
    # Mock the POST request to store the payload
    mock_post_response = MagicMock()
    mock_post_response.status_code = 200
    
    # Mock the GET request that would retrieve the stored payload
    mock_get_response = MagicMock()
    mock_get_response.text = """
    <html>
        <body>
            <div class="comment"><script>alert(1)</script></div>
        </body>
    </html>
    """
    
    # Patch the session to return our mock responses
    with patch('httpx.AsyncClient.post', new_callable=AsyncMock, return_value=mock_post_response), \
         patch('httpx.AsyncClient.get', new_callable=AsyncMock, return_value=mock_get_response):
        
        async with XSSDetector(test_url, mock_payload_engine, mock_analyzer) as detector:
            # This will test both the storage and retrieval of the XSS payload
            findings = await detector.test_stored_xss()
            
            # Verify that a stored XSS finding was reported
            assert any(finding['type'] == 'STORED' for finding in detector.findings)
