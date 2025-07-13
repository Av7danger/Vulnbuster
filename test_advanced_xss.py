"""
Test script for the advanced XSS module.
This script demonstrates the usage of the advanced XSS detection capabilities.
"""

import asyncio
from modes.web.modules.advanced_xss import XSSDetector, XSSType

class MockPayloadEngine:
    """Mock payload engine for testing."""
    
    def get_payloads(self, payload_type):
        """Return test payloads."""
        return [
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

class MockAnalyzer:
    """Mock analyzer for testing."""
    pass

async def test_xss_detection():
    """Test XSS detection with a mock HTTP server."""
    # Create a test URL with a parameter
    test_url = "http://example.com/search?q=test"
    
    # Initialize the XSS detector
    payload_engine = MockPayloadEngine()
    analyzer = MockAnalyzer()
    
    # Create a mock response that reflects the payload
    class MockResponse:
        def __init__(self, text):
            self.text = text
    
    # Test with a reflected XSS
    with patch('httpx.AsyncClient.get', new_callable=AsyncMock) as mock_get:
        # Configure the mock to return a response that reflects our payload
        mock_get.return_value = MockResponse(
            "<html><body>Search results for: <script>alert(1)</script></body></html>"
        )
        
        async with XSSDetector(test_url, payload_engine, analyzer, verbose=True) as detector:
            # Run the detection
            findings = await detector.detect_xss()
            
            # Print the findings
            print("\n=== XSS Detection Results ===")
            for i, finding in enumerate(findings, 1):
                print(f"\nFinding {i}:")
                for key, value in finding.items():
                    print(f"  {key}: {value}")
            
            # Verify we found the reflected XSS
            assert any(finding['type'] == 'REFLECTED' for finding in findings), \
                "Failed to detect reflected XSS"

if __name__ == "__main__":
    from unittest.mock import patch, AsyncMock
    
    # Run the test
    asyncio.run(test_xss_detection())
