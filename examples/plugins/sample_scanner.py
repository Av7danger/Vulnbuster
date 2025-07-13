"""
Sample Scanner Plugin for VulnBuster

This is an example of how to create a custom scanner plugin.
"""

import re
from typing import Dict, Any, Optional

from vulnbuster.interfaces.enhanced_plugin import ActiveScannerPlugin
from vulnbuster.interfaces.scanner import ScanResult, ScanContext, ScanSeverity, ScanConfidence


class SampleActiveScanner(ActiveScannerPlugin):
    """
    A sample active scanner that checks for common web vulnerabilities.
    """
    
    name = "sample_scanner"
    version = "1.0.0"
    description = "A sample active scanner for demonstration purposes"
    author = "VulnBuster Team"
    
    # Default configuration for this scanner
    config_schema = {
        **ActiveScannerPlugin.config_schema,
        "properties": {
            **ActiveScannerPlugin.config_schema["properties"],
            "check_xss": {"type": "boolean", "default": True},
            "check_sqli": {"type": "boolean", "default": True},
            "check_lfi": {"type": "boolean", "default": True},
            "custom_payloads": {
                "type": "array",
                "items": {"type": "string"},
                "default": []
            },
            "max_pages": {"type": "integer", "default": 10, "minimum": 1}
        }
    }
    
    async def setup(self) -> None:
        """Initialize the scanner."""
        await super().setup()
        self._logger.info("Initializing SampleActiveScanner")
        
        # Initialize patterns for vulnerability detection
        self._xss_patterns = [
            re.compile(r'<script>.*</script>', re.IGNORECASE | re.DOTALL),
            re.compile(r'on\w+\s*=', re.IGNORECASE),
            re.compile(r'javascript:', re.IGNORECASE),
        ]
        
        self._sqli_patterns = [
            re.compile(r'\b(?:select|insert|update|delete|drop|alter|create|truncate)\\b', 
                      re.IGNORECASE),
            re.compile(r'\b(?:union\\s+select|union\\s+all\\s+select)\\b', 
                      re.IGNORECASE | re.DOTALL),
            re.compile(r'\\'\\s*[oO][rR]\\s*\\'\\'\\s*=\\s*\\'', re.IGNORECASE),
        ]
        
        self._lfi_patterns = [
            re.compile(r'(?:\.\./|/\w+/\\.\./|/\\.\\./|/\\./|file:/|/\\|)', 
                     re.IGNORECASE),
            re.compile(r'(?:/etc/passwd|/etc/shadow|/proc/self/environ|/etc/hosts)',
                     re.IGNORECASE),
        ]
    
    async def check_xss(self, url: str, context: ScanContext) -> Optional[Dict[str, Any]]:
        """Check for XSS vulnerabilities."""
        if not self.config.get("check_xss", True):
            return None
            
        self._logger.debug("Checking for XSS in %s", url)
        
        # Test with common XSS payloads
        test_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            *self.config.get("custom_payloads", [])
        ]
        
        for payload in test_payloads:
            try:
                # Test in query parameters
                test_url = f"{url}?test={payload}" if '?' not in url else f"{url}&test={payload}"
                response = await self.http.get(test_url)
                
                # Check if payload is reflected in response
                if response.status == 200 and payload in await response.text():
                    return {
                        "type": "xss",
                        "payload": payload,
                        "url": test_url,
                        "reflected": True
                    }
                    
            except Exception as e:
                self._logger.warning("Error checking XSS for %s: %s", url, str(e))
                
        return None
    
    async def check_sqli(self, url: str, context: ScanContext) -> Optional[Dict[str, Any]]:
        """Check for SQL injection vulnerabilities."""
        if not self.config.get("check_sqli", True):
            return None
            
        self._logger.debug("Checking for SQLi in %s", url)
        
        test_payloads = [
            "' OR '1'='1",
            '" OR "1"="1',
            "' OR 1=1 -- ",
            *self.config.get("custom_payloads", [])
        ]
        
        for payload in test_payloads:
            try:
                # Test in query parameters
                test_url = f"{url}?id={payload}" if '?' not in url else f"{url}&id={payload}"
                response = await self.http.get(test_url)
                
                # Look for SQL error messages in response
                response_text = await response.text()
                error_indicators = [
                    "SQL syntax",
                    "mysql_fetch",
                    "syntax error",
                    "unexpected end",
                    "ORA-",
                    "Microsoft OLE DB"
                ]
                
                if any(indicator in response_text for indicator in error_indicators):
                    return {
                        "type": "sqli",
                        "payload": payload,
                        "url": test_url,
                        "error_based": True
                    }
                    
            except Exception as e:
                self._logger.warning("Error checking SQLi for %s: %s", url, str(e))
                
        return None
    
    async def check_lfi(self, url: str, context: ScanContext) -> Optional[Dict[str, Any]]:
        """Check for Local File Inclusion vulnerabilities."""
        if not self.config.get("check_lfi", True):
            return None
            
        self._logger.debug("Checking for LFI in %s", url)
        
        test_payloads = [
            "../../../../etc/passwd",
            "....//....//....//....//etc/passwd",
            "%00",
            *self.config.get("custom_payloads", [])
        ]
        
        for payload in test_payloads:
            try:
                # Test in query parameters
                param = "file" if "file=" in url.lower() else "page"
                test_url = f"{url}?{param}={payload}" if '?' not in url else f"{url}&{param}={payload}"
                response = await self.http.get(test_url)
                
                # Check for common LFI indicators in response
                response_text = await response.text()
                if "root:" in response_text and ":/root:" in response_text:
                    return {
                        "type": "lfi",
                        "payload": payload,
                        "url": test_url,
                        "leaked_file": "/etc/passwd"
                    }
                    
            except Exception as e:
                self._logger.warning("Error checking LFI for %s: %s", url, str(e))
                
        return None
    
    async def run_scan(self, target: str, result: ScanResult, context: ScanContext) -> None:
        """Run the scanner against the target."""
        self._logger.info("Starting scan of %s", target)
        
        # Check for XSS
        if xss_result := await self.check_xss(target, context):
            result.add_finding(
                title=f"Cross-Site Scripting (XSS) Vulnerability",
                description=(
                    f"Reflected XSS vulnerability found in {target}. "
                    f"The application reflects user input without proper encoding."
                ),
                severity=ScanSeverity.HIGH,
                confidence=ScanConfidence.FIRM,
                details={
                    "type": "reflected_xss",
                    "payload": xss_result["payload"],
                    "url": xss_result["url"]
                }
            )
        
        # Check for SQLi
        if sqli_result := await self.check_sqli(target, context):
            result.add_finding(
                title=f"SQL Injection Vulnerability",
                description=(
                    f"SQL injection vulnerability found in {target}. "
                    f"The application is vulnerable to SQL injection attacks."
                ),
                severity=ScanSeverity.CRITICAL,
                confidence=ScanConfidence.FIRM,
                details={
                    "type": "sqli",
                    "payload": sqli_result["payload"],
                    "url": sqli_result["url"]
                }
            )
        
        # Check for LFI
        if lfi_result := await self.check_lfi(target, context):
            result.add_finding(
                title=f"Local File Inclusion (LFI) Vulnerability",
                description=(
                    f"Local File Inclusion vulnerability found in {target}. "
                    f"The application is vulnerable to directory traversal attacks."
                ),
                severity=ScanSeverity.HIGH,
                confidence=ScanConfidence.FIRM,
                details={
                    "type": "lfi",
                    "payload": lfi_result["payload"],
                    "url": lfi_result["url"],
                    "leaked_file": lfi_result["leaked_file"]
                }
            )
        
        self._logger.info("Completed scan of %s", target)


# Example usage
if __name__ == "__main__":
    import asyncio
    from vulnbuster.interfaces.enhanced_plugin import PluginManager
    from vulnbuster.core import VulnBusterApp
    
    async def main():
        # Create a VulnBuster app instance
        app = VulnBusterApp()
        
        # Create plugin manager
        plugin_manager = PluginManager(app)
        
        try:
            # Load the sample scanner
            scanner = await plugin_manager.load_plugin(
                SampleActiveScanner,
                check_xss=True,
                check_sqli=True,
                check_lfi=True,
                custom_payloads=[
                    # Add any custom payloads here
                ]
            )
            
            # Run a scan
            target = "http://example.com/vulnerable/page.php"
            result = await scanner.scan(target)
            
            # Print results
            print(f"Scan results for {target}:")
            for finding in result.findings:
                print(f"- {finding['title']} ({finding['severity']})")
                print(f"  {finding['description']}")
                print(f"  Confidence: {finding['confidence']}")
                print(f"  Details: {finding['details']}")
                print()
                
        finally:
            # Clean up
            await plugin_manager.cleanup_all()
    
    # Run the example
    asyncio.run(main())
