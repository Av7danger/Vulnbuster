"""
GraphQL security scanner for VulnBuster.
"""

import asyncio
from typing import Dict, List, Optional, Any

from vulnbuster.interfaces.enhanced_scanner import EnhancedActiveScanner, ScanResult
from vulnbuster.interfaces.enhanced_reporter import (
    ReportFinding, ReportSeverity, ReportConfidence
)

from .client import GraphQLClient
from .fuzzer import GraphQLFuzzer


class GraphQLScanner(EnhancedActiveScanner):
    """GraphQL security scanner for VulnBuster."""
    
    name = "graphql_scanner"
    description = "Scans for GraphQL API vulnerabilities"
    version = "1.0.0"
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client: Optional[GraphQLClient] = None
        self.fuzzer: Optional[GraphQLFuzzer] = None
    
    async def setup(self) -> None:
        """Initialize the scanner."""
        await super().setup()
        
        # Get target URL from scan context or configuration
        target = self.config.get("target")
        if not target:
            raise ValueError("No target URL specified for GraphQL scanner")
        
        # Initialize GraphQL client
        headers = self.config.get("headers", {})
        timeout = self.config.get("timeout", 30)
        
        self.client = GraphQLClient(
            endpoint=target,
            headers=headers,
            timeout=timeout,
            http_client=self.http_client
        )
        
        # Initialize fuzzer
        self.fuzzer = GraphQLFuzzer(
            client=self.client,
            max_depth=self.config.get("max_depth", 3),
            max_queries=self.config.get("max_queries", 100),
            timeout=self.config.get("fuzz_timeout", 30)
        )
    
    async def run_scan(self, target: str, result: ScanResult, context: Dict[str, Any]) -> None:
        """
        Run the GraphQL security scan.
        
        Args:
            target: Target URL to scan
            result: ScanResult object to store findings
            context: Additional context for the scan
        """
        if not self.client or not self.fuzzer:
            raise RuntimeError("Scanner not properly initialized. Call setup() first.")
        
        self.logger.info(f"Starting GraphQL security scan for {target}")
        
        try:
            # Run the fuzzer
            vulnerabilities = await self.fuzzer.fuzz()
            
            # Convert vulnerabilities to findings
            for vuln in vulnerabilities:
                finding = self._create_finding(vuln)
                result.add_finding(finding)
                
            self.logger.info(f"Completed GraphQL scan. Found {len(vulnerabilities)} issues.")
            
        except Exception as e:
            self.logger.error(f"Error during GraphQL scan: {str(e)}", exc_info=True)
            raise
    
    def _create_finding(self, vulnerability: Dict[str, Any]) -> ReportFinding:
        """Convert a vulnerability dictionary to a ReportFinding."""
        # Determine severity
        severity_str = vulnerability.get("severity", "medium").upper()
        severity = getattr(ReportSeverity, severity_str, ReportSeverity.MEDIUM)
        
        # Build description
        description = f"**{vulnerability['title']}**\n\n"
        description += f"**Description:** {vulnerability['description']}\n\n"
        description += f"**Remediation:** {vulnerability.get('remediation', 'No remediation provided.')}"
        
        # Build evidence
        evidence = []
        if "evidence" in vulnerability:
            evidence.append({
                "source": "GraphQL Fuzzer",
                "content": f"Vulnerability details: {vulnerability['evidence']}"
            })
        
        # Create and return the finding
        return ReportFinding(
            id=f"graphql-{vulnerability['category'].lower().replace(' ', '-')}-{len(evidence)}",
            title=vulnerability["title"],
            description=description,
            severity=severity,
            confidence=ReportConfidence.FIRM,
            location=self.config.get("target", ""),
            details=vulnerability.get("evidence", {}),
            evidence=evidence,
            remediation=vulnerability.get("remediation", ""),
            references=[
                "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
                "https://blog.yeswehack.com/yeswerhackers/how-exploit-common-vulnerabilities-graphql-part-1/"
            ],
            tags=["graphql", "api", vulnerability["category"].lower().replace(" ", "-")],
            cwe=self._get_cwe_for_category(vulnerability["category"])
        )
    
    def _get_cwe_for_category(self, category: str) -> int:
        """Get the appropriate CWE ID for a vulnerability category."""
        cwe_map = {
            "Denial of Service": 400,  # Uncontrolled Resource Consumption
            "Information Disclosure": 200,  # Information Exposure
            "Security Misconfiguration": 16,  # Configuration
            "Injection": 74,  # Injection
            "Broken Authentication": 287,  # Improper Authentication
        }
        return cwe_map.get(category, 0)  # 0 = No CWE maps to this issue
    
    async def cleanup(self) -> None:
        """Clean up resources."""
        if self.client:
            await self.client.close()
        await super().cleanup()
    
    @classmethod
    def get_default_config(cls) -> Dict[str, Any]:
        """Get the default configuration for this scanner."""
        return {
            "target": "",  # Required: The GraphQL endpoint to scan
            "headers": {
                # Default headers can be overridden in the config
                "User-Agent": "VulnBuster/1.0",
                "Accept": "application/json",
                "Content-Type": "application/json"
            },
            "timeout": 30,  # Request timeout in seconds
            "max_depth": 3,  # Maximum depth for query generation
            "max_queries": 100,  # Maximum number of queries to generate
            "fuzz_timeout": 30  # Maximum time to spend fuzzing (seconds)
        }
