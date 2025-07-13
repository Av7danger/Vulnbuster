"""
Reporter Demo

This script demonstrates how to use the enhanced reporter interface to generate
reports in various formats.
"""

import asyncio
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import List

from vulnbuster.interfaces.enhanced_reporter import (
    ReportFinding, ReportMetadata, ReportSeverity, ReportConfidence,
    get_reporter, ReportFormat
)

# Create sample findings
def create_sample_findings(count: int = 5) -> List[ReportFinding]:
    """Generate sample findings for demonstration."""
    findings = []
    severities = list(ReportSeverity)
    confidences = list(ReportConfidence)
    
    for i in range(1, count + 1):
        severity = random.choice(severities)
        confidence = random.choice(confidences)
        
        finding = ReportFinding(
            title=f"Sample Finding {i}",
            description=(
                f"This is a sample finding with {severity.value} severity "
                f"and {confidence.value} confidence. It demonstrates how findings "
                "can be reported in various formats."
            ),
            severity=severity,
            confidence=confidence,
            location=f"https://example.com/vulnerable/endpoint/{i}",
            details={
                "http_method": random.choice(["GET", "POST"]),
                "parameter": random.choice(["id", "q", "search", "filter"]),
                "status_code": random.choice([200, 403, 500]),
            },
            evidence=[
                {
                    "source": "Request",
                    "content": f"GET /vulnerable/endpoint/{i}?id=1' OR '1'='1"
                },
                {
                    "source": "Response",
                    "content": (
                        "HTTP/1.1 200 OK\n"
                        "Content-Type: text/html\n"
                        "\n"
                        "<html>... Database error: You have an error in your SQL syntax ...</html>"
                    )
                }
            ],
            remediation=(
                "To fix this vulnerability, use parameterized queries or prepared statements.\n"
                "Example:\n"
                "```python\n"
                "# Bad: String concatenation\n"
                "query = \"SELECT * FROM users WHERE id = \" + user_input\n\n"
                "# Good: Parameterized query\n"
                "query = \"SELECT * FROM users WHERE id = %s\"\n"
                "cursor.execute(query, (user_input,))\n"
                "```"
            ),
            references=[
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
            ],
            tags=["web", "injection", "sql"],
            cwe=89,  # SQL Injection
            cve=f"CVE-2023-{random.randint(1000, 9999)}",
            cvss_score=random.uniform(3.0, 9.5),
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            risk_score=random.uniform(0.0, 10.0)
        )
        findings.append(finding)
    
    return findings

async def generate_reports():
    """Generate reports in all available formats."""
    # Create sample findings
    findings = create_sample_findings(5)
    
    # Create report metadata
    metadata = ReportMetadata(
        title="VulnBuster Security Scan Report",
        description="This report contains the results of a security scan.",
        version="1.0.0",
        scan_target="https://example.com",
        scan_duration=random.uniform(10.5, 30.2),
        custom_fields={
            "scanner_version": "1.0.0",
            "scan_type": "full",
            "environment": "production"
        }
    )
    
    # Create output directory
    output_dir = Path("reports")
    output_dir.mkdir(exist_ok=True)
    
    # Generate reports in all formats
    for fmt in ReportFormat:
        try:
            print(f"Generating {fmt.value.upper()} report...")
            
            # Create reporter instance
            reporter = get_reporter(
                format=fmt,
                output_file=output_dir / f"report.{fmt.value}",
                min_severity=ReportSeverity.LOW  # Include all findings
            )
            
            # Generate the report
            report = await reporter.generate(findings, metadata)
            
            # Save the report
            await reporter.save(report)
            
            print(f"  ✓ Report saved to {reporter.options.output_file}")
            
        except Exception as e:
            print(f"  ✗ Failed to generate {fmt.value.upper()} report: {str(e)}")
    
    print("\nReport generation complete!")

if __name__ == "__main__":
    asyncio.run(generate_reports())
