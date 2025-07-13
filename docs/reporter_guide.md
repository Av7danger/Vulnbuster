# VulnBuster Enhanced Reporter Guide

## Overview

The enhanced reporter system in VulnBuster provides a flexible and extensible way to generate security scan reports in multiple formats. This guide covers how to use and extend the reporter system.

## Available Report Formats

| Format    | Description                                      | File Extension |
|-----------|--------------------------------------------------|----------------|
| HTML      | Interactive HTML report with filtering           | .html          |
| Markdown  | GitHub-flavored markdown for easy sharing        | .md            |
| JSON      | Machine-readable output with schema validation   | .json          |
| SARIF     | Standard format for static analysis tools        | .sarif         |
| Text      | Plain text report for console output             | .txt           |
| PDF       | Printable PDF document                           | .pdf           |

## Basic Usage

### Generating a Report

```python
from vulnbuster.interfaces.enhanced_reporter import (
    ReportFinding, ReportMetadata, get_reporter, ReportFormat
)

# Create findings
findings = [
    ReportFinding(
        title="SQL Injection Vulnerability",
        description="Found SQL injection in login form",
        severity="high",
        confidence="firm",
        location="https://example.com/login"
    )
]

# Create metadata
metadata = ReportMetadata(
    title="Security Scan Report",
    scan_target="example.com",
    scan_duration=42.5
)

# Generate and save HTML report
reporter = get_reporter(
    format=ReportFormat.HTML,
    output_file="report.html"
)

report = await reporter.generate(findings, metadata)
await reporter.save(report)
```

### Using the Reporter in a Scanner

```python
from vulnbuster.interfaces.enhanced_scanner import ActiveScannerPlugin
from vulnbuster.interfaces.enhanced_reporter import ReportFinding, ReportSeverity

class MyScanner(ActiveScannerPlugin):
    name = "my_scanner"
    
    async def run_scan(self, target: str, result, context):
        # Perform scan...
        
        # Add findings
        finding = ReportFinding(
            title="Vulnerability Found",
            description="Detailed description of the issue",
            severity=ReportSeverity.HIGH,
            confidence="firm",
            location=target
        )
        result.add_finding(finding)
```

## Advanced Features

### Custom Templates

You can provide custom templates for HTML and other template-based formats:

```python
reporter = get_reporter(
    format=ReportFormat.HTML,
    output_file="custom_report.html",
    template="path/to/custom_template.html",
    custom_templates_dir="path/to/templates"
)
```

### Filtering Findings

Filter findings by severity:

```python
# Only include medium and higher severity findings
reporter = get_reporter(
    format=ReportFormat.HTML,
    min_severity="medium"
)
```

### Custom Styling

For HTML and PDF reports, you can provide custom CSS:

```python
reporter = get_reporter(
    format=ReportFormat.HTML,
    custom_styles={
        "header_color": "#2c3e50",
        "critical_color": "#c0392b",
        "high_color": "#e67e22",
        "medium_color": "#f1c40f",
        "low_color": "#3498db",
        "info_color": "#95a5a6"
    }
)
```

## Report Metadata

The `ReportMetadata` class allows you to include additional information about the scan:

```python
metadata = ReportMetadata(
    title="Quarterly Security Scan",
    description="Scan of production environment",
    version="1.0.0",
    scan_target="api.example.com",
    scan_duration=125.75,  # seconds
    custom_fields={
        "environment": "production",
        "scan_type": "authenticated",
        "scanner_version": "1.2.3"
    }
)
```

## Creating Custom Reporters

You can create custom reporters by subclassing `BaseReporter`:

```python
from vulnbuster.interfaces.enhanced_reporter import BaseReporter, ReportFormat

class MyCustomReporter(BaseReporter):
    """Custom reporter that generates reports in a custom format."""
    
    async def _generate_report(self, findings, metadata, summary):
        """Generate the report content."""
        # Your custom report generation logic here
        return "My custom report content"

# Register the custom reporter
ReportFormat.MY_FORMAT = "my_format"
get_reporter.registry[ReportFormat.MY_FORMAT] = MyCustomReporter
```

## Example: Generating All Report Formats

```python
import asyncio
from pathlib import Path
from vulnbuster.interfaces.enhanced_reporter import get_reporter, ReportFormat

async def generate_all_reports(findings, metadata):
    output_dir = Path("reports")
    output_dir.mkdir(exist_ok=True)
    
    for fmt in ReportFormat:
        try:
            reporter = get_reporter(
                format=fmt,
                output_file=output_dir / f"report.{fmt.value}"
            )
            report = await reporter.generate(findings, metadata)
            await reporter.save(report)
            print(f"Generated {fmt.value.upper()} report")
        except Exception as e:
            print(f"Error generating {fmt.value.upper()} report: {e}")

# Usage:
# asyncio.run(generate_all_reports(findings, metadata))
```

## Dependencies

Some report formats require additional dependencies:

- PDF: `weasyprint` (requires additional system dependencies)
- HTML: `jinja2` (included in requirements)

Install PDF support:

```bash
# On Ubuntu/Debian
sudo apt-get install python3-cffi python3-brotli libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0

# On macOS
brew install python-cffi pango gdk-pixbuf libffi

# Then install Python packages
pip install weasyprint
```

## Troubleshooting

### PDF Generation Fails

If PDF generation fails, ensure you have all required system dependencies installed (see above). On some systems, you may need to install additional fonts.

### Template Not Found

If you get template-related errors, ensure your template paths are correct and the template files exist. Use absolute paths if needed.

### Encoding Issues

For non-ASCII characters, ensure your environment uses UTF-8 encoding. You can set this in your script:

```python
import sys
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
```

## Best Practices

1. **Use Appropriate Severity Levels**: Be consistent with severity assignments
2. **Include Detailed Evidence**: Always include request/response pairs when possible
3. **Provide Clear Remediation**: Include specific, actionable remediation steps
4. **Use Custom Fields**: Add context with custom fields in the metadata
5. **Test All Formats**: Ensure your reports render correctly in all target formats
