# VulnBuster API Reference

This document provides detailed documentation for VulnBuster's Python API, which allows for programmatic interaction with the security scanning engine.

## 📋 Table of Contents

- [Core Classes](#-core-classes)
- [Scanner API](#-scanner-api)
- [Plugin API](#-plugin-api)
- [AI Model API](#-ai-model-api)
- [Report API](#-report-api)
- [Utility Functions](#-utility-functions)
- [Error Handling](#-error-handling)
- [Examples](#-examples)

## 🏛️ Core Classes

### VulnBuster

Main entry point for the VulnBuster API.

```python
class VulnBuster:
    def __init__(self, config=None):
        """Initialize VulnBuster with optional configuration."""
        pass
    
    def scan(self, target, **kwargs):
        """Run a security scan on the target."""
        pass
    
    def list_plugins(self):
        """List all available plugins."""
        pass
    
    def get_plugin(self, name):
        """Get a plugin by name."""
        pass
```

### Finding

Represents a security finding.

```python
class Finding:
    def __init__(self, title, description, severity, **kwargs):
        """
        Initialize a new finding.
        
        Args:
            title (str): Short title of the finding
            description (str): Detailed description
            severity (str): Severity level (info, low, medium, high, critical)
            **kwargs: Additional attributes (e.g., confidence, details, references)
        """
        pass
    
    def to_dict(self):
        """Convert finding to dictionary."""
        pass
    
    @classmethod
    def from_dict(cls, data):
        """Create finding from dictionary."""
        pass
```

## 🔍 Scanner API

### BaseScanner

Abstract base class for all scanners.

```python
class BaseScanner(ABC):
    @abstractmethod
    async def scan(self, target):
        """
        Scan a target for vulnerabilities.
        
        Args:
            target: Target to scan (URL, IP, file path, etc.)
            
        Returns:
            List[Finding]: List of security findings
        """
        pass
```

### WebScanner

```python
class WebScanner(BaseScanner):
    def __init__(self, config=None):
        """
        Initialize the web scanner.
        
        Args:
            config (dict, optional): Scanner configuration
        """
        pass
    
    async def scan(self, url, **kwargs):
        """
        Scan a web application.
        
        Args:
            url (str): Target URL
            **kwargs: Additional scan options
            
        Returns:
            List[Finding]: List of security findings
        """
        pass
```

### MobileScanner

```python
class MobileScanner(BaseScanner):
    def __init__(self, platform, config=None):
        """
        Initialize the mobile scanner.
        
        Args:
            platform (str): Target platform ('android' or 'ios')
            config (dict, optional): Scanner configuration
        """
        pass
    
    async def scan(self, target, **kwargs):
        """
        Scan a mobile application.
        
        Args:
            target (str): Path to APK/IPA file or bundle ID
            **kwargs: Additional scan options
            
        Returns:
            List[Finding]: List of security findings
        """
        pass
```

## 🔌 Plugin API

### BasePlugin

Base class for all plugins.

```python
class BasePlugin(ABC):
    # Required attributes
    name = None
    version = "1.0.0"
    description = ""
    
    def __init__(self, config=None):
        """
        Initialize the plugin.
        
        Args:
            config (dict, optional): Plugin configuration
        """
        self.config = self.default_config.copy()
        if config:
            self.config.update(config)
    
    async def setup(self):
        """Setup hook called before scanning starts."""
        pass
    
    async def teardown(self):
        """Cleanup hook called after scanning completes."""
        pass
    
    def validate_config(self):
        """Validate plugin configuration."""
        pass
```

### ScannerPlugin

Base class for scanner plugins.

```python
class ScannerPlugin(BasePlugin):
    """Base class for scanner plugins."""
    
    async def scan(self, target, **kwargs):
        """
        Scan a target for vulnerabilities.
        
        Args:
            target: Target to scan
            **kwargs: Additional scan options
            
        Returns:
            List[Finding]: List of security findings
        """
        pass
```

### ReportPlugin

Base class for report plugins.

```python
class ReportPlugin(BasePlugin):
    """Base class for report plugins."""
    
    async def generate(self, findings, output_file=None, **kwargs):
        """
        Generate a report from findings.
        
        Args:
            findings (List[Finding]): List of security findings
            output_file (str, optional): Output file path
            **kwargs: Additional report options
            
        Returns:
            str: Generated report or path to report file
        """
        pass
```

## 🤖 AI Model API

### AIModel

Base class for AI models.

```python
class AIModel(ABC):
    """Base class for AI models."""
    
    def __init__(self, model_path=None, **kwargs):
        """
        Initialize the AI model.
        
        Args:
            model_path (str, optional): Path to model file or directory
            **kwargs: Additional model parameters
        """
        pass
    
    @abstractmethod
    async def predict(self, inputs, **kwargs):
        """
        Make predictions on input data.
        
        Args:
            inputs: Input data for prediction
            **kwargs: Additional prediction parameters
            
        Returns:
            Prediction results
        """
        pass
    
    async def train(self, data, **kwargs):
        """
        Train the model on data.
        
        Args:
            data: Training data
            **kwargs: Additional training parameters
            
        Returns:
            Training metrics
        """
        pass
```

### SecurityClassifier

```python
class SecurityClassifier(AIModel):
    """Classifies security-related text."""
    
    async def predict(self, texts, **kwargs):
        """
        Classify security-related text.
        
        Args:
            texts (List[str]): List of text inputs
            **kwargs: Additional prediction parameters
            
        Returns:
            List[Dict]: List of classification results
        """
        pass
```

## 📊 Report API

### ReportGenerator

```python
class ReportGenerator:
    """Generates reports from scan results."""
    
    def __init__(self, format='html', **kwargs):
        """
        Initialize the report generator.
        
        Args:
            format (str): Report format (html, json, pdf, etc.)
            **kwargs: Additional report options
        """
        pass
    
    def add_findings(self, findings):
        """
        Add findings to the report.
        
        Args:
            findings (List[Finding]): List of security findings
        """
        pass
    
    def generate(self, output_file=None, **kwargs):
        """
        Generate the report.
        
        Args:
            output_file (str, optional): Output file path
            **kwargs: Additional generation options
            
        Returns:
            str: Generated report or path to report file
        """
        pass
```

## 🛠️ Utility Functions

### HTTP Client

```python
async def http_request(method, url, **kwargs):
    """
    Make an HTTP request.
    
    Args:
        method (str): HTTP method (GET, POST, etc.)
        url (str): Target URL
        **kwargs: Additional request parameters
        
    Returns:
        dict: Response data
    """
    pass
```

### File Utilities

```python
def read_file(path, mode='r'):
    """
    Read a file's contents.
    
    Args:
        path (str): File path
        mode (str): File open mode
        
    Returns:
        File contents
    """
    pass

def write_file(path, data, mode='w'):
    """
    Write data to a file.
    
    Args:
        path (str): File path
        data: Data to write
        mode (str): File open mode
    """
    pass
```

## ❌ Error Handling

### VulnBusterError

Base exception for all VulnBuster errors.

```python
class VulnBusterError(Exception):
    """Base exception for VulnBuster."""
    pass
```

### ScannerError

```python
class ScannerError(VulnBusterError):
    """Raised when a scanner encounters an error."""
    pass
```

### PluginError

```python
class PluginError(VulnBusterError):
    """Raised when a plugin encounters an error."""
    pass
```

## 📝 Examples

### Basic Scan

```python
from vulnbuster import VulnBuster, WebScanner

async def main():
    # Initialize VulnBuster
    vb = VulnBuster()
    
    # Create a web scanner
    scanner = WebScanner()
    
    try:
        # Run a scan
        findings = await scanner.scan('https://example.com')
        
        # Process findings
        for finding in findings:
            print(f"[{finding.severity.upper()}] {finding.title}")
            
    except Exception as e:
        print(f"Scan failed: {str(e)}")

# Run the async function
import asyncio
asyncio.run(main())
```

### Custom Plugin

```python
from vulnbuster.plugins import ScannerPlugin
from vulnbuster.models import Finding, Severity

class MyScanner(ScannerPlugin):
    """Custom security scanner."""
    
    name = "my_scanner"
    description = "Scans for custom security issues"
    
    async def scan(self, target, **kwargs):
        findings = []
        
        # Custom scanning logic
        if "test" in target:
            findings.append(
                Finding(
                    title="Test Vulnerability",
                    description="This is a test finding",
                    severity=Severity.HIGH,
                    details={"target": target}
                )
            )
            
        return findings
```

### Report Generation

```python
from vulnbuster.report import ReportGenerator

async def generate_report(findings, output_file='report.html'):
    # Create a report generator
    report_gen = ReportGenerator(format='html')
    
    # Add findings to the report
    report_gen.add_findings(findings)
    
    # Generate the report
    report_path = await report_gen.generate(
        output_file=output_file,
        title="Security Scan Report",
        include_remediation=True
    )
    
    return report_path
```

## 📚 Related Documentation

- [Architecture](./architecture.md)
- [Plugin Development](./plugin-development.md)
- [Testing Guide](./testing.md)
- [Deployment Guide](./deployment.md)
