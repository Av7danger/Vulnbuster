# Plugin Development Guide

This guide explains how to develop custom plugins for VulnBuster to extend its functionality.

## 📋 Plugin Types

VulnBuster supports several types of plugins:

1. **Scanner Plugins** - Add new security checks
2. **Report Plugins** - Custom report formats
3. **AI Model Plugins** - Custom ML models
4. **Integration Plugins** - Third-party integrations
5. **Authentication Plugins** - Custom auth methods

## 🏗️ Basic Plugin Structure

```python
from vulnbuster.plugins import BasePlugin

class MyPlugin(BasePlugin):
    """Documentation for your plugin"""
    
    # Required attributes
    name = "my_plugin"
    version = "1.0.0"
    description = "Description of what this plugin does"
    
    # Optional attributes
    author = "Your Name"
    license = "MIT"
    
    # Plugin configuration
    default_config = {
        'enabled': True,
        'timeout': 30,
        'custom_setting': 'default_value'
    }
    
    def __init__(self, config=None):
        super().__init__(config)
        # Initialize your plugin here
        self._initialize()
    
    def _initialize(self):
        """Initialize plugin resources"""
        pass
    
    def setup(self):
        """Setup hook called before scanning starts"""
        pass
    
    def teardown(self):
        """Cleanup hook called after scanning completes"""
        pass
    
    def validate_config(self):
        """Validate plugin configuration"""
        if not self.config.get('api_key'):
            raise ValueError("API key is required")
```

## 🔌 Scanner Plugin

Scanner plugins perform security checks against targets.

### Example: Simple Header Checker

```python
from vulnbuster.plugins import ScannerPlugin
from vulnbuster.models import Finding, Severity

class HeaderChecker(ScannerPlugin):
    """Checks for security-related HTTP headers"""
    
    name = "header_checker"
    description = "Checks for missing security headers"
    
    required_headers = [
        'X-Content-Type-Options',
        'X-Frame-Options',
        'Content-Security-Policy',
        'X-XSS-Protection',
        'Strict-Transport-Security'
    ]
    
    async def scan(self, target):
        """Scan a target for missing security headers"""
        findings = []
        
        try:
            # Make HTTP request
            response = await self.http_client.get(target)
            
            # Check for missing headers
            missing_headers = [
                h for h in self.required_headers 
                if h.lower() not in response.headers
            ]
            
            if missing_headers:
                findings.append(
                    Finding(
                        title="Missing Security Headers",
                        description=f"Missing recommended security headers: {', '.join(missing_headers)}",
                        severity=Severity.MEDIUM,
                        details={
                            'missing_headers': missing_headers,
                            'url': target
                        },
                        confidence=0.9
                    )
                )
                
        except Exception as e:
            self.logger.error(f"Error scanning {target}: {str(e)}")
            
        return findings
```

## 📊 Report Plugin

Report plugins generate different output formats.

### Example: JSON Report Plugin

```python
import json
from pathlib import Path
from vulnbuster.plugins import ReportPlugin

class JSONReport(ReportPlugin):
    """Generates JSON reports"""
    
    name = "json_report"
    description = "Generates JSON formatted reports"
    
    async def generate(self, findings, output_file=None, **kwargs):
        """Generate JSON report"""
        report = {
            'metadata': {
                'generated_at': self._current_time(),
                'scanner': 'VulnBuster',
                'version': self._get_version()
            },
            'findings': [f.to_dict() for f in findings]
        }
        
        json_data = json.dumps(report, indent=2)
        
        if output_file:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json_data)
            return str(output_path.absolute())
            
        return json_data
    
    def _current_time(self):
        from datetime import datetime
        return datetime.utcnow().isoformat()
    
    def _get_version(self):
        import vulnbuster
        return vulnbuster.__version__
```

## 🤖 AI Model Plugin

AI model plugins integrate custom ML models.

### Example: Custom Text Classifier

```python
import numpy as np
from typing import List, Dict, Any
from vulnbuster.plugins import AIModelPlugin

class CustomTextClassifier(AIModelPlugin):
    """Custom text classification model"""
    
    name = "custom_text_classifier"
    description = "Classifies text into security categories"
    
    def __init__(self, model_path=None):
        super().__init__()
        self.model = self._load_model(model_path)
        
    def _load_model(self, model_path):
        """Load the ML model"""
        # Implement model loading logic
        return None  # Return loaded model
    
    async def predict(self, texts: List[str], **kwargs) -> List[Dict[str, Any]]:
        """Make predictions on input texts"""
        results = []
        
        for text in texts:
            # Preprocess text
            processed = self._preprocess(text)
            
            # Get model prediction
            prediction = self.model.predict([processed])
            
            # Process prediction
            results.append({
                'text': text,
                'prediction': prediction[0],
                'confidence': float(np.max(prediction[0])),
                'class': self._get_class(prediction[0])
            })
            
        return results
    
    def _preprocess(self, text: str) -> str:
        """Preprocess input text"""
        # Implement text preprocessing
        return text.lower().strip()
    
    def _get_class(self, prediction) -> str:
        """Convert prediction to class label"""
        # Implement class mapping
        return "secure" if prediction[0] > 0.5 else "insecure"
```

## 🔌 Integration Plugin

Integration plugins connect with external services.

### Example: Slack Notifier

```python
import slack_sdk
from vulnbuster.plugins import IntegrationPlugin

class SlackNotifier(IntegrationPlugin):
    """Sends scan results to Slack"""
    
    name = "slack_notifier"
    description = "Sends scan results to Slack"
    
    default_config = {
        'webhook_url': None,
        'channel': '#security',
        'username': 'VulnBuster',
        'icon_emoji': ':shield:'
    }
    
    def __init__(self, config=None):
        super().__init__(config)
        self.client = None
        
    async def setup(self):
        """Initialize Slack client"""
        if not self.config.get('webhook_url'):
            raise ValueError("Slack webhook URL is required")
            
        self.client = slack_sdk.WebhookClient(self.config['webhook_url'])
    
    async def send_alert(self, findings, **kwargs):
        """Send findings to Slack"""
        if not self.client:
            await self.setup()
            
        message = self._format_message(findings)
        
        try:
            response = self.client.send(
                text=message,
                channel=self.config['channel'],
                username=self.config['username'],
                icon_emoji=self.config['icon_emoji']
            )
            return response.status_code == 200
            
        except Exception as e:
            self.logger.error(f"Error sending Slack notification: {str(e)}")
            return False
    
    def _format_message(self, findings):
        """Format findings as Slack message"""
        critical = sum(1 for f in findings if f.severity == 'critical')
        high = sum(1 for f in findings if f.severity == 'high')
        
        return (
            f"*Vulnerability Scan Complete*\n"
            f"*Critical*: {critical} | "
            f"*High*: {high} | "
            f"*Total*: {len(findings)}\n"
            "Run `vulnbuster report view` for details"
        )
```

## 🔌 Authentication Plugin

Authentication plugins handle different authentication methods.

### Example: OAuth2 Authentication

```python
from oauthlib.oauth2 import BackendApplicationClient
from requests_oauthlib import OAuth2Session
from vulnbuster.plugins import AuthPlugin

class OAuth2Auth(AuthPlugin):
    """OAuth2 authentication plugin"""
    
    name = "oauth2_auth"
    description = "OAuth 2.0 authentication"
    
    default_config = {
        'token_url': None,
        'client_id': None,
        'client_secret': None,
        'scope': ['read', 'write']
    }
    
    def __init__(self, config=None):
        super().__init__(config)
        self.session = None
        
    async def authenticate(self):
        """Authenticate and return session"""
        client = BackendApplicationClient(
            client_id=self.config['client_id'],
            scope=self.config['scope']
        )
        
        self.session = OAuth2Session(client=client)
        
        self.session.fetch_token(
            token_url=self.config['token_url'],
            client_id=self.config['client_id'],
            client_secret=self.config['client_secret'],
            scope=self.config['scope']
        )
        
        return self.session
    
    def get_auth_headers(self):
        """Get authentication headers"""
        if not self.session:
            raise RuntimeError("Not authenticated. Call authenticate() first.")
            
        token = self.session.token.get('access_token')
        return {'Authorization': f'Bearer {token}'}
```

## 📦 Packaging Plugins

### Project Structure

```
my_plugin/
├── README.md
├── setup.py
├── my_plugin/
│   ├── __init__.py
│   ├── scanner.py
│   ├── report.py
│   └── models.py
└── tests/
    └── test_plugin.py
```

### setup.py

```python
from setuptools import setup, find_packages

setup(
    name="vulnbuster-my-plugin",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        'vulnbuster>=1.0.0',
        # Add other dependencies
    ],
    entry_points={
        'vulnbuster.plugins': [
            'my_scanner = my_plugin.scanner:MyScanner',
            'my_report = my_plugin.report:MyReport',
        ],
    },
    author="Your Name",
    author_email="your.email@example.com",
    description="Custom VulnBuster plugins",
    license="MIT",
    keywords="security testing vulnerability scanner",
    url="https://github.com/yourusername/vulnbuster-my-plugin",
)
```

## 🧪 Testing Plugins

### Example Test

```python
import pytest
from my_plugin.scanner import HeaderChecker

@pytest.fixture
def header_checker():
    return HeaderChecker()

@pytest.mark.asyncio
async def test_header_checker(header_checker, mock_http_server):
    # Setup mock server
    mock_http_server.expect_request("/").respond_with_data(
        "<html><body>Test</body></html>",
        headers={"X-Content-Type-Options": "nosniff"}
    )
    
    # Run scan
    findings = await header_checker.scan(mock_http_server.url_for("/"))
    
    # Assert results
    assert len(findings) == 1  # Should report missing headers
    assert "X-Frame-Options" in findings[0].description
```

## 📚 Best Practices

1. **Error Handling**
   - Catch and log exceptions
   - Provide meaningful error messages
   - Handle edge cases

2. **Performance**
   - Use async/await for I/O operations
   - Implement timeouts
   - Cache expensive operations

3. **Security**
   - Never log sensitive data
   - Validate all inputs
   - Use secure defaults

4. **Documentation**
   - Document all public methods
   - Include usage examples
   - Document configuration options

5. **Testing**
   - Write unit tests
   - Test edge cases
   - Mock external dependencies

## ➡️ Next Steps

- [API Reference](./api-reference.md)
- [Testing Guide](./testing.md)
- [Deployment Guide](./deployment.md)
