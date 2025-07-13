# Testing Guide

This guide covers testing practices and utilities for VulnBuster to ensure code quality and reliability.

## 🧪 Testing Strategy

VulnBuster uses a multi-layered testing approach:

1. **Unit Tests**: Test individual components in isolation
2. **Integration Tests**: Test interactions between components
3. **Functional Tests**: Test end-to-end functionality
4. **Performance Tests**: Test performance characteristics
5. **Security Tests**: Test for security vulnerabilities

## 🛠️ Test Setup

### Prerequisites

- Python 3.8+
- `pytest`
- `pytest-cov` (for coverage reporting)
- `pytest-asyncio` (for async tests)
- `pytest-mock` (for mocking)

### Directory Structure

```
tests/
├── unit/
│   ├── test_scanner.py
│   ├── test_models.py
│   └── test_utils.py
├── integration/
│   ├── test_web_scanner.py
│   └── test_cloud_scanner.py
├── functional/
│   ├── test_cli.py
│   └── test_api.py
├── performance/
│   └── test_scaling.py
├── security/
│   └── test_vulnerabilities.py
└── conftest.py
```

### Running Tests

```bash
# Run all tests
pytest

# Run tests with coverage
pytest --cov=vulnbuster tests/

# Run a specific test file
pytest tests/unit/test_scanner.py

# Run tests matching a pattern
pytest -k "test_scan"

# Run tests with detailed output
pytest -v
```

## 📝 Writing Tests

### Test Structure

```python
import pytest
from vulnbuster.scanners import WebScanner
from vulnbuster.models import Finding, Severity

class TestWebScanner:
    """Tests for the WebScanner class."""
    
    @pytest.fixture
    def scanner(self):
        """Create a WebScanner instance for testing."""
        return WebScanner()
    
    @pytest.mark.asyncio
    async def test_scan_secure_headers(self, scanner, mock_http_server):
        """Test scanning for security headers."""
        # Setup mock server
        mock_http_server.expect_request("/").respond_with_data(
            "<html></html>",
            headers={
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY"
            }
        )
        
        # Run scan
        findings = await scanner.scan(mock_http_server.url_for("/"))
        
        # Assert results
        assert len(findings) == 0
```

### Async Testing

```python
import pytest
import asyncio

@pytest.mark.asyncio
async def test_async_operation():
    """Test an async operation."""
    result = await some_async_function()
    assert result == expected_value
```

### Mocking

```python
import pytest
from unittest.mock import patch, MagicMock

@pytest.mark.asyncio
async def test_with_mocks():
    """Test with mocked dependencies."""
    with patch('vulnbuster.scanners.requests.get') as mock_get:
        # Configure mock
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html>Test</html>"
        mock_get.return_value = mock_response
        
        # Test code that uses the mock
        result = await fetch_webpage("http://example.com")
        assert "Test" in result
```

### Fixtures

```python
import pytest
from vulnbuster import VulnBuster

@pytest.fixture
def vb_instance():
    """Create a VulnBuster instance for testing."""
    return VulnBuster()

@pytest.fixture
def mock_http_server(aiohttp_client, aiohttp_server):
    """Create a mock HTTP server for testing."""
    async def create_test_app():
        from aiohttp import web
        
        async def handle(request):
            return web.Response(text="Test")
            
        app = web.Application()
        app.router.add_get("/", handle)
        return app
        
    return aiohttp_server(create_test_app)
```

## 🔍 Test Types

### Unit Tests

Test individual functions and classes in isolation.

```python
def test_finding_initialization():
    """Test Finding class initialization."""
    finding = Finding(
        title="Test Finding",
        description="This is a test",
        severity="high"
    )
    assert finding.title == "Test Finding"
    assert finding.severity == "high"
```

### Integration Tests

Test interactions between components.

```python
@pytest.mark.asyncio
async def test_web_scanner_integration():
    """Test WebScanner with real HTTP client."""
    scanner = WebScanner()
    findings = await scanner.scan("https://example.com")
    assert isinstance(findings, list)
```

### Functional Tests

Test end-to-end functionality.

```python
def test_cli_scan(runner):
    """Test the scan CLI command."""
    result = runner.invoke(cli, ["scan", "https://example.com"])
    assert result.exit_code == 0
    assert "Scan complete" in result.output
```

### Performance Tests

```python
import time
import pytest

@pytest.mark.performance
def test_scan_performance(benchmark):
    """Test scanner performance."""
    scanner = WebScanner()
    
    def run_scan():
        return asyncio.run(scanner.scan("https://example.com"))
        
    # Run benchmark
    result = benchmark(run_scan)
    assert len(result) >= 0
```

### Security Tests

```python
import ast
import astor
from vulnbuster.analysis.security import SecurityVisitor

def test_code_for_insecure_patterns():
    """Test for insecure code patterns."""
    code = """
    def login(username, password):
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        return db.execute(query)
    """
    
    # Parse and analyze code
    tree = ast.parse(code)
    visitor = SecurityVisitor()
    visitor.visit(tree)
    
    # Check for SQL injection
    assert "SQL injection" in [v[1] for v in visitor.violations]
```

## 📊 Test Coverage

### Coverage Reporting

```bash
# Generate coverage report
pytest --cov=vulnbuster --cov-report=html

# Show missing lines
pytest --cov=vulnbuster --cov-report term-missing
```

### Coverage Configuration

Add to `setup.cfg` or `pyproject.toml`:

```ini
[tool.coverage.run]
source = ["vulnbuster"]
omit = [
    "**/tests/**",
    "**/__pycache__/**",
    "**/migrations/**"
]

[tool.coverage.report]
fail_under = 90
show_missing = true
skip_covered = true
```

## 🧩 Testing Plugins

### Testing Plugin Discovery

```python
def test_plugin_discovery():
    """Test that plugins are discovered correctly."""
    vb = VulnBuster()
    plugins = vb.list_plugins()
    assert "web_scanner" in plugins
    assert "cloud_scanner" in plugins
```

### Testing Plugin Functionality

```python
@pytest.mark.asyncio
async def test_web_scanner_plugin():
    """Test the web scanner plugin."""
    scanner = WebScanner()
    await scanner.setup()
    
    try:
        findings = await scanner.scan("https://example.com")
        assert isinstance(findings, list)
    finally:
        await scanner.teardown()
```

## 🔄 Continuous Integration

### GitHub Actions Example

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:13
        env:
          POSTGRES_PASSWORD: postgres
        ports:
          - 5432:5432
    
    steps:
    - uses: actions/checkout@v2
    
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: '3.9'
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -e .[test]
    
    - name: Run tests
      run: |
        pytest --cov=vulnbuster --cov-report=xml
    
    - name: Upload coverage
      uses: codecov/codecov-action@v1
      with:
        file: ./coverage.xml
        fail_ci_if_error: true
```

## 🚨 Common Issues

### Async Test Hanging

If an async test hangs, ensure you're using `@pytest.mark.asyncio` and properly awaiting all coroutines.

### Mocking Async Functions

```python
# Correct
mock_async = AsyncMock(return_value=42)

# Incorrect
mock_async = MagicMock(return_value=42)  # Will not work with async/await
```

### Database Fixtures

For tests requiring a database, use fixtures to set up and tear down test data.

## 📚 Related Documentation

- [API Reference](./api-reference.md)
- [Plugin Development](./plugin-development.md)
- [Architecture](./architecture.md)
