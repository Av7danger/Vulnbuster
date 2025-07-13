# Migration Guide: Scanner v2

This guide helps you migrate from the old Scanner implementation to the new enhanced Scanner with built-in HTTP client.

## What's New

- Built-in HTTP client with rate limiting and retries
- Improved request/response handling
- Better type hints and documentation
- Simplified scanner interface
- Enhanced error handling and logging

## Key Changes

### 1. New HTTP Client Module

The new `HTTPClient` class provides robust HTTP functionality:

```python
from vulnbuster.interfaces.http_client import HTTPClient

# Create a client with custom configuration
http = HTTPClient(
    base_url="https://example.com",
    rate_limit=10,  # requests per second
    max_retries=3,
    timeout=30.0
)

# Make requests
response = await http.get("/api/endpoint")
```

### 2. Enhanced Scanner Base Class

The new `EnhancedScanner` class includes built-in HTTP client:

```python
from vulnbuster.interfaces.enhanced_scanner import EnhancedScanner

class MyScanner(EnhancedScanner):
    name = "my_scanner"
    
    async def run_scan(self, target: str, result: ScanResult, context: ScanContext) -> None:
        # Use the built-in HTTP client
        response = await self.get(target)
        if response.status == 200:
            result.add_finding(
                title="Vulnerability Found",
                description="Found a potential vulnerability",
                severity=ScanSeverity.HIGH,
                confidence=ScanConfidence.FIRM,
                details={"response": await response.text()}
            )
```

### 3. Backward Compatibility

The original `Scanner` class remains available but is now a thin wrapper around `EnhancedScanner`.

## Migration Steps

### 1. Update Imports

Change:
```python
from vulnbuster.interfaces.scanner import Scanner, ActiveScanner, PassiveScanner
```

To:
```python
from vulnbuster.interfaces.enhanced_scanner import (
    EnhancedScanner as Scanner,
    EnhancedActiveScanner as ActiveScanner,
    EnhancedPassiveScanner as PassiveScanner
)
```

### 2. Update Scanner Implementation

#### Before:
```python
class MyScanner(ActiveScanner):
    async def setup(self):
        self.session = aiohttp.ClientSession()
    
    async def teardown(self):
        await self.session.close()
    
    async def run_scan(self, target, result, context):
        async with self.session.get(target) as response:
            # Process response
```

#### After:
```python
class MyScanner(ActiveScanner):
    async def run_scan(self, target, result, context):
        response = await self.get(target)
        # Process response
        # No need to manage session manually
```

### 3. Handle Configuration Changes

The configuration structure has been updated:

```yaml
# Old format
scanner:
  timeout: 30
  max_retries: 3

# New format
scanner:
  enabled: true
  tags: []
  metadata: {}
  http:
    timeout: 30
    max_retries: 3
    rate_limit: 10
    verify_ssl: true
```

## New Features

### Rate Limiting
```python
# Configure rate limiting (requests per second)
scanner = MyScanner({
    'http': {
        'rate_limit': 5  # 5 requests per second
    }
})
```

### Request/Response Hooks
```python
# Add request hook
async def log_request(request_ctx):
    print(f"Request: {request_ctx.method} {request_ctx.url}")

scanner = MyScanner()
scanner.http.add_request_hook(log_request)
```

### Retry Logic
```python
# Configure retries
scanner = MyScanner({
    'http': {
        'max_retries': 3,
        'retry_delay': 1.0,  # Initial delay in seconds
        'max_retry_delay': 10.0  # Maximum delay
    }
})
```

## Troubleshooting

### Common Issues

1. **Session Management**
   - The HTTP client now manages sessions automatically
   - No need to create/close sessions manually

2. **Configuration**
   - Update your config files to use the new structure
   - HTTP-specific settings should be under the `http` key

3. **Async/Await**
   - All HTTP methods are now async
   - Make sure to use `await` when making requests

## Examples

### Basic Scanner
```python
from vulnbuster.interfaces.enhanced_scanner import EnhancedActiveScanner
from vulnbuster.interfaces.scanner import ScanResult, ScanContext

class SimpleScanner(EnhancedActiveScanner):
    name = "simple_scanner"
    
    async def run_scan(self, target: str, result: ScanResult, context: ScanContext) -> None:
        response = await self.get(target)
        if "admin" in await response.text():
            result.add_finding(
                title="Admin Interface Detected",
                description="Admin interface is accessible",
                severity=ScanSeverity.MEDIUM,
                confidence=ScanConfidence.FIRM
            )
```

### Using Hooks
```python
class HookedScanner(EnhancedActiveScanner):
    name = "hooked_scanner"
    
    async def setup(self):
        await super().setup()
        self.http.add_request_hook(self.log_request)
        self.http.add_response_hook(self.log_response)
    
    async def log_request(self, request_ctx):
        print(f"Request: {request_ctx.method} {request_ctx.url}")
    
    async def log_response(self, response_ctx):
        print(f"Response: {response_ctx.status} in {response_ctx.elapsed:.2f}s")
    
    async def run_scan(self, target, result, context):
        # Hooks will be called automatically
        await self.get(target)
```

## Next Steps

1. Update your scanner implementations to use the new base classes
2. Test thoroughly in a development environment
3. Update any configuration files
4. Monitor for any deprecation warnings
