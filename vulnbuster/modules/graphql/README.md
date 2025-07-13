# GraphQL Security Module

This module provides comprehensive security testing capabilities for GraphQL APIs, including schema introspection, query generation, and vulnerability detection.

## Features

- **Schema Introspection**: Automatically extract and analyze GraphQL schemas
- **Query Generation**: Generate test queries based on the schema
- **Vulnerability Detection**: Identify common GraphQL security issues
- **Fuzzing**: Test for edge cases and potential vulnerabilities
- **Integration**: Seamlessly integrates with the VulnBuster scanning framework

## Components

### GraphQL Client (`client.py`)
A flexible client for interacting with GraphQL APIs, supporting:
- Schema introspection
- Query execution
- Custom headers and authentication
- Async/await support

### GraphQL Fuzzer

A powerful security testing tool for GraphQL APIs that combines traditional fuzzing techniques with AI-powered test case generation.

## Features

- **Schema Introspection**: Automatically discovers the GraphQL schema
- **Type-Based Fuzzing**: Generates test cases based on GraphQL types
- **AI-Powered Testing**: Uses AI to generate sophisticated test cases
- **Query Chaining**: Tests complex query combinations
- **Mutation Testing**: Identifies business logic flaws
- **Field Fuzzing**: Tests individual fields with malicious inputs
- **Performance Testing**: Identifies potential DoS vectors

## Installation

```bash
pip install -r requirements.txt
```

## Quick Start

```python
from vulnbuster.modules.graphql.client import GraphQLClient
from vulnbuster.modules.graphql.fuzzer import GraphQLFuzzer

# Initialize the client
client = GraphQLClient("http://target.com/graphql")

# Create and run the fuzzer
fuzzer = GraphQLFuzzer(
    client=client,
    enable_ai_suggestions=True,
    max_ai_suggestions=20
)

# Run the fuzzer
vulnerabilities = await fuzzer.fuzz()

# Process results
for vuln in vulnerabilities:
    print(f"Found {vuln['severity']} issue: {vuln['title']}")
    print(f"Description: {vuln['description']}")
    print(f"Query: {vuln['query']}")
```

## Configuration

### GraphQLFuzzer Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `client` | `GraphQLClient` | Required | Configured GraphQL client |
| `enable_ai_suggestions` | `bool` | `True` | Whether to use AI for test case generation |
| `max_ai_suggestions` | `int` | `20` | Maximum number of AI suggestions to generate |
| `max_depth` | `int` | `5` | Maximum depth for generated queries |
| `max_width` | `int` | `5` | Maximum width (fields per level) for generated queries |
| `request_timeout` | `int` | `30` | Timeout for HTTP requests in seconds |
| `max_concurrent_requests` | `int` | `10` | Maximum number of concurrent requests |

## AI-Powered Testing

The fuzzer includes an AI suggestor that generates sophisticated test cases by analyzing the GraphQL schema. The AI can identify:

- Complex query chains
- Business logic flaws
- Security vulnerabilities
- Performance issues

### Customizing AI Prompts

You can customize the AI prompts by extending the `AISuggestor` class:

```python
from vulnbuster.modules.graphql.ai_suggestor import AISuggestor

class CustomAISuggestor(AISuggestor):
    async def suggest_query_chains(self, schema: Dict[str, Any]) -> List[Dict[str, Any]]:
        # Custom implementation
        pass
```

## Testing Strategy

The fuzzer employs a multi-layered testing approach:

1. **Schema Analysis**: Examines the GraphQL schema for potential issues
2. **Type Fuzzing**: Tests each field with various input types
3. **Query Chaining**: Tests complex query combinations
4. **Mutation Testing**: Attempts to bypass business logic
5. **AI Analysis**: Generates sophisticated test cases

## Security Considerations

- Always test against a staging environment first
- Be cautious with destructive operations
- Monitor API rate limits
- Review generated queries before execution in production

## Contributing

Contributions are welcome! Please read our [contributing guidelines](CONTRIBUTING.md) before submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. (`fuzzer.py`)
Advanced fuzzing engine that tests for:
- Introspection vulnerabilities
- Query batching attacks
- Field suggestion leaks
- Directive bypasses
- Query depth attacks

### GraphQL Scanner (`scanner.py`)
VulnBuster scanner implementation that:
- Integrates with the VulnBuster framework
- Converts findings to standardized report format
- Handles configuration and cleanup

### Utilities (`utils.py`)
Helper functions for:
- Detecting GraphQL endpoints
- Analyzing query complexity
- Generating sample queries
- Parsing and validating GraphQL responses

## Usage

### Basic Usage

```python
from vulnbuster.modules.graphql.scanner import GraphQLScanner
from vulnbuster.interfaces.enhanced_scanner import ScanResult

async def scan_graphql():
    # Create a scanner instance
    scanner = GraphQLScanner()
    
    # Configure the scanner
    config = {
        "target": "https://example.com/graphql",
        "headers": {
            "Authorization": "Bearer token123"
        }
    }
    
    # Initialize the scanner
    await scanner.setup(config)
    
    # Create a result object
    result = ScanResult()
    
    # Run the scan
    await scanner.run_scan(config["target"], result, {})
    
    # Print the findings
    for finding in result.findings:
        print(f"[{finding.severity}] {finding.title}")
    
    # Clean up
    await scanner.cleanup()

# Run the scan
import asyncio
asyncio.run(scan_graphql())
```

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `target` | string | Required | The GraphQL endpoint URL |
| `headers` | dict | `{}` | Custom HTTP headers |
| `timeout` | int | `30` | Request timeout in seconds |
| `max_depth` | int | `3` | Maximum query depth for generation |
| `max_queries` | int | `100` | Maximum number of queries to generate |
| `fuzz_timeout` | int | `30` | Maximum time to spend fuzzing |

## Detected Vulnerabilities

- **Information Disclosure**: Exposed schema information
- **Denial of Service**: Query batching and depth attacks
- **Security Misconfiguration**: Insecure default configurations
- **Injection**: Potential injection points in queries and mutations
- **Broken Authentication**: Authentication bypass attempts

## Dependencies

- `graphql-core` - For parsing and validating GraphQL
- `aiohttp` - For async HTTP requests
- `pydantic` - For data validation and settings

## License

This module is part of the VulnBuster project and is licensed under the same terms.
