# Web Application Scanning

VulnBuster's web application scanner is designed to identify security vulnerabilities in web applications. This guide covers how to use the web scanner effectively.

## 🎯 Features

- **Comprehensive Scanning**
  - Crawling and discovery
  - Parameter analysis
  - Authentication testing
  - Session management testing

- **Vulnerability Detection**
  - OWASP Top 10 vulnerabilities
  - Business logic flaws
  - Configuration issues
  - Information disclosure

- **Advanced Techniques**
  - AI-powered fuzzing
  - Context-aware scanning
  - Custom payload support
  - False positive reduction

## 🚀 Basic Usage

### Quick Scan

```bash
vulnbuster scan https://example.com
```

### Full Scan with All Checks

```bash
vulnbuster scan https://example.com --full
```

### Scan with Authentication

```bash
vulnbuster scan https://example.com --auth-type form \
  --auth-url https://example.com/login \
  --auth-data 'username=admin&password=pass123&login=submit'
```

## 🔧 Configuration Options

### Scan Scope

```bash
# Limit crawling to specific paths
vulnbuster scan https://example.com --include '/api/,/admin/'

# Exclude specific paths
vulnbuster scan https://example.com --exclude '/logout,/cgi-bin/'

# Set crawl depth (default: 5)
vulnbuster scan https://example.com --depth 3
```

### Performance Tuning

```bash
# Set number of concurrent requests (default: 10)
vulnbuster scan https://example.com --threads 20

# Set request timeout in seconds (default: 30)
vulnbuster scan https://example.com --timeout 60

# Rate limit requests per second
vulnbuster scan https://example.com --rate-limit 5
```

### Authentication

#### Form-based Authentication

```bash
vulnbuster scan https://example.com --auth-type form \
  --auth-url https://example.com/login \
  --auth-data 'username=admin&password=pass123&login=submit' \
  --auth-verify 'Logout'  # Verification string
```

#### HTTP Basic Authentication

```bash
vulnbuster scan https://example.com --auth-type basic \
  --auth-cred 'admin:pass123'
```

#### Session-based Authentication

```bash
# Using cookies
vulnbuster scan https://example.com --cookie 'PHPSESSID=abc123; csrftoken=xyz456'

# Using headers
vulnbuster scan https://example.com --header 'Authorization: Bearer token123'
```

## 🔍 Advanced Scanning

### Custom Headers

```bash
vulnbuster scan https://example.com \
  --header 'User-Agent: Custom-Agent/1.0' \
  --header 'X-Custom-Header: value'
```

### Proxy Support

```bash
# HTTP/HTTPS proxy
vulnbuster scan https://example.com --proxy http://proxy:8080

# SOCKS proxy
vulnbuster scan https://example.com --proxy socks5://user:pass@proxy:1080
```

### Custom Payloads

```bash
# Load custom payloads from file
vulnbuster scan https://example.com --payloads ./custom-payloads.txt

# Use specific payload sets
vulnbuster scan https://example.com --payload-sets xss,sqli,command-injection
```

### API Scanning

```bash
# Scan OpenAPI/Swagger specification
vulnbuster api-scan https://api.example.com --openapi openapi.json

# Scan GraphQL endpoint
vulnbuster api-scan https://api.example.com/graphql --graphql

# Custom API endpoint testing
vulnbuster api-scan https://api.example.com/endpoint --method POST \
  --data '{"param1":"value1"}' --content-type 'application/json'
```

## 📊 Reporting

### Generate Reports

```bash
# HTML report (default)
vulnbuster scan https://example.com --output report.html

# JSON report
vulnbuster scan https://example.com --format json --output report.json

# PDF report
vulnbuster scan https://example.com --format pdf --output report.pdf

# Multiple formats
vulnbuster scan https://example.com --format html,json,pdf --output-dir reports/
```

### Report Options

```bash
# Include request/response samples
vulnbuster scan https://example.com --include-samples

# Include remediation advice
vulnbuster scan https://example.com --include-remediation

# Custom report template
vulnbuster scan https://example.com --template ./custom-template.html
```

## 🛡️ Security Considerations

### Safe Scanning

```bash
# Read-only mode (no destructive actions)
vulnbuster scan https://example.com --readonly

# Skip dangerous tests
vulnbuster scan https://example.com --skip-dangerous

# Set a custom user agent
vulnbuster scan https://example.com --user-agent 'VulnBuster Security Scan'
```

### Rate Limiting

```bash
# Respect robots.txt
vulnbuster scan https://example.com --respect-robots

# Add delay between requests (seconds)
vulnbuster scan https://example.com --delay 1.5

# Limit scan time (minutes)
vulnbuster scan https://example.com --max-scan-time 60
```

## 🧩 Plugins

### List Available Plugins

```bash
vulnbuster plugins list
```

### Enable/Disable Plugins

```bash
# Enable specific plugins
vulnbuster scan https://example.com --enable-plugins xss,sqli

# Disable specific plugins
vulnbuster scan https://example.com --disable-plugins brute-force

# Load plugins from directory
vulnbuster scan https://example.com --plugin-dir ./custom-plugins/
```

## 🧪 Testing Methodology

### Scan Phases

1. **Discovery**
   - Spidering/crawling
   - Parameter discovery
   - Technology fingerprinting

2. **Assessment**
   - Vulnerability scanning
   - Configuration testing
   - Authentication testing

3. **Verification**
   - False positive reduction
   - Manual verification
   - Risk assessment

### Custom Test Cases

```yaml
# tests/custom-tests.yaml
- name: Custom SQL Injection Test
  type: sqli
  description: Tests for custom SQL injection vectors
  payloads:
    - "' OR '1'='1"
    - "' OR 1=1--"
  matchers:
    - type: regex
      pattern: '(SQL syntax|MySQL|PostgreSQL|ORA-|error in your SQL)'
      part: response_body
```

```bash
# Run with custom tests
vulnbuster scan https://example.com --tests ./tests/custom-tests.yaml
```

## 🚨 Troubleshooting

### Common Issues

1. **Connection Errors**
   - Verify network connectivity
   - Check if the target is reachable
   - Try with `--proxy` if behind a firewall

2. **Authentication Failures**
   - Verify credentials
   - Check for CSRF tokens
   - Try with `--debug` for more details

3. **Scan Too Slow**
   - Reduce thread count
   - Increase timeout values
   - Use `--fast` mode for quick scans

### Debugging

```bash
# Enable debug output
vulnbuster scan https://example.com --debug

# Save debug logs to file
vulnbuster scan https://example.com --log-file debug.log

# Set log level (debug, info, warning, error, critical)
vulnbuster scan https://example.com --log-level debug
```

## 📚 Additional Resources

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [Mozilla Web Security Guidelines](https://infosec.mozilla.org/guidelines/web_security)

## ➡️ Next Steps

- Learn about [Mobile Security Analysis](../mobile-analysis.md)
- Explore [Cloud Security Scanning](../cloud-scanning.md)
- Read about [AI-Powered Analysis](../ai-analysis.md)
