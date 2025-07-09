# VulnBuster API Reference

## Core Framework

### Scanner Class
```python
from core.scanner import Scanner

scanner = Scanner(config)
results = await scanner.scan(target)
```

### AI Engine
```python
from core.ai import ask_mixtral, summarize_scan

# Ask AI for suggestions
response = await ask_mixtral(prompt, context)

# Summarize scan results
summary = await summarize_scan(results)
```

### Payload Engine
```python
from core.payloads import PayloadEngine

engine = PayloadEngine()
payloads = engine.get_payloads('xss')
```

## AI Modules

### Prompt Tuner
```python
from ai.prompt_tuner import tune_prompt

enhanced_prompt = await tune_prompt('poc', base_prompt, context)
```

### AI Memory
```python
from ai.memory import AIMemory

memory = AIMemory()
session_id = await memory.log_interaction(prompt, response, context)
relevant = await memory.recall_context(current_prompt)
```

## Vulnerability Modules

### SSRF Scanner
```python
from modules.ssrf import test_ssrf

results = await test_ssrf(url, protocols, bypasses, oob_handler)
```

### WAF Bypass Engine
```python
from bypass.waf_engine import WAFBypassEngine

bypass_engine = WAFBypassEngine()
mutations = await bypass_engine.mutate_payload(payload, technique)
results = await bypass_engine.run_bypass_campaign(target_url, payloads)
```

### Dynamic Analysis
```python
from dynamic.frida_runner import FridaRunner

runner = FridaRunner(target_package)
await runner.connect_device()
await runner.attach_to_app()
await runner.inject_hooks()
results = await runner.run_dynamic_analysis(duration=60)
```

## Post-Exploitation

### Database Enumeration
```python
from post_exploitation.db_enum import dump_db, ai_analyze_hash

data = await dump_db(target, dbtype='mysql')
analysis = await ai_analyze_hash(hash_string)
```

### Shell Verification
```python
from post_exploitation.shell_verifier import verify_shell_execution

result = await verify_shell_execution(shell_url)
```

## Reconnaissance

### API Intelligence
```python
from recon.api_intel import APIIntelligence

intel = APIIntelligence(shodan_key, censys_creds, dnsdb_key)
enrichment = await intel.enrich_host(target)
analysis = await intel.ai_analyze_enrichment(enrichment)
```

### Port Scanning
```python
from network.portscan import active_port_scan, passive_service_detect

ports = await active_port_scan(host, [80, 443, 8080])
services = await passive_service_detect(headers)
```

## Configuration

### Scan Profiles
```python
import json

with open('config/scan_profiles.json', 'r') as f:
    profiles = json.load(f)

recon_profile = profiles['recon']
```

### Custom Configuration
```python
config = {
    'mode': 'web',
    'target': 'https://target.com',
    'modules': ['xss', 'sqli', 'ssrf'],
    'ai_mode': 'full',
    'waf_bypass': True,
    'api_enrich': True
}
```

## CLI Integration

### Main Entry Point
```python
from main import VulnBuster, build_config_from_args

args = parse_arguments()
config = build_config_from_args(args)
vulnbuster = VulnBuster(config)
results = await vulnbuster.run_scan()
```

### CI/CD Runner
```python
from scripts.ci_cd_runner import CICDRunner

runner = CICDRunner()
result = await runner.run_scan(config)
runner.output_json(result)
```

## Data Structures

### Scan Results
```python
{
    'type': 'xss',
    'url': 'https://target.com/page',
    'parameter': 'search',
    'payload': '<script>alert(1)</script>',
    'severity': 'high',
    'description': 'Reflected XSS vulnerability',
    'evidence': 'Response contains payload',
    'remediation': 'Input validation required'
}
```

### AI Context
```python
{
    'target_url': 'https://target.com',
    'tech_stack': ['php', 'apache', 'mysql'],
    'previous_findings': ['sqli', 'idor'],
    'headers': {'Server': 'Apache/2.4.29'},
    'parameters': ['id', 'search', 'user']
}
```

## Error Handling

### Exception Types
```python
class VulnBusterError(Exception):
    """Base exception for VulnBuster"""
    pass

class ConfigurationError(VulnBusterError):
    """Configuration-related errors"""
    pass

class ScanError(VulnBusterError):
    """Scan execution errors"""
    pass

class AIError(VulnBusterError):
    """AI-related errors"""
    pass
```

### Error Handling Example
```python
try:
    results = await scanner.scan(target)
except ScanError as e:
    print(f"Scan failed: {e}")
except AIError as e:
    print(f"AI error: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
```

## Logging

### Logger Configuration
```python
import logging
from core.utils import setup_logging

setup_logging(verbose=True)
logger = logging.getLogger('vulnbuster')
```

### Log Levels
- `DEBUG`: Detailed debugging information
- `INFO`: General information about scan progress
- `WARNING`: Warning messages for potential issues
- `ERROR`: Error messages for failed operations
- `CRITICAL`: Critical errors that may stop execution

## Performance

### Async Operations
All VulnBuster operations are async for optimal performance:

```python
import asyncio

async def main():
    scanner = Scanner(config)
    results = await scanner.scan(target)
    return results

results = asyncio.run(main())
```

### Batch Operations
```python
# Scan multiple targets
targets = ['https://target1.com', 'https://target2.com']
tasks = [scanner.scan(target) for target in targets]
results = await asyncio.gather(*tasks)
```

## Security Considerations

### Input Validation
```python
from core.utils import validate_url, sanitize_input

url = validate_url(input_url)
payload = sanitize_input(user_payload)
```

### Rate Limiting
```python
import asyncio

async def rate_limited_request(url, delay=1):
    await asyncio.sleep(delay)
    # Make request
```

### Error Information
```python
# Don't expose sensitive information in errors
try:
    result = await sensitive_operation()
except Exception as e:
    logger.error("Operation failed")
    # Don't log e directly if it contains sensitive data
``` 