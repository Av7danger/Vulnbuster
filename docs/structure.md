# VulnBuster Directory Structure

```
vulnbuster/
├── 📁 core/                          # Core framework components
│   ├── __init__.py
│   ├── scanner.py                    # Main scanner engine
│   ├── utils.py                      # Utility functions
│   ├── session.py                    # Session management
│   ├── chain.py                      # Exploit chaining
│   ├── analyzer.py                   # Analysis engine
│   ├── reporter.py                   # Report generation
│   ├── repl_interface.py             # REPL interface
│   ├── plugin_loader.py              # Plugin system
│   ├── payloads.py                   # Payload management
│   ├── wordlistgen.py                # Wordlist generation
│   ├── csrf.py                       # CSRF utilities
│   ├── poc_builder.py                # PoC builder
│   ├── payload_learning.py           # Payload learning
│   ├── aee_engine.py                 # AI exploitation engine
│   ├── rule_engine.py                # Auto rule learner
│   ├── flow_renderer.py              # Visual flow renderer
│   ├── payload_diff.py               # Payload diff viewer
│   ├── vuln_replay.py                # Vulnerability replay
│   ├── waf_bypass.py                 # WAF bypass engine
│   ├── discover.py                   # Content discovery
│   ├── shellgen.py                   # Reverse shell generator
│   └── ai.py                         # AI utilities
│
├── 📁 ai/                            # AI and machine learning
│   ├── __init__.py
│   ├── via_engine.py                 # VIA AI engine
│   ├── ai_bridge.py                  # AI bridge utilities
│   ├── poc_builder.py                # AI PoC builder
│   ├── ai_shell.py                   # AI shell generator
│   ├── ai_gadget_suggester.py        # ROP gadget suggester
│   ├── prompt_tuner.py               # Prompt tuning system
│   └── memory.py                     # AI memory system
│
├── 📁 modes/                         # Scanning modes
│   ├── __init__.py
│   ├── web/                          # Web application scanning
│   │   ├── __init__.py
│   │   ├── scanner.py
│   │   ├── crawler.py
│   │   └── modules/                  # Web-specific modules
│   │       ├── __init__.py
│   │       ├── xss.py
│   │       ├── sqli.py
│   │       ├── ssrf.py
│   │       ├── lfi.py
│   │       ├── csrf.py
│   │       ├── idor.py
│   │       ├── upload.py
│   │       ├── redirect.py
│   │       ├── cors.py
│   │       ├── clickjacking.py
│   │       ├── websocket.py
│   │       ├── ssti.py
│   │       ├── xxe.py
│   │       ├── dom_xss.py
│   │       ├── header_injection.py
│   │       ├── graphql.py
│   │       ├── jwt_analyzer.py
│   │       ├── upload_path_brute.py
│   │       ├── lfi_exploiter.py
│   │       ├── subdomain_takeover.py
│   │       ├── git_leaks.py
│   │       └── pollution.py
│   ├── android/                      # Android application scanning
│   │   ├── __init__.py
│   │   └── scanner.py
│   ├── ios/                          # iOS application scanning
│   │   ├── __init__.py
│   │   └── scanner.py
│   ├── cloud/                        # Cloud infrastructure scanning
│   │   ├── __init__.py
│   │   └── scanner.py
│   ├── windows/                      # Windows binary scanning
│   │   ├── __init__.py
│   │   └── scanner.py
│   ├── iot/                          # IoT device scanning
│   │   ├── __init__.py
│   │   └── scanner.py
│   └── edge/                         # Edge computing scanning
│       ├── __init__.py
│       └── scanner.py
│
├── 📁 modules/                       # Shared vulnerability modules
│   ├── __init__.py
│   ├── exploitdb_finder.py           # Exploit-DB integration
│   ├── ssrf.py                       # SSRF scanner
│   ├── header_injection.py           # Header injection
│   ├── graphql.py                    # GraphQL scanner
│   ├── git_leaks.py                  # Git repository leaks
│   ├── subdomain_takeover.py         # Subdomain takeover
│   ├── pollution.py                  # Parameter pollution
│   ├── jwt_analyzer.py               # JWT analysis
│   ├── upload_path_brute.py          # Upload path bruteforcing
│   ├── lfi_exploiter.py              # LFI exploitation
│   ├── subdomain_brute.py            # Subdomain bruteforcing
│   └── fingerprint.py                # Target fingerprinting
│
├── 📁 post_exploitation/             # Post-exploitation tools
│   ├── __init__.py
│   ├── db_enum.py                    # Database enumeration
│   ├── shell_verifier.py             # Shell verification
│   ├── auto_shell_uploader.py        # Auto shell uploader
│   ├── shellcheck.py                 # Shell checker
│   ├── sqli_enum.py                  # SQLi enumeration
│   └── xss_webhook.py                # XSS webhook handler
│
├── 📁 binex/                         # Binary exploitation
│   ├── __init__.py
│   └── static_analyzer.py            # Static binary analysis
│
├── 📁 network/                       # Network reconnaissance
│   ├── __init__.py
│   └── portscan.py                   # Port and service scanning
│
├── 📁 recon/                         # Reconnaissance tools
│   ├── __init__.py
│   └── api_intel.py                  # API intelligence (Shodan, Censys)
│
├── 📁 bypass/                        # WAF and protection bypass
│   ├── __init__.py
│   └── waf_engine.py                 # WAF bypass engine
│
├── 📁 dynamic/                       # Dynamic analysis
│   ├── __init__.py
│   ├── frida_runner.py               # Frida dynamic analysis
│   └── logs/                         # Dynamic analysis logs
│
├── 📁 oob/                           # Out-of-band detection
│   ├── __init__.py
│   ├── http_listener.py              # HTTP OOB listener
│   ├── dns_listener.py               # DNS OOB listener
│   └── webhook_listener.py           # Webhook OOB listener
│
├── 📁 ctf_modules/                   # CTF-specific modules
│   ├── __init__.py
│   └── ctf_challenges.py             # CTF challenge support
│
├── 📁 payloads/                      # Payload collections
│   ├── __init__.py
│   ├── mutators.py                   # Payload mutators
│   ├── xss.json                      # XSS payloads
│   ├── sqli.json                     # SQLi payloads
│   └── lfi.json                      # LFI payloads
│
├── 📁 templates/                     # Report templates
│   ├── __init__.py
│   ├── report_template.html          # Basic HTML template
│   └── report_pentest.html.j2        # Pentest Jinja2 template
│
├── 📁 config/                        # Configuration files
│   ├── __init__.py
│   ├── config.json                   # Main configuration
│   └── scan_profiles.json            # Scan profiles
│
├── 📁 prompts/                       # AI prompt templates
│   ├── __init__.py
│   └── template_poc.j2               # PoC generation template
│
├── 📁 kb/                            # Knowledge base
│   ├── __init__.py
│   └── core_index.py                 # Knowledge base index
│
├── 📁 scripts/                       # Utility scripts
│   ├── __init__.py
│   └── ci_cd_runner.py               # CI/CD runner
│
├── 📁 plugins/                       # Plugin system
│   ├── __init__.py
│   └── README.md                     # Plugin development guide
│
├── 📁 wordlists/                     # Wordlist collections
│   ├── __init__.py
│   ├── subdomains.txt                # Subdomain wordlist
│   ├── directories.txt               # Directory wordlist
│   └── parameters.txt                # Parameter wordlist
│
├── 📁 reports/                       # Generated reports
│   ├── __init__.py
│   └── README.md                     # Reports documentation
│
├── 📁 docs/                          # Documentation
│   ├── __init__.py
│   ├── user-guide.md                 # User guide
│   ├── api-reference.md              # API reference
│   ├── module-development.md         # Module development guide
│   ├── ai-integration.md             # AI integration guide
│   ├── deployment.md                 # Deployment guide
│   └── structure.md                  # This file
│
├── 📁 tests/                         # Test suite
│   ├── __init__.py
│   ├── test_core.py                  # Core tests
│   ├── test_modules.py               # Module tests
│   ├── test_ai.py                    # AI tests
│   └── test_integration.py           # Integration tests
│
├── 📁 examples/                      # Usage examples
│   ├── __init__.py
│   ├── basic_scan.py                 # Basic scan example
│   ├── ai_enhanced_scan.py           # AI-enhanced scan example
│   ├── ctf_scan.py                   # CTF scan example
│   └── bug_bounty_scan.py            # Bug bounty scan example
│
├── 📁 docker/                        # Docker configuration
│   ├── Dockerfile                    # Main Dockerfile
│   ├── docker-compose.yml            # Docker Compose
│   └── docker-entrypoint.sh          # Docker entrypoint
│
├── 📁 .github/                       # GitHub configuration
│   ├── workflows/                    # GitHub Actions
│   │   ├── ci.yml                    # Continuous integration
│   │   ├── security.yml              # Security scanning
│   │   └── release.yml               # Release automation
│   ├── ISSUE_TEMPLATE/               # Issue templates
│   └── PULL_REQUEST_TEMPLATE.md      # PR template
│
├── 📁 memory/                        # AI memory storage
│   ├── __init__.py
│   └── logs.json                     # AI interaction logs
│
├── 📁 audit/                         # Audit logs
│   ├── __init__.py
│   └── recording.jsonl               # Scan recording logs
│
├── 📁 kb/                            # Knowledge base storage
│   ├── __init__.py
│   ├── findings.jsonl                # Scan findings
│   └── confirmed_vulns.jsonl         # Confirmed vulnerabilities
│
├── 📄 main.py                        # Main entry point
├── 📄 requirements.txt               # Python dependencies
├── 📄 requirements-dev.txt           # Development dependencies
├── 📄 requirements-full.txt          # Full dependencies
├── 📄 setup.py                       # Package setup
├── 📄 pyproject.toml                 # Modern Python packaging
├── 📄 README.md                      # Main documentation
├── 📄 LICENSE                        # License file
├── 📄 CONTRIBUTING.md                # Contributing guidelines
├── 📄 CHANGELOG.md                   # Version history
├── 📄 SECURITY.md                    # Security policy
├── 📄 CODE_OF_CONDUCT.md             # Code of conduct
├── 📄 .gitignore                     # Git ignore rules
├── 📄 .pre-commit-config.yaml        # Pre-commit hooks
├── 📄 pytest.ini                     # Pytest configuration
├── 📄 tox.ini                        # Tox configuration
└── 📄 Makefile                       # Build automation
```

## Directory Purpose

### Core Framework (`core/`)
Contains the main framework components, engines, and utilities that power VulnBuster.

### AI System (`ai/`)
All AI-related components including the VIA engine, prompt tuning, and memory system.

### Scanning Modes (`modes/`)
Domain-specific scanners for web, mobile, cloud, IoT, and other targets.

### Modules (`modules/`)
Shared vulnerability detection and exploitation modules used across modes.

### Post-Exploitation (`post_exploitation/`)
Tools for post-exploitation activities like database enumeration and shell verification.

### Specialized Tools
- **Binary Exploitation** (`binex/`) - ELF/PE analysis
- **Network Recon** (`network/`) - Port scanning and service detection
- **Reconnaissance** (`recon/`) - API intelligence and external data
- **Bypass** (`bypass/`) - WAF and protection evasion
- **Dynamic Analysis** (`dynamic/`) - Runtime analysis with Frida
- **OOB Detection** (`oob/`) - Out-of-band vulnerability detection

### Configuration and Data
- **Config** (`config/`) - Configuration files and scan profiles
- **Payloads** (`payloads/`) - Attack payload collections
- **Templates** (`templates/`) - Report templates
- **Wordlists** (`wordlists/`) - Dictionary files
- **Knowledge Base** (`kb/`) - Learning and pattern storage

### Development and Deployment
- **Scripts** (`scripts/`) - Utility scripts and CI/CD runners
- **Tests** (`tests/`) - Comprehensive test suite
- **Examples** (`examples/`) - Usage examples and tutorials
- **Documentation** (`docs/`) - Complete documentation
- **Docker** (`docker/`) - Containerization support

### AI and Memory
- **Prompts** (`prompts/`) - AI prompt templates
- **Memory** (`memory/`) - AI interaction storage
- **Audit** (`audit/`) - Scan recording and replay

This structure provides:
- **Clear separation** of concerns
- **Easy navigation** and discovery
- **Scalable architecture** for future features
- **Professional organization** suitable for enterprise use
- **Comprehensive coverage** of all security testing domains 