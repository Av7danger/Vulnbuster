# 🧨 VulnBuster - AI-Powered Offensive Security Framework

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://hub.docker.com/)
[![CI/CD](https://img.shields.io/badge/CI%2FCD-Ready-green.svg)](https://github.com/features/actions)
[![AI-Powered](https://img.shields.io/badge/AI--Powered-Mixtral-orange.svg)](https://mistral.ai/)
[![Multi-Domain](https://img.shields.io/badge/Multi--Domain-Web%2FMobile%2FCloud%2FIoT-purple.svg)]()

> **The Ultimate AI-Augmented Offensive Security Framework for CTFs, Bug Bounties, and Red Teams**

VulnBuster combines cutting-edge AI intelligence with comprehensive vulnerability scanning, exploitation, and post-exploitation capabilities across multiple domains. Built for the modern security researcher, it automates complex attack chains and provides intelligent insights that traditional tools miss.

## 🌟 Features

### 🧠 AI-Augmented Capabilities
- **AI Payload Oracle** - Dynamic payload selection based on context and tech stack
- **Intelligent PoC Generator** - Auto-generate exploits in Python, cURL, JavaScript
- **Chain Reasoner** - AI-powered vulnerability chaining and exploit suggestions
- **Memory-Enhanced Context** - Learn from past scans and improve over time
- **Risk-Aware Reporting** - AI-generated risk assessments and remediation guidance

### ⚔️ Multi-Domain Coverage
- **Web Applications** - XSS, SQLi, SSRF, LFI, CSRF, IDOR, GraphQL, JWT
- **Mobile Apps** - Android APK analysis, iOS IPA analysis
- **Cloud Infrastructure** - AWS, GCP, Azure security testing
- **IoT/Edge Devices** - Firmware analysis and device testing
- **Binary Exploitation** - ELF/PE analysis, ROP chain generation

### 🛡️ Advanced Offensive Modules
- **WAF Bypass Engine** - Advanced evasion techniques with AI suggestions
- **Dynamic Analysis** - Frida hooks, sandbox execution, memory analysis
- **API Intelligence** - Shodan, Censys, DNSDB integration
- **Subdomain Takeover** - DNS misconfiguration detection
- **Reverse Shell Toolkit** - Multi-language payload generation

### 🧪 Post-Exploitation Tools
- **Database Enumeration** - Auto-dump and analyze after SQLi
- **Shell Verification** - Confirm shell execution and functionality
- **File Upload Exploitation** - Path bruteforcing and verification
- **JWT Analysis** - Token forging and vulnerability detection
- **LFI Exploitation** - Auto-attempt common LFI targets

### 🚀 Production Features
- **Docker Support** - Containerized deployment
- **CI/CD Integration** - GitHub Actions, GitLab CI ready
- **Scan Profiles** - Recon, exploit, bounty-hardcore, CTF modes
- **Visual Flow Rendering** - Interactive scan visualization
- **Offline Mode** - Air-gapped environment support

## 📦 Installation

### Quick Start (Docker)
```bash
# Pull and run VulnBuster
docker pull vulnbuster/framework:latest
docker run -it vulnbuster/framework --help
```

### Local Installation
```bash
# Clone repository
git clone https://github.com/your-username/vulnbuster.git
cd vulnbuster

# Install dependencies
pip install -r requirements.txt

# Install optional tools
sudo apt-get install nmap sqlmap dirb nikto frida-tools

# Verify installation
python main.py --help
```

### Advanced Setup
```bash
# Install with all optional dependencies
pip install -r requirements-full.txt

# Setup API keys for enhanced features
export SHODAN_API_KEY="your-shodan-key"
export CENSYS_API_ID="your-censys-id"
export CENSYS_API_SECRET="your-censys-secret"
export DNSDB_API_KEY="your-dnsdb-key"
```

## 🚀 Usage

### Basic Web Application Scan
```bash
# Simple vulnerability scan
python main.py --mode web -u https://target.com --vulns xss,sqli,ssrf

# AI-enhanced scan with automatic exploitation
python main.py --mode web -u https://target.com --ai-mode full --auto-poc --exploit-chain
```

### Bug Bounty Hardcore Mode
```bash
# Comprehensive bug bounty scan
python main.py --mode web -u https://target.com \
  --profile bounty-hardcore \
  --ai-tune --ai-memory \
  --waf-bypass --api-enrich \
  --fingerprint --subdomain-brute \
  --record --flow-render
```

### CTF Mode
```bash
# CTF-focused scanning
python main.py --mode web -u https://target.com \
  --profile ctf \
  --lfi-exploit --upload-brute \
  --jwt-analyze --shell-verify \
  --exploit-chain --oracle-mode
```

### Mobile Application Analysis
```bash
# Android APK analysis
python main.py --mode android --apk app.apk \
  --android-dynamic --frida \
  --scan-apis --scan-keys \
  --build-wordlist

# iOS IPA analysis
python main.py --mode ios --ipa app.ipa \
  --scan-manifest --list-components
```

### Cloud Infrastructure Testing
```bash
# AWS security testing
python main.py --mode cloud --provider aws \
  --scan iam,s3,lambda,ec2 \
  --api-enrich --offline
```

### CI/CD Integration
```bash
# Automated pipeline scanning
python scripts/ci_cd_runner.py \
  --target https://target.com \
  --profile recon \
  --offline --format json

# Docker CI/CD
docker run vulnbuster/framework \
  --mode web -u https://target.com \
  --ci-cd --format json
```

## 🧠 AI Features

### AI Payload Oracle
```bash
# Enable AI-driven payload selection
python main.py --mode web -u https://target.com --oracle-mode

# AI will dynamically select payloads based on:
# - Parameter names and context
# - Technology stack detection
# - Previous successful payloads
# - WAF bypass requirements
```

### AI Memory and Learning
```bash
# Enable AI memory for context recall
python main.py --mode web -u https://target.com --ai-memory

# AI will:
# - Remember successful attack patterns
# - Suggest improvements based on past scans
# - Adapt payloads for similar targets
# - Learn from false positives/negatives
```

### AI Chain Reasoning
```bash
# Enable AI exploit chaining
python main.py --mode web -u https://target.com --exploit-chain

# AI will suggest chains like:
# - IDOR → File Upload → RCE
# - LFI → Log Injection → Shell
# - SQLi → File Write → Web Shell
```

## 🛡️ Advanced Features

### WAF Bypass Engine
```bash
# Advanced WAF bypass with AI suggestions
python main.py --mode web -u https://target.com \
  --waf-bypass --bypass-technique auto

# Techniques include:
# - Case variations and encoding
# - Keyword splitting and comments
# - AI-suggested bypass patterns
# - Response analysis for 403/406 patterns
```

### Dynamic Analysis
```bash
# Android dynamic analysis with Frida
python main.py --mode android --apk app.apk \
  --android-dynamic --frida --emulator

# Features:
# - Memory string extraction
# - Syscall tracking
# - Network call monitoring
# - File operation logging
```

### API Intelligence
```bash
# Enhanced reconnaissance with API data
python main.py --mode web -u https://target.com \
  --api-enrich --shodan-key YOUR_KEY \
  --censys-creds ID:SECRET --dnsdb-key YOUR_KEY

# Enrichment includes:
# - Host information and port scans
# - DNS history and subdomains
# - Technology stack detection
# - AI-powered vulnerability suggestions
```

## 📊 Output and Reporting

### Report Formats
```bash
# Generate multiple report formats
python main.py --mode web -u https://target.com \
  --format html,json,markdown \
  --report-template pentest \
  --client "Client Name"

# Available formats:
# - HTML (interactive with charts)
# - JSON (machine-readable)
# - Markdown (documentation)
# - All formats simultaneously
```

### CI/CD Output
```bash
# Clean JSON output for pipelines
python main.py --mode web -u https://target.com \
  --ci-cd --format json

# Output includes:
# - Vulnerability summary
# - Risk scoring
# - Exploit suggestions
# - Machine-readable format
```

## 🔧 Configuration

### Scan Profiles
```bash
# Use predefined scan profiles
python main.py --profile recon      # Reconnaissance mode
python main.py --profile exploit    # Exploitation mode
python main.py --profile bounty-hardcore  # Bug bounty mode
python main.py --profile ctf        # CTF mode
```

### Custom Configuration
```json
{
  "mode": "web",
  "ai_mode": "full",
  "modules": ["xss", "sqli", "ssrf"],
  "waf_bypass": true,
  "api_enrich": true,
  "ai_memory": true,
  "output": "reports",
  "format": ["html", "json"]
}
```

## 🐳 Docker Support

### Quick Docker Commands
```bash
# Build image
docker build -t vulnbuster .

# Run basic scan
docker run vulnbuster --mode web -u https://target.com

# Run with volume mounts
docker run -v $(pwd)/reports:/app/reports vulnbuster \
  --mode web -u https://target.com --format json

# Run in CI/CD mode
docker run vulnbuster --ci-cd --mode web -u https://target.com
```

## 🔒 Security and Ethics

### Responsible Disclosure
- VulnBuster is designed for authorized security testing only
- Always obtain proper authorization before scanning targets
- Follow responsible disclosure practices
- Respect rate limits and terms of service

### Legal Compliance
- Use only on systems you own or have explicit permission to test
- Comply with local laws and regulations
- Follow bug bounty program rules and guidelines
- Respect privacy and data protection requirements

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup
```bash
# Clone and setup development environment
git clone https://github.com/your-username/vulnbuster.git
cd vulnbuster
pip install -r requirements-dev.txt
pre-commit install
```

### Testing
```bash
# Run tests
python -m pytest tests/

# Run with coverage
python -m pytest tests/ --cov=vulnbuster --cov-report=html
```

## 📈 Roadmap

### 🚀 Version 2.0 (Q2 2024)
- [ ] **Real-time sandbox integration**
- [ ] **Advanced WAF bypass techniques**
- [ ] **Machine learning model training**
- [ ] **Cloud-native deployment options**
- [ ] **Enterprise features and integrations**

### 🔮 Version 2.1 (Q3 2024)
- [ ] **Zero-day vulnerability detection**
- [ ] **Advanced social engineering modules**
- [ ] **Blockchain/Web3 security testing**
- [ ] **IoT device exploitation**
- [ ] **Mobile app reverse engineering**

### 🌟 Version 2.2 (Q4 2024)
- [ ] **AI-powered social engineering**
- [ ] **Advanced persistence mechanisms**
- [ ] **Multi-vector attack simulation**
- [ ] **Real-time threat intelligence**
- [ ] **Advanced evasion techniques**

## 📚 Documentation

- [User Guide](docs/user-guide.md)
- [API Reference](docs/api-reference.md)
- [Module Development](docs/module-development.md)
- [AI Integration](docs/ai-integration.md)
- [Deployment Guide](docs/deployment.md)

## 🏆 Benchmarks

VulnBuster has been tested against industry-leading tools:

| Feature | VulnBuster | Burp Suite Pro | Nuclei | Metasploit |
|---------|------------|----------------|--------|------------|
| AI-Powered | ✅ | ❌ | ❌ | ❌ |
| Multi-Domain | ✅ | ❌ | ❌ | ❌ |
| Exploit Chaining | ✅ | ❌ | ❌ | ❌ |
| WAF Bypass | ✅ | ⚠️ | ❌ | ❌ |
| Dynamic Analysis | ✅ | ⚠️ | ❌ | ❌ |
| CI/CD Ready | ✅ | ❌ | ✅ | ❌ |
| Open Source | ✅ | ❌ | ✅ | ✅ |

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Mistral AI** for providing the Mixtral model
- **Frida** for dynamic analysis capabilities
- **Shodan, Censys, DNSDB** for API integrations
- **Open source community** for inspiration and tools

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/your-username/vulnbuster/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-username/vulnbuster/discussions)
- **Documentation**: [Wiki](https://github.com/your-username/vulnbuster/wiki)
- **Email**: support@vulnbuster.com

---

**Built with ❤️ by the VulnBuster Team**

*Empowering security researchers with AI-powered offensive security tools.* 