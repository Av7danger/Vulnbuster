# VulnBuster User Guide

## Table of Contents
1. [Getting Started](#getting-started)
2. [Basic Usage](#basic-usage)
3. [Advanced Features](#advanced-features)
4. [AI Integration](#ai-integration)
5. [Scan Modes](#scan-modes)
6. [Reporting](#reporting)
7. [Troubleshooting](#troubleshooting)

## Getting Started

### Installation
```bash
# Quick install
git clone https://github.com/your-username/vulnbuster.git
cd vulnbuster
pip install -r requirements.txt
```

### First Scan
```bash
# Basic web application scan
python main.py --mode web -u https://target.com --vulns xss,sqli
```

## Basic Usage

### Web Application Scanning
```bash
# Scan for common vulnerabilities
python main.py --mode web -u https://target.com --vulns xss,sqli,ssrf,lfi

# AI-enhanced scan
python main.py --mode web -u https://target.com --ai-mode full --auto-poc
```

### Mobile Application Analysis
```bash
# Android APK analysis
python main.py --mode android --apk app.apk --scan-apis --scan-keys

# iOS IPA analysis
python main.py --mode ios --ipa app.ipa --scan-manifest
```

### Cloud Infrastructure Testing
```bash
# AWS security testing
python main.py --mode cloud --provider aws --scan iam,s3,lambda
```

## Advanced Features

### AI-Powered Scanning
```bash
# Enable AI payload oracle
python main.py --mode web -u https://target.com --oracle-mode

# Enable AI memory and learning
python main.py --mode web -u https://target.com --ai-memory

# Enable exploit chaining
python main.py --mode web -u https://target.com --exploit-chain
```

### WAF Bypass
```bash
# Advanced WAF bypass
python main.py --mode web -u https://target.com --waf-bypass

# Specific bypass technique
python main.py --mode web -u https://target.com --waf-bypass --bypass-technique encoding
```

### Dynamic Analysis
```bash
# Android dynamic analysis
python main.py --mode android --apk app.apk --android-dynamic --frida
```

### API Intelligence
```bash
# Enhanced reconnaissance
python main.py --mode web -u https://target.com --api-enrich --shodan-key YOUR_KEY
```

## AI Integration

### AI Payload Oracle
The AI payload oracle dynamically selects payloads based on:
- Parameter names and context
- Technology stack detection
- Previous successful payloads
- WAF bypass requirements

### AI Memory System
The AI memory system:
- Remembers successful attack patterns
- Suggests improvements based on past scans
- Adapts payloads for similar targets
- Learns from false positives/negatives

### AI Chain Reasoning
AI suggests exploit chains like:
- IDOR → File Upload → RCE
- LFI → Log Injection → Shell
- SQLi → File Write → Web Shell

## Scan Modes

### Recon Mode
```bash
python main.py --profile recon -u https://target.com
```
- Passive reconnaissance
- Subdomain enumeration
- Technology fingerprinting
- API intelligence gathering

### Exploit Mode
```bash
python main.py --profile exploit -u https://target.com
```
- Active vulnerability testing
- Exploitation attempts
- Post-exploitation activities
- Shell generation and verification

### Bug Bounty Mode
```bash
python main.py --profile bounty-hardcore -u https://target.com
```
- Comprehensive vulnerability scanning
- AI-enhanced analysis
- Risk scoring and reporting
- Professional report generation

### CTF Mode
```bash
python main.py --profile ctf -u https://target.com
```
- CTF-specific challenges
- LFI/RFI exploitation
- JWT analysis and forging
- Reverse shell generation

## Reporting

### Report Formats
```bash
# Generate multiple formats
python main.py --mode web -u https://target.com --format html,json,markdown

# Professional report
python main.py --mode web -u https://target.com --report-template pentest --client "Client Name"
```

### CI/CD Integration
```bash
# Clean JSON output for pipelines
python main.py --mode web -u https://target.com --ci-cd --format json
```

## Troubleshooting

### Common Issues

#### Installation Problems
```bash
# Update pip
pip install --upgrade pip

# Install with verbose output
pip install -r requirements.txt -v

# Use virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

#### Permission Issues
```bash
# Fix permissions
sudo chmod +x main.py
sudo chmod +x scripts/*.py
```

#### API Key Issues
```bash
# Set environment variables
export SHODAN_API_KEY="your-key"
export CENSYS_API_ID="your-id"
export CENSYS_API_SECRET="your-secret"
```

### Getting Help
- Check the [FAQ](faq.md)
- Review [Issues](https://github.com/your-username/vulnbuster/issues)
- Join our [Discussions](https://github.com/your-username/vulnbuster/discussions)
- Contact support: support@vulnbuster.com 