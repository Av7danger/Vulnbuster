# Mobile Security Analysis

VulnBuster's mobile security module provides comprehensive analysis for both Android and iOS applications. This guide covers how to perform static and dynamic analysis of mobile apps.

## 🎯 Features

- **Android & iOS Support**
  - Static analysis of APK and IPA files
  - Dynamic analysis with Frida integration
  - Runtime instrumentation
  - Binary analysis

- **Vulnerability Detection**
  - Insecure data storage
  - Insecure communication
  - Insecure authentication
  - Code tampering
  - Reverse engineering risks

- **Advanced Analysis**
  - AI-powered vulnerability detection
  - Behavior analysis
  - Custom rule engine
  - Report generation

## 🚀 Getting Started

### Prerequisites

- **Android**
  - Java Development Kit (JDK) 11+
  - Android SDK (for some features)
  - ADB (for device analysis)

- **iOS**
  - macOS (for IPA analysis)
  - Xcode command line tools
  - Jailbroken iOS device (for dynamic analysis)

### Basic Usage

#### Android APK Analysis

```bash
# Basic static analysis
vulnbuster mobile-scan app.apk --platform android

# Full analysis with dynamic instrumentation
vulnbuster mobile-scan app.apk --platform android --frida

# Save report to file
vulnbuster mobile-scan app.apk --platform android --output report.html
```

iOS IPA Analysis

```bash
# Static analysis of IPA file
vulnbuster mobile-scan app.ipa --platform ios

# Dynamic analysis on jailbroken device
vulnbuster mobile-scan app.ipa --platform ios --device-ip 192.168.1.100
```

## 🔧 Configuration

### Android Configuration

```bash
# Set Android SDK path
vulnbuster config set android.sdk_path /path/to/android/sdk

# Enable/disable specific analyzers
vulnbuster mobile-scan app.apk --enable analyzers.dex,analyzers.manifest

# Set custom rules
vulnbuster mobile-scan app.apk --rules ./custom-rules.yaml
```

iOS Configuration

```bash
# Set iOS device IP for dynamic analysis
vulnbuster config set ios.device_ip 192.168.1.100

# Configure Frida settings
vulnbuster config set frida.enabled true
vulnbuster config set frida.script ./custom-script.js
```

## 🔍 Static Analysis

### Manifest Analysis

```bash
# Check manifest for security issues
vulnbuster mobile-analyze manifest AndroidManifest.xml --platform android

# Check Info.plist for iOS
vulnbuster mobile-analyze info-plist Info.plist --platform ios
```

### Code Analysis

```bash
# Analyze DEX files
vulnbuster mobile-analyze dex classes.dex --platform android

# Analyze native libraries
vulnbuster mobile-analyze native lib/ --platform android
```

### Security Checks

```bash
# Check for hardcoded secrets
vulnbuster mobile-analyze secrets app.apk --platform android

# Check for insecure storage
vulnbuster mobile-analyze storage app.apk --platform android

# Check for insecure network communication
vulnbuster mobile-analyze network app.apk --platform android
```

## 🛠️ Dynamic Analysis

### Frida Integration

```bash
# List Frida scripts
vulnbuster frida list-scripts

# Run with specific Frida script
vulnbuster mobile-scan app.apk --frida --script ssl-pinning-bypass.js

# Custom Frida script
vulnbuster mobile-scan app.apk --frida --script custom-hook.js
```

### Runtime Monitoring

```bash
# Monitor file system access
vulnbuster mobile-monitor fs app.apk --output fs_logs.txt

# Monitor network traffic
vulnbuster mobile-monitor network app.apk --output network_logs.pcap

# Monitor cryptographic operations
vulnbuster mobile-monitor crypto app.apk --output crypto_logs.txt
```

### Bypassing Protections

```bash
# Bypass SSL pinning
vulnbuster mobile-scan app.apk --frida --bypass ssl-pinning

# Bypass root/jailbreak detection
vulnbuster mobile-scan app.apk --frida --bypass root-detection

# Bypass debugger detection
vulnbuster mobile-scan app.apk --frida --bypass debugger-detection
```

## 📊 Reporting

### Generate Reports

```bash
# HTML report (default)
vulnbuster mobile-scan app.apk --output report.html

# JSON report
vulnbuster mobile-scan app.apk --format json --output report.json

# PDF report with executive summary
vulnbuster mobile-scan app.apk --format pdf --template executive --output report.pdf
```

### Report Customization

```bash
# Include CVSS scores
vulnbuster mobile-scan app.apk --cvss

# Include remediation advice
vulnbuster mobile-scan app.apk --remediation

# Custom report template
vulnbuster mobile-scan app.apk --template ./custom-template.html
```

## 🔐 Secure Development

### Integration with CI/CD

```yaml
# .gitlab-ci.yml example
mobile_scan:
  stage: test
  image: vulnbuster/mobile-scanner:latest
  script:
    - vulnbuster mobile-scan app/build/outputs/apk/debug/app-debug.apk
      --platform android
      --output report.html
      --fail-on high
  artifacts:
    paths:
      - report.html
```

### Secure Coding Guidelines

1. **Data Storage**
   - Use Android Keystore/Keychain
   - Encrypt sensitive data
   - Avoid storing secrets in code

2. **Network Security**
   - Use HTTPS with certificate pinning
   - Implement proper SSL/TLS settings
   - Validate server certificates

3. **Authentication**
   - Use biometric authentication
   - Implement proper session management
   - Secure OAuth/OpenID Connect flows

## 🧩 Plugins

### Available Plugins

```bash
# List available plugins
vulnbuster mobile-plugins list

# Enable specific plugins
vulnbuster mobile-scan app.apk --enable-plugin ssl_analysis,secrets_detection

# Load custom plugin
vulnbuster mobile-scan app.apk --plugin ./custom_plugin.py
```

### Writing Custom Plugins

```python
# Example custom plugin
from vulnbuster.plugins import MobileAnalysisPlugin

class CustomPlugin(MobileAnalysisPlugin):
    name = "custom_plugin"
    description = "Custom security checks"
    
    def analyze(self, target, report):
        # Your analysis code here
        if self._check_insecure_component(target):
            report.add_finding(
                title="Insecure Component Detected",
                severity="high",
                description="An insecure component was found",
                details={"component": "com.example.insecure"}
            )
        
        return report
```

## 🚨 Troubleshooting

### Common Issues

1. **APK Decompilation Failures**
   - Ensure Java is installed
   - Check file permissions
   - Try with `--no-decompile`

2. **Frida Connection Issues**
   - Check device connectivity
   - Verify Frida server is running
   - Try `adb forward tcp:27042 tcp:27042`

3. **iOS Analysis on Non-macOS**
   - Use `--no-ipa` flag
   - Provide pre-extracted files
   - Use a macOS VM or CI/CD pipeline

### Debugging

```bash
# Enable debug output
vulnbuster mobile-scan app.apk --debug

# Save debug logs
vulnbuster mobile-scan app.apk --log-file debug.log

# Increase verbosity
vulnbuster mobile-scan app.apk -vvv
```

## 📚 Additional Resources

- [OWASP Mobile Security Testing Guide](https://owasp.org/www-project-mobile-security-testing-guide/)
- [Mozilla Web Security Guidelines](https://infosec.mozilla.org/guidelines/web_security)
- [Android Security Guidelines](https://developer.android.com/topic/security/best-practices)

## ➡️ Next Steps

- Learn about [Web Application Scanning](../web-scanning.md)
- Explore [Cloud Security Scanning](../cloud-scanning.md)
- Read about [AI-Powered Analysis](../ai-analysis.md)
