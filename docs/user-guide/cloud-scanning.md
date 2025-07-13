# Cloud Security Scanning

VulnBuster's cloud security module provides comprehensive security assessment for cloud environments including AWS, Azure, and GCP. This guide covers how to perform security assessments of your cloud infrastructure.

## 🎯 Features

- **Multi-Cloud Support**
  - Amazon Web Services (AWS)
  - Microsoft Azure
  - Google Cloud Platform (GCP)
  - Kubernetes & Containers

- **Security Assessment**
  - Infrastructure as Code (IaC) scanning
  - Configuration auditing
  - Identity and Access Management (IAM) analysis
  - Network security assessment
  - Data protection analysis

- **Compliance**
  - CIS Benchmarks
  - NIST Cybersecurity Framework
  - GDPR, HIPAA, PCI-DSS
  - Custom compliance frameworks

## 🚀 Getting Started

### Prerequisites

- **AWS**
  - AWS CLI configured with credentials
  - IAM permissions for security auditing
  
- **Azure**
  - Azure CLI installed and logged in
  - Required RBAC permissions
  
- **GCP**
  - Google Cloud SDK installed
  - Project owner or security admin role

### Basic Usage

#### AWS Security Scan

```bash
# Scan all AWS services in the current profile/region
vulnbuster cloud-scan --provider aws

# Scan specific AWS services
vulnbuster cloud-scan --provider aws --services ec2,s3,iam

# Scan multiple regions
vulnbuster cloud-scan --provider aws --regions us-east-1,us-west-2
```

#### Azure Security Scan

```bash
# Scan Azure subscription
vulnbuster cloud-scan --provider azure

# Scan specific resource groups
vulnbuster cloud-scan --provider azure --resource-groups prod,dev
```

#### GCP Security Scan

```bash
# Scan GCP project
vulnbuster cloud-scan --provider gcp --project my-project-id

# Scan specific GCP services
vulnbuster cloud-scan --provider gcp --services compute,storage,iam
```

## 🔧 Configuration

### AWS Configuration

```bash
# Set AWS profile
vulnbuster config set aws.profile my-profile

# Set AWS regions
vulnbuster config set aws.regions us-east-1,us-west-2

# Enable/disable specific checks
vulnbuster config set aws.checks.s3_public_access true
vulnbuster config set aws.checks.encryption_at_rest true
```

### Azure Configuration

```bash
# Set Azure subscription
vulnbuster config set azure.subscription_id xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# Configure resource groups
vulnbuster config set azure.resource_groups prod,dev,test
```

### GCP Configuration

```bash
# Set GCP project
vulnbuster config set gcp.project my-project-id

# Configure authentication
vulnbuster config set gcp.credentials /path/to/credentials.json
```

## 🔍 Security Checks

### Infrastructure as Code (IaC) Scanning

```bash
# Scan Terraform files
vulnbuster iac-scan --format terraform ./terraform/

# Scan CloudFormation templates
vulnbuster iac-scan --format cloudformation ./cloudformation/

# Scan Kubernetes manifests
vulnbuster iac-scan --format kubernetes ./k8s/
```

### Container Security

```bash
# Scan Docker images
vulnbuster container-scan my-image:latest

# Scan Kubernetes cluster
vulnbuster k8s-scan --kubeconfig ~/.kube/config

# Scan container registry
vulnbuster registry-scan gcr.io/my-project
```

### Serverless Security

```bash
# Scan AWS Lambda functions
vulnbuster lambda-scan --region us-east-1

# Scan Azure Functions
vulnbuster function-scan --resource-group my-rg

# Scan Google Cloud Functions
vulnbuster gcf-scan --project my-project
```

## 🛡️ Compliance Scanning

### CIS Benchmarks

```bash
# Run CIS benchmark for AWS
vulnbuster compliance-scan --provider aws --standard cis

# Run specific CIS controls
vulnbuster compliance-scan --provider aws --standard cis --controls 1.1,1.2,1.3
```

### Custom Compliance

```yaml
# custom-compliance.yaml
version: 1.0
name: "My Company Security Standard"
controls:
  - id: VULNBUSTER-001
    title: Ensure no public S3 buckets
    description: S3 buckets should not be publicly accessible
    severity: high
    query: |
      from aws_s3_bucket
      where 
        block_public_acls == false or
        block_public_policy == false or
        ignore_public_acls == false or
        restrict_public_buckets == false
```

```bash
# Run custom compliance scan
vulnbuster compliance-scan --custom ./custom-compliance.yaml
```

## 📊 Reporting

### Generate Reports

```bash
# HTML report (default)
vulnbuster cloud-scan --provider aws --output report.html

# JSON report
vulnbuster cloud-scan --provider aws --format json --output report.json

# JUnit XML for CI/CD
vulnbuster cloud-scan --provider aws --format junit --output report.xml
```

### Report Customization

```bash
# Include resource details
vulnbuster cloud-scan --include-resources

# Include remediation steps
vulnbuster cloud-scan --include-remediation

# Custom report template
vulnbuster cloud-scan --template ./custom-template.html
```

## 🔄 Continuous Monitoring

### Scheduled Scans

```bash
# Schedule daily scan
vulnbuster schedule create "Daily AWS Scan" \
  --command "vulnbuster cloud-scan --provider aws" \
  --schedule "0 0 * * *" \
  --output s3://my-bucket/reports/
```

### Integration with CI/CD

```yaml
# .gitlab-ci.yml example
cloud_scan:
  stage: security
  image: vulnbuster/cloud-scanner:latest
  script:
    - vulnbuster cloud-scan --provider aws --output report.html
  artifacts:
    paths:
      - report.html
  only:
    - main
```

## 🧩 Plugins

### Available Plugins

```bash
# List available plugins
vulnbuster cloud-plugins list

# Enable specific plugins
vulnbuster cloud-scan --enable-plugin iam_analysis,network_security

# Load custom plugin
vulnbuster cloud-scan --plugin ./custom_plugin.py
```

### Writing Custom Plugins

```python
# Example custom plugin
from vulnbuster.plugins import CloudAnalysisPlugin

class CustomPlugin(CloudAnalysisPlugin):
    name = "custom_plugin"
    description = "Custom cloud security checks"
    
    def analyze(self, resources, report):
        # Your analysis code here
        for resource in resources:
            if self._check_insecure_config(resource):
                report.add_finding(
                    title="Insecure Configuration Detected",
                    severity="high",
                    description="An insecure configuration was found",
                    resource=resource.arn,
                    details={"issue": "public access enabled"}
                )
        
        return report
```

## 🚨 Troubleshooting

### Common Issues

1. **Authentication Failures**
   - Verify credentials are properly configured
   - Check IAM/RBAC permissions
   - Ensure correct region/subscription/project is set

2. **Permission Denied Errors**
   - Update IAM policies/RBAC roles
   - Use principle of least privilege
   - Check service principals/service accounts

3. **Rate Limiting**
   - Implement retry logic
   - Reduce concurrency
   - Contact cloud provider for quota increases

### Debugging

```bash
# Enable debug output
vulnbuster cloud-scan --debug

# Save debug logs
vulnbuster cloud-scan --log-file debug.log

# Increase verbosity
vulnbuster cloud-scan -vvv
```

## 📚 Additional Resources

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [AWS Security Best Practices](https://aws.amazon.com/security/)
- [Microsoft Cloud Security](https://www.microsoft.com/security/business/cloud-security)
- [Google Cloud Security](https://cloud.google.com/security)

## ➡️ Next Steps

- Learn about [Web Application Scanning](../web-scanning.md)
- Explore [Mobile Security Analysis](../mobile-analysis.md)
- Read about [AI-Powered Analysis](../ai-analysis.md)
