# Cloud Security Domain Documentation

## Overview
The cloud security domain provides security scanning and analysis capabilities for cloud environments. Currently, it offers a foundational structure with stubbed implementations for major cloud providers.

## Core Components

### 1. CloudScanner
- **File**: `modes/cloud/scanner.py`
- **Purpose**: Main scanning engine for cloud security analysis
- **Current State**: Partially implemented with stubs for core functionality
- **Features**:
  - Basic scan workflow management
  - Placeholder for cloud provider integrations
  - Basic result collection and reporting
  - AI/ML integration points (stubbed)

### 2. Scan Workflow

#### Current Implementation
1. **Metadata Extraction**
   - Basic target and provider information
   - Scan timestamp

2. **Configuration File Scanning** (Stubbed)
   - Placeholder for cloud configuration analysis
   - Intended to support Terraform, CloudFormation, etc.

3. **Secret/Key Detection** (Stubbed)
   - Placeholder for credential scanning
   - Will detect exposed API keys and secrets

4. **Public Resource Checks** (Stubbed)
   - Placeholder for public bucket/container scanning
   - Will identify publicly accessible cloud resources

5. **IAM Policy Analysis** (Stubbed)
   - Placeholder for permission analysis
   - Will detect over-privileged roles and policies

6. **Dynamic Analysis** (Stubbed)
   - Cloud API interaction
   - OOB/callback detection
   - Network exposure checks

### 3. Cloud Provider Support

#### AWS (Stubbed)
- **Services to be Supported**:
  - IAM analysis
  - S3 bucket security
  - EC2 instance security
  - Lambda function security
  - Security group analysis

#### Azure (Stubbed)
- **Services to be Supported**:
  - RBAC analysis
  - Storage account security
  - Virtual machine security
  - Function app security
  - Network security group analysis

#### GCP (Stubbed)
- **Services to be Supported**:
  - IAM analysis
  - Cloud Storage security
  - Compute Engine security
  - Cloud Functions security
  - VPC network analysis

## Implementation Status

### Implemented
- Basic scanner framework
- Scan workflow definition
- Placeholder methods for core features
- Basic result collection
- Report generation stubs

### Pending Implementation
- Cloud provider SDK integrations (boto3, google-cloud, azure)
- Configuration file parsing
- IAM policy analysis
- Public resource detection
- Secret scanning
- Dynamic analysis capabilities
- Comprehensive reporting
- AI/ML integration

## Configuration

Example configuration:
```yaml
cloud:
  provider: aws  # aws, azure, or gcp
  target: my-account
  regions: 
    - us-east-1
    - us-west-2
  checks:
    - iam
    - s3
    - ec2
    - lambda
  credentials:
    profile: default  # or path to credentials file
  report:
    format: html
    output: ./reports/
```

## Future Enhancements

### Short-term
1. Implement AWS provider integration
2. Add basic IAM analysis
3. Implement S3 bucket scanning
4. Add secret detection
5. Create basic reporting

### Medium-term
1. Add Azure and GCP provider support
2. Implement configuration file parsing
3. Add dynamic analysis capabilities
4. Enhance IAM analysis
5. Add remediation guidance

### Long-term
1. Multi-cloud security posture management
2. Advanced AI/ML analysis
3. Automated remediation
4. Compliance mapping (CIS, NIST, etc.)
5. Integration with CSPM tools

## Usage Example (Future)

```python
from modes.cloud.scanner import CloudScanner

config = {
    'provider': 'aws',
    'target': 'my-aws-account',
    'regions': ['us-east-1', 'us-west-2'],
    'checks': ['iam', 's3', 'ec2'],
    'credentials': {
        'profile': 'production'
    }
}

scanner = CloudScanner(config)
results = await scanner.run()
```

## Required Permissions

### AWS
- `SecurityAudit` managed policy
- Additional read-only permissions for specific services

### Azure
- `Security Reader` role
- Additional read permissions for resource groups and resources

### GCP
- `Security Reviewer` role
- Additional read permissions for specific services
