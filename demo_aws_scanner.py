"""
Demo script for AWS security scanner with mock data.
This script demonstrates the AWS security scanner functionality without requiring AWS credentials.
"""

import asyncio
import json
import textwrap
import datetime
from typing import List, Dict, Any

from modes.cloud.modules.aws_scanner import AWSScanner, AWSFinding, AWSService, AWSSeverity

class MockAWSScanner(AWSScanner):
    """Mock AWS Scanner for demonstration purposes."""
    
    def __init__(self, aws_access_key_id=None, aws_secret_access_key=None, regions=None):
        """Initialize the mock scanner with sample findings."""
        self.findings = []
        self.enable_security_hub = True
        self.security_hub_region = 'us-east-1'
        self._add_mock_findings()
    
    async def scan(self, services=None, export_to_security_hub=True):
        """
        Mock scan method that returns the pre-populated findings.
        
        Args:
            services: List of services to scan (ignored in mock)
            export_to_security_hub: Whether to export findings to Security Hub
            
        Returns:
            List of security findings
        """
        # In a real implementation, this would scan the actual AWS account
        # For the demo, we'll just return the mock findings we already have
        if export_to_security_hub and self.enable_security_hub:
            print(f"\n🔐 Exporting {len(self.findings)} findings to AWS Security Hub in {self.security_hub_region}...")
            # Simulate Security Hub export
            print("✅ Successfully exported findings to Security Hub")
            print(f"ℹ️  Visit https://{self.security_hub_region}.console.aws.amazon.com/securityhub/ to view findings")
        
        return self.findings
    
    def _add_mock_findings(self):
        self.findings.append(AWSFinding(
            service=AWSService.IAM,
            resource_id="root-account",
            finding_type="ROOT_ACCOUNT_ACTIVE_KEYS",
            severity=AWSSeverity.CRITICAL,
            description="Root account has active access keys",
            details={"key_count": 2, "last_used": "2023-01-01T00:00:00Z"},
            remediation="Remove all access keys associated with the root account and use IAM users/roles instead.",
            region="global",
            references=[
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html"
            ]
        ))
        
        self.findings.append(AWSFinding(
            service=AWSService.S3,
            resource_id="example-bucket",
            finding_type="PUBLIC_READ_ACCESS",
            severity=AWSSeverity.HIGH,
            description="S3 bucket has public read access",
            details={
                "bucket": "example-bucket",
                "public_access_block_configuration": {
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False
                }
            },
            remediation="Enable Block Public Access settings for the S3 bucket.",
            region="us-east-1",
            references=[
                "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
            ]
        ))
        
        self.findings.append(AWSFinding(
            service=AWSService.LAMBDA,
            resource_id="test-function",
            finding_type="SENSITIVE_ENV_VARIABLES",
            severity=AWSSeverity.HIGH,
            description="Lambda function has sensitive environment variables",
            details={
                "function_arn": "arn:aws:lambda:us-east-1:123456789012:function:test-function",
                "sensitive_keys": ["DB_PASSWORD", "API_KEY"],
                "runtime": "python3.9"
            },
            remediation="Store sensitive data in AWS Secrets Manager or AWS Systems Manager Parameter Store.",
            region="us-east-1",
            references=[
                "https://docs.aws.amazon.com/secretsmanager/latest/userguide/integrating_csi_driver.html"
            ]
        ))
        
        self.findings.append(AWSFinding(
            service=AWSService.ECS,
            resource_id="test-container",
            finding_type="PRIVILEGED_CONTAINER",
            severity=AWSSeverity.HIGH,
            description="Privileged container found in ECS task",
            details={
                "cluster_name": "test-cluster",
                "task_definition_arn": "arn:aws:ecs:us-east-1:123456789012:task-definition/test-task:1",
                "container_name": "test-container",
                "image": "nginx:latest"
            },
            remediation="Avoid running containers in privileged mode unless absolutely necessary.",
            region="us-east-1",
            references=[
                "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html#container_definition_privileged"
            ]
        ))
        
        # Add a finding for container insights disabled
        self.findings.append(AWSFinding(
            service=AWSService.ECS,
            resource_id="test-cluster",
            finding_type="ECS_CONTAINER_INSIGHTS_DISABLED",
            severity=AWSSeverity.MEDIUM,
            description="ECS Cluster test-cluster does not have Container Insights enabled",
            details={
                "cluster_arn": "arn:aws:ecs:us-east-1:123456789012:cluster/test-cluster",
                "region": "us-east-1"
            },
            remediation="Enable Container Insights for the ECS cluster to monitor container metrics.",
            region="us-east-1",
            references=[
                "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/cloudwatch-container-insights.html"
            ]
        ))
        
        # Add mock ECR findings
        self.findings.append(AWSFinding(
            service=AWSService.ECR,
            resource_id="test-repo",
            finding_type="ECR_SCAN_ON_PUSH_DISABLED",
            severity=AWSSeverity.HIGH,
            description="ECR repository test-repo does not have scan on push enabled",
            details={
                "repository_arn": "arn:aws:ecr:us-east-1:123456789012:repository/test-repo",
                "repository_uri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-repo",
                "created_at": "2023-01-01T00:00:00"
            },
            remediation="Enable scan on push for the ECR repository to automatically scan images for vulnerabilities.",
            region="us-east-1",
            references=[
                "https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html"
            ]
        ))
        
        self.findings.append(AWSFinding(
            service=AWSService.ECR,
            resource_id="vulnerable-repo",
            finding_type="ECR_IMAGE_VULNERABILITIES",
            severity=AWSSeverity.HIGH,
            description="ECR repository vulnerable-repo contains images with 3 critical/high severity vulnerabilities",
            details={
                "repository_arn": "arn:aws:ecr:us-east-1:123456789012:repository/vulnerable-repo",
                "vulnerability_count": 3,
                "vulnerabilities": [
                    {
                        "severity": "CRITICAL",
                        "name": "CVE-2023-1234",
                        "uri": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1234",
                        "description": "Critical vulnerability in package X"
                    },
                    {
                        "severity": "HIGH",
                        "name": "CVE-2023-5678",
                        "uri": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-5678",
                        "description": "High severity issue in package Y"
                    }
                ],
                "scan_completed_at": "2023-01-01T12:00:00"
            },
            remediation=(
                "Update the base image to a version without these vulnerabilities. "
                "Regularly update your images and their dependencies to the latest secure versions. "
                "Consider using a vulnerability scanning tool in your CI/CD pipeline."
            ),
            region="us-east-1",
            references=[
                "https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html"
            ]
        ))
        
        # Add mock AWS Config findings
        self.findings.append(AWSFinding(
            service=AWSService.CONFIG,
            resource_id="config-us-east-1",
            finding_type="CONFIG_RECORDER_DISABLED",
            severity=AWSSeverity.HIGH,
            description="AWS Config is not enabled in region us-east-1",
            details={
                "region": "us-east-1",
                "recorders": []
            },
            remediation=(
                "Enable AWS Config to track changes to your AWS resources. "
                "AWS Config provides detailed historical configuration information that can be "
                "used for security analysis, compliance auditing, and troubleshooting."
            ),
            region="us-east-1",
            references=[
                "https://docs.aws.amazon.com/config/latest/developerguide/gs-console.html"
            ]
        ))
        
        self.findings.append(AWSFinding(
            service=AWSService.CONFIG,
            resource_id="arn:aws:config:us-east-1:123456789012:config-rule/config-rule-123456",
            finding_type="CONFIG_RULE_NON_COMPLIANT",
            severity=AWSSeverity.MEDIUM,
            description="AWS Config rule restricted-ssh has 5 non-compliant resources",
            details={
                "rule_name": "restricted-ssh",
                "rule_arn": "arn:aws:config:us-east-1:123456789012:config-rule/config-rule-123456",
                "non_compliant_count": 5,
                "non_compliant_resources": [
                    "sg-12345678",
                    "sg-87654321",
                    "sg-11223344"
                ],
                "region": "us-east-1"
            },
            remediation=(
                "Review and remediate the non-compliant resources for AWS Config rule restricted-ssh. "
                "Addressing these issues will help ensure your resources are configured according to "
                "your organization's security and compliance requirements."
            ),
            region="us-east-1",
            references=[
                "https://us-east-1.console.aws.amazon.com/config/home?region=us-east-1#/rules/rule-details/restricted-ssh"
            ]
        ))
        
        # Add mock CloudFront findings
        self.findings.append(AWSFinding(
            service=AWSService.CLOUDFRONT,
            resource_id="E2A1B2C3D4E5F6",
            finding_type="CLOUDFRONT_WAF_DISABLED",
            severity=AWSSeverity.HIGH,
            description="CloudFront distribution E2A1B2C3D4E5F6 does not have WAF enabled",
            details={
                "distribution_id": "E2A1B2C3D4E5F6",
                "domain_name": "d1234abcd.cloudfront.net",
                "status": "Deployed"
            },
            remediation=(
                "Enable AWS WAF (Web Application Firewall) for the CloudFront distribution. "
                "WAF helps protect your web applications from common web exploits that could affect "
                "application availability, compromise security, or consume excessive resources."
            ),
            region="us-east-1",
            references=[
                "https://docs.aws.amazon.com/waf/latest/developerguide/cloudfront-features.html"
            ]
        ))
        
        self.findings.append(AWSFinding(
            service=AWSService.CLOUDFRONT,
            resource_id="E2A1B2C3D4E5F6",
            finding_type="CLOUDFRONT_INSECURE_SSL_PROTOCOL",
            severity=AWSSeverity.HIGH,
            description="CloudFront distribution E2A1B2C3D4E5F6 is using an insecure minimum SSL/TLS protocol version: TLSv1.1",
            details={
                "distribution_id": "E2A1B2C3D4E5F6",
                "domain_name": "d1234abcd.cloudfront.net",
                "minimum_protocol_version": "TLSv1.1",
                "ssl_support_method": "sni-only",
                "certificate_source": "acm"
            },
            remediation=(
                "Update the SSL/TLS security policy to use a minimum protocol version of TLSv1.2_2021 or later. "
                "Older SSL/TLS protocols have known vulnerabilities and should not be used."
            ),
            region="us-east-1",
            references=[
                "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html"
            ]
        ))
    
    # Add mock EKS findings
        self.findings.append(AWSFinding(
            service=AWSService.EKS,
            resource_id="test-cluster",
            finding_type="EKS_LOGGING_DISABLED",
            severity=AWSSeverity.MEDIUM,
            description="EKS cluster test-cluster does not have logging enabled",
            details={
                "cluster_arn": "arn:aws:eks:us-east-1:123456789012:cluster/test-cluster",
                "status": "ACTIVE",
                "kubernetes_version": "1.20",
                "platform_version": "eks.123",
                "endpoint_public_access": True,
                "endpoint_private_access": False
            },
            remediation=(
                "Enable audit and other important log types for the EKS cluster. "
                "This helps with security analysis, compliance, and troubleshooting."
            ),
            region="us-east-1",
            references=[
                "https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html"
            ]
        ))
        
        self.findings.append(AWSFinding(
            service=AWSService.EKS,
            resource_id="test-cluster",
            finding_type="EKS_PUBLIC_ACCESS_ENABLED",
            severity=AWSSeverity.HIGH,
            description="EKS cluster test-cluster has public endpoint access from the internet (0.0.0.0/0)",
            details={
                "cluster_arn": "arn:aws:eks:us-east-1:123456789012:cluster/test-cluster",
                "public_access_cidrs": ["0.0.0.0/0"],
                "status": "ACTIVE"
            },
            remediation=(
                "Restrict public access to the EKS cluster endpoint by updating the publicAccessCidrs setting. "
                "Limit access to specific IP ranges that require access to the cluster."
            ),
            region="us-east-1",
            references=[
                "https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html"
            ]
        ))
        
        self.findings.append(AWSFinding(
            service=AWSService.EKS,
            resource_id="test-cluster",
            finding_type="EKS_SECRETS_NOT_ENCRYPTED",
            severity=AWSSeverity.HIGH,
            description="EKS cluster test-cluster does not have encryption at rest enabled for Kubernetes secrets",
            details={
                "cluster_arn": "arn:aws:eks:us-east-1:123456789012:cluster/test-cluster",
                "status": "ACTIVE"
            },
            remediation=(
                "Enable encryption at rest for Kubernetes secrets using AWS Key Management Service (KMS). "
                "This ensures that sensitive data stored in etcd is encrypted."
            ),
            region="us-east-1",
            references=[
                "https://docs.aws.amazon.com/eks/latest/userguide/encryption-at-rest.html"
            ]
        ))

async def demo_aws_scanner():
    """Run the AWS security scanner demo."""
    # Clear the console for better visibility
    import os
    os.system('cls' if os.name == 'nt' else 'clear')
    
    print("\n" + "="*80)
    print(" " * 30 + "AWS SECURITY SCANNER DEMO")
    print("="*80)
    print("This is a demonstration of the AWS security scanner using mock data.\n")
    
    # Initialize the scanner with mock data and Security Hub integration
    print("Initializing mock AWS scanner with Security Hub integration...")
    scanner = MockAWSScanner()
    
    # Define services to scan
    services_to_scan = [
        AWSService.IAM,
        AWSService.S3,
        AWSService.EC2,
        AWSService.RDS,
        AWSService.LAMBDA,
        AWSService.ECS,
        AWSService.ECR,
        AWSService.EKS,
        AWSService.CLOUDFRONT,
        AWSService.CONFIG,
        AWSService.CLOUDTRAIL
    ]
    
    # Run the scan with Security Hub export
    print("\n" + "-"*40)
    print("         SCANNING AWS RESOURCES")
    print("-"*40)
    
    # Run the scan with Security Hub export
    print("🔍 Starting security scan with Security Hub integration...")
    findings = await scanner.scan(services=services_to_scan, export_to_security_hub=True)
    
    # Print summary
    print("\n" + "="*80)
    print(" " * 30 + "SCAN COMPLETE")
    print("="*80)
    
    # Group findings by service
    findings_by_service = {}
    for finding in findings:
        if finding.service not in findings_by_service:
            findings_by_service[finding.service] = []
        findings_by_service[finding.service].append(finding)
    
    # Print findings by service
    for service, service_findings in findings_by_service.items():
        print(f"\n{service.value.upper()} Findings ({len(service_findings)}):")
        print("-" * (len(service.value) + 11))
        
        for i, finding in enumerate(service_findings, 1):
            print(f"{i}. [{finding.severity.value.upper()}] {finding.finding_type}")
            print(f"   {finding.description}")
    
    # Print total findings by severity
    severity_counts = {severity: 0 for severity in AWSSeverity}
    for finding in findings:
        severity_counts[finding.severity] += 1
    
    print("\n" + "="*80)
    print(" " * 30 + "SCAN SUMMARY")
    print("="*80)
    print(f"\nTotal Findings: {len(findings)}")
    for severity, count in severity_counts.items():
        if count > 0:
            print(f"- {severity.value.upper()}: {count}")
    
    # Security Hub integration status
    print("\n" + "-"*40)
    print("     SECURITY HUB INTEGRATION STATUS")
    print("-"*40)
    print("✅ Security Hub integration is enabled and configured")
    print("✅ Findings have been exported to AWS Security Hub")
    print("ℹ️  Visit the AWS Security Hub console to view detailed findings")
    print("   https://console.aws.amazon.com/securityhub/")
    
    # Example of additional Security Hub features
    print("\n" + "-"*40)
    print("     SECURITY HUB FEATURES")
    print("-"*40)
    print("🔍 View all findings in the Security Hub console")
    print("📊 Create custom insights and dashboards")
    print("🔔 Set up CloudWatch Events for real-time alerts")
    print("📈 Track compliance with industry standards")
    print("🤖 Enable automated response and remediation")
    
    # Print the findings with better formatting
    for service, severities in findings_by_service.items():
        print(f"\n{'━' * 40}")
        print(f"🔒 {service} SECURITY FINDINGS".center(40))
        print(f"{'━' * 40}\n")
        
        for severity, service_findings in sorted(severities.items(), key=lambda x: x[0], reverse=True):
            emoji = SEVERITY_EMOJIS.get(severity, '•')
            print(f"{emoji} {severity} SEVERITY ({len(service_findings)} findings):\n")
            
            for i, finding in enumerate(service_findings, 1):
                # Print finding header
                print(f"  {i}. {finding.description}")
                print(f"     {'─' * (len(finding.description) + 4)}\n")
                
                # Print resource info
                print(f"     {'🔹 Resource:':<15} {finding.resource_id}")
                print(f"     {'🌐 Region:':<15} {finding.region}")
                
                # Print details in a formatted way
                if finding.details:
                    print(f"     \n     📋 Details:")
                    for key, value in finding.details.items():
                        if isinstance(value, dict):
                            print(f"        {key}:")
                            for k, v in value.items():
                                print(f"          {k}: {v}")
                        else:
                            print(f"        {key}: {value}")
                
                # Print remediation
                print(f"\n     💡 Remediation:")
                print(f"        {textwrap.fill(finding.remediation, width=70, subsequent_indent='        ')}")
                
                # Print references
                if finding.references:
                    print("\n     📚 References:")
                    for ref in finding.references:
                        print(f"        • {ref}")
                
                print("\n     " + "─" * 60 + "\n")
    
    # Print summary
    print("\n" + "=" * 80)
    print("SCAN SUMMARY".center(80))
    print("=" * 80)
    
    # Calculate findings by severity
    severity_counts = {}
    for finding in findings:
        severity = finding.severity.value.upper()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    # Print severity breakdown
    print("\n📊 FINDINGS BY SEVERITY:")
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        if severity in severity_counts:
            emoji = SEVERITY_EMOJIS.get(severity, '•')
            print(f"  {emoji} {severity}: {severity_counts[severity]}")
    
    # Print total findings
    print(f"\n🔍 TOTAL FINDINGS: {len(findings)}")
    
    # Print services scanned
    services_scanned = ", ".join([s.value.upper() for s in services_to_scan])
    print(f"\n🛡️  SERVICES SCANNED: {services_scanned}")
    
    # Print disclaimer
    print("\n" + "⚠️ " + "-" * 76 + " ⚠️")
    print("  NOTE: This was a demonstration using mock data. To scan your actual")
    print("  AWS environment, use the test_aws_scanner_manual.py script.")
    print("  " + "-" * 76)
    
    print("\n" + "✅ Scan completed successfully!".center(80) + "\n")

if __name__ == "__main__":
    asyncio.run(demo_aws_scanner())
