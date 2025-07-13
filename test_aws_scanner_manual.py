"""
Manual test script for AWS security scanner.
This script provides a simple way to test the AWS security scanner with your AWS credentials.
"""

import asyncio
import os
import sys
import logging
from typing import List, Dict, Any

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))

from modes.cloud.modules.aws_scanner import AWSScanner, AWSService, AWSFinding, AWSSeverity

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

async def print_findings(findings: List[AWSFinding]) -> None:
    """Print the findings in a readable format."""
    if not findings:
        print("No security findings detected!")
        return
    
    # Group findings by service and severity
    findings_by_service = {}
    for finding in findings:
        service = finding.service.value.upper()
        if service not in findings_by_service:
            findings_by_service[service] = {}
        
        severity = finding.severity.value.upper()
        if severity not in findings_by_service[service]:
            findings_by_service[service][severity] = []
        
        findings_by_service[service][severity].append(finding)
    
    # Print the findings
    for service, severities in findings_by_service.items():
        print(f"\n{'='*80}")
        print(f"{service} SECURITY FINDINGS")
        print(f"{'='*80}")
        
        for severity, service_findings in sorted(severities.items(), key=lambda x: x[0], reverse=True):
            print(f"\n{severity} Severity Findings:")
            print("-" * 30)
            
            for i, finding in enumerate(service_findings, 1):
                print(f"{i}. {finding.finding_type}")
                print(f"   Resource: {finding.resource_id}")
                print(f"   Description: {finding.description}")
                
                if finding.region:
                    print(f"   Region: {finding.region}")
                
                if finding.details:
                    print("   Details:")
                    for key, value in finding.details.items():
                        print(f"     - {key}: {value}")
                
                if finding.remediation:
                    print(f"\n   Remediation: {finding.remediation}")
                
                if finding.references:
                    print("\n   References:")
                    for ref in finding.references:
                        print(f"     - {ref}")
                
                print()

def get_aws_credentials() -> Dict[str, str]:
    """Get AWS credentials from environment variables or prompt the user."""
    credentials = {}
    
    # Try to get credentials from environment variables
    aws_access_key_id = os.environ.get('AWS_ACCESS_KEY_ID')
    aws_secret_access_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
    aws_session_token = os.environ.get('AWS_SESSION_TOKEN')
    aws_profile = os.environ.get('AWS_PROFILE')
    
    if aws_access_key_id and aws_secret_access_key:
        print("Using AWS credentials from environment variables")
        credentials.update({
            'access_key': aws_access_key_id,
            'secret_key': aws_secret_access_key,
            'session_token': aws_session_token
        })
    elif aws_profile:
        print(f"Using AWS profile: {aws_profile}")
        credentials['profile'] = aws_profile
    else:
        print("AWS credentials not found in environment variables")
        use_profile = input("Do you want to use an AWS profile? (y/n): ").strip().lower() == 'y'
        
        if use_profile:
            profile = input("Enter AWS profile name [default]: ").strip()
            if profile:
                credentials['profile'] = profile
            else:
                credentials['profile'] = 'default'
        else:
            access_key = input("Enter AWS Access Key ID: ").strip()
            secret_key = input("Enter AWS Secret Access Key: ").strip()
            session_token = input("Enter AWS Session Token (optional, press Enter to skip): ").strip()
            
            if not access_key or not secret_key:
                print("Error: Access Key ID and Secret Access Key are required")
                sys.exit(1)
            
            credentials.update({
                'access_key': access_key,
                'secret_key': secret_key
            })
            
            if session_token:
                credentials['session_token'] = session_token
    
    # Get regions to scan
    regions_input = os.environ.get('AWS_REGIONS', '').strip()
    if regions_input:
        regions = [r.strip() for r in regions_input.split(',') if r.strip()]
    else:
        regions_input = input("Enter AWS regions to scan (comma-separated, leave empty for all regions): ").strip()
        regions = [r.strip() for r in regions_input.split(',')] if regions_input else None
    
    if regions:
        credentials['regions'] = regions
    
    return credentials

async def main():
    """Main function to run the AWS security scanner."""
    print("=" * 80)
    print("AWS SECURITY SCANNER")
    print("=" * 80)
    print("This script will scan your AWS account for security issues.")
    print("Please ensure you have the necessary permissions to perform these scans.\n")
    
    # Get AWS credentials
    credentials = get_aws_credentials()
    
    # Get services to scan
    print("\nSelect services to scan:")
    print("1. IAM (Identity and Access Management)")
    print("2. S3 (Simple Storage Service)")
    print("3. EC2 (Elastic Compute Cloud)")
    print("4. RDS (Relational Database Service)")
    print("5. CloudTrail")
    print("6. All services")
    
    service_choice = input("\nEnter your choice (comma-separated numbers or 'all'): ").strip().lower()
    
    if service_choice == 'all':
        services = list(AWSService)
    else:
        service_map = {
            '1': AWSService.IAM,
            '2': AWSService.S3,
            '3': AWSService.EC2,
            '4': AWSService.RDS,
            '5': AWSService.CLOUDTRAIL
        }
        
        choices = [c.strip() for c in service_choice.split(',')]
        services = [service_map[choice] for choice in choices if choice in service_map]
    
    if not services:
        print("No valid services selected. Exiting.")
        return
    
    # Create and run the scanner
    print("\nStarting AWS security scan...\n")
    
    try:
        scanner = AWSScanner(**credentials)
        findings = await scanner.scan(services=services)
        
        print("\n" + "=" * 80)
        print("SCAN COMPLETE")
        print("=" * 80)
        
        await print_findings(findings)
        
        # Print summary
        print("\n" + "=" * 80)
        print("SCAN SUMMARY")
        print("=" * 80)
        
        if not findings:
            print("No security findings detected!")
        else:
            # Count findings by service and severity
            summary = {}
            for finding in findings:
                service = finding.service.value
                severity = finding.severity.value
                
                if service not in summary:
                    summary[service] = {}
                
                summary[service][severity] = summary[service].get(severity, 0) + 1
            
            # Print the summary
            for service, severities in summary.items():
                print(f"\n{service.upper()}:")
                for severity, count in sorted(severities.items(), key=lambda x: x[0], reverse=True):
                    print(f"  {severity.upper()}: {count} findings")
            
            print(f"\nTotal findings: {len(findings)}")
    
    except Exception as e:
        logger.error(f"Error during scan: {str(e)}", exc_info=True)
        print(f"\nAn error occurred during the scan: {str(e)}")
        print("Please check the logs for more details.")

if __name__ == "__main__":
    asyncio.run(main())
