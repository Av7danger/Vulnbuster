"""AWS Security Hub integration for VulnBuster.

This module provides functionality to interact with AWS Security Hub, including:
- Sending findings to Security Hub
- Retrieving findings from Security Hub
- Managing Security Hub insights and custom actions
"""
import json
from typing import Dict, List, Optional, Any
import boto3
from botocore.exceptions import ClientError
import logging

from ..models import AWSFinding, AWSSeverity, AWSService

logger = logging.getLogger(__name__)

class SecurityHubIntegration:
    """Class for interacting with AWS Security Hub."""
    
    def __init__(self, session: boto3.Session, region: str = 'us-east-1'):
        """Initialize the Security Hub integration.
        
        Args:
            session: Boto3 session to use for AWS API calls
            region: AWS region to use for Security Hub
        """
        self.session = session
        self.region = region
        self.client = self.session.client('securityhub', region_name=region)
        self.product_arn = f"arn:aws:securityhub:{region}::product/vulnbuster/vulnbuster"
    
    def enable_security_hub(self) -> bool:
        """Enable AWS Security Hub in the current region.
        
        Returns:
            bool: True if Security Hub was enabled, False otherwise
        """
        try:
            self.client.enable_security_hub(
                EnableDefaultStandards=True,
                Tags={
                    'CreatedBy': 'VulnBuster',
                    'Purpose': 'Security Scanning'
                }
            )
            logger.info(f"Enabled AWS Security Hub in {self.region}")
            return True
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceConflictException':
                logger.info(f"AWS Security Hub is already enabled in {self.region}")
                return True
            logger.error(f"Error enabling AWS Security Hub in {self.region}: {str(e)}")
            return False
    
    def import_findings(self, findings: List[AWSFinding]) -> Dict[str, Any]:
        """Import findings into AWS Security Hub.
        
        Args:
            findings: List of AWSFinding objects to import
            
        Returns:
            Dict containing the import results
        """
        if not findings:
            return {}
            
        # Convert findings to Security Hub format
        security_hub_findings = [self._convert_to_security_hub_finding(f) for f in findings]
        
        # Split into batches of 100 (Security Hub batch limit)
        batch_size = 100
        results = {
            'SuccessCount': 0,
            'FailedCount': 0,
            'FailedFindings': []
        }
        
        for i in range(0, len(security_hub_findings), batch_size):
            batch = security_hub_findings[i:i + batch_size]
            try:
                response = self.client.batch_import_findings(Findings=batch)
                results['SuccessCount'] += response.get('SuccessCount', 0)
                results['FailedCount'] += response.get('FailedCount', 0)
                
                if 'FailedFindings' in response:
                    results['FailedFindings'].extend(response['FailedFindings'])
                
                logger.info(f"Imported {response.get('SuccessCount', 0)} findings to Security Hub in {self.region}")
                if response.get('FailedCount', 0) > 0:
                    logger.warning(f"Failed to import {response.get('FailedCount', 0)} findings to Security Hub in {self.region}")
                    
            except ClientError as e:
                logger.error(f"Error importing findings to Security Hub in {self.region}: {str(e)}")
                results['FailedCount'] += len(batch)
                results['FailedFindings'].extend([
                    {'Id': f.get('Id', 'unknown'), 'ErrorCode': str(e), 'ErrorMessage': str(e)}
                    for f in batch
                ])
        
        return results
    
    def _convert_to_security_hub_finding(self, finding: AWSFinding) -> Dict[str, Any]:
        """Convert an AWSFinding to Security Hub finding format.
        
        Args:
            finding: AWSFinding to convert
            
        Returns:
            Dict containing the Security Hub finding
        """
        # Map our severity to Security Hub severity
        severity_map = {
            AWSSeverity.INFORMATIONAL: 0,
            AWSSeverity.LOW: 1,
            AWSSeverity.MEDIUM: 4,
            AWSSeverity.HIGH: 7,
            AWSSeverity.CRITICAL: 9
        }
        
        # Map our service to AWS service name
        service_map = {
            AWSService.IAM: 'iam',
            AWSService.S3: 's3',
            AWSService.EC2: 'ec2',
            AWSService.RDS: 'rds',
            AWSService.LAMBDA: 'lambda',
            AWSService.ECS: 'ecs',
            AWSService.ECR: 'ecr',
            AWSService.EKS: 'eks',
            AWSService.CLOUDFRONT: 'cloudfront',
            AWSService.CONFIG: 'config',
            AWSService.CLOUDTRAIL: 'cloudtrail'
        }
        
        # Create the finding ID
        finding_id = f"vulnbuster-{finding.service}-{finding.finding_type}-{finding.resource_id}"
        
        # Format the finding for Security Hub
        security_hub_finding = {
            'SchemaVersion': '2018-10-08',
            'Id': finding_id,
            'ProductArn': self.product_arn,
            'GeneratorId': f'vulnbuster/{finding.service}/{finding.finding_type}',
            'AwsAccountId': self.session.client('sts').get_caller_identity().get('Account'),
            'Types': [f'Software and Configuration Checks/Vulnerabilities/{finding.service.upper()}'],
            'CreatedAt': finding.timestamp.isoformat() if hasattr(finding, 'timestamp') else None,
            'UpdatedAt': finding.timestamp.isoformat() if hasattr(finding, 'timestamp') else None,
            'Severity': {
                'Label': finding.severity.value.upper(),
                'Original': str(severity_map.get(finding.severity, 0)),
                'Product': float(severity_map.get(finding.severity, 0))
            },
            'Title': f"[{finding.service.upper()}] {finding.finding_type.replace('_', ' ').title()}",
            'Description': finding.description,
            'Remediation': {
                'Recommendation': {
                    'Text': finding.remediation,
                    'Url': finding.references[0] if finding.references else 'https://vulnbuster.readthedocs.io/'
                }
            },
            'Resources': [
                {
                    'Type': service_map.get(finding.service, 'Other'),
                    'Id': finding.resource_id,
                    'Region': finding.region or self.region,
                    'Details': {
                        'AwsSecurityFinding': {
                            'Type': f"VulnBuster/{finding.service}/{finding.finding_type}",
                            'Severity': {
                                'Label': finding.severity.value.upper(),
                                'Normalized': severity_map.get(finding.severity, 0) * 10
                            }
                        }
                    }
                }
            ],
            'FindingProviderFields': {
                'Severity': {
                    'Label': finding.severity.value.upper(),
                    'Original': str(severity_map.get(finding.severity, 0))
                },
                'Types': [f'VulnBuster/{finding.service}/{finding.finding_type}']
            }
        }
        
        # Add any additional details
        if finding.details:
            security_hub_finding['Resources'][0]['Details']['Other'] = finding.details
        
        return security_hub_finding
    
    def get_findings(self, filters: Optional[Dict] = None) -> List[Dict]:
        """Get findings from Security Hub.
        
        Args:
            filters: Filters to apply to the findings query
            
        Returns:
            List of findings matching the filters
        """
        if filters is None:
            filters = {}
            
        paginator = self.client.get_paginator('get_findings')
        findings = []
        
        try:
            for page in paginator.paginate(Filters=filters):
                findings.extend(page.get('Findings', []))
        except ClientError as e:
            logger.error(f"Error getting findings from Security Hub: {str(e)}")
            
        return findings
    
    def create_insight(self, name: str, filters: Dict) -> Optional[Dict]:
        """Create a Security Hub insight.
        
        Args:
            name: Name of the insight
            filters: Filters to apply to the insight
            
        Returns:
            Dict containing the insight details, or None if creation failed
        """
        try:
            response = self.client.create_insight(
                Name=name,
                Filters=filters,
                GroupByAttribute='Resource.Type'
            )
            logger.info(f"Created Security Hub insight: {name}")
            return response
        except ClientError as e:
            logger.error(f"Error creating Security Hub insight {name}: {str(e)}")
            return None
    
    def delete_insight(self, insight_arn: str) -> bool:
        """Delete a Security Hub insight.
        
        Args:
            insight_arn: ARN of the insight to delete
            
        Returns:
            bool: True if deletion was successful, False otherwise
        """
        try:
            self.client.delete_insight(InsightArn=insight_arn)
            logger.info(f"Deleted Security Hub insight: {insight_arn}")
            return True
        except ClientError as e:
            logger.error(f"Error deleting Security Hub insight {insight_arn}: {str(e)}")
            return False
