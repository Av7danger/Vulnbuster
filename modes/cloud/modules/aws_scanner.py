"""
AWS Security Scanner for VulnBuster

This module provides comprehensive security scanning for AWS resources,
including IAM, S3, EC2, and other AWS services.
"""

import boto3
import logging
from typing import List, Dict, Any, Optional
from enum import Enum
import boto3
from botocore.exceptions import ClientError, BotoCoreError
import json
from datetime import datetime, timezone

# Import models and security hub integration
from ..models import AWSFinding, AWSSeverity, AWSService
from .security_hub_integration import SecurityHubIntegration
from .kubernetes_scanner import KubernetesScanner

logger = logging.getLogger(__name__)

class AWSService(str, Enum):
    """Enumeration of AWS services that can be scanned."""
    IAM = "iam"
    S3 = "s3"
    EC2 = "ec2"
    RDS = "rds"
    LAMBDA = "lambda"
    ECS = "ecs"
    CLOUDFRONT = "cloudfront"
    CLOUDTRAIL = "cloudtrail"
    CONFIG = "config"
    KMS = "kms"
    SECURITYHUB = "securityhub"
    ECR = "ecr"  # Elastic Container Registry
    EKS = "eks"  # Elastic Kubernetes Service

class AWSSeverity(str, Enum):
    """Enumeration of issue severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class AWSFinding:
    """Represents a security finding in AWS."""
    service: AWSService
    resource_id: str
    finding_type: str
    severity: AWSSeverity
    description: str
    details: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    region: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

class AWSScanner:
    """Main AWS security scanner class."""
    
    def __init__(self, aws_access_key_id: str = None, aws_secret_access_key: str = None,
                 aws_session_token: str = None, regions: List[str] = None,
                 enable_security_hub: bool = True, security_hub_region: str = None):
        """Initialize the AWS scanner.
        
        Args:
            aws_access_key_id: AWS access key ID
            aws_secret_access_key: AWS secret access key
            aws_session_token: AWS session token
            regions: List of AWS regions to scan (defaults to all regions)
            enable_security_hub: Whether to enable Security Hub integration
            security_hub_region: AWS region to use for Security Hub (defaults to first region in regions)
        """
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key
        self.aws_session_token = aws_session_token
        self.regions = regions or []
        self.findings = []
        self.enable_security_hub = enable_security_hub
        self.security_hub_region = security_hub_region
        
        # Create a session
        self.session = boto3.Session(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token
        )
        
        # If no regions specified, get all available regions
        if not self.regions:
            try:
                ec2 = self.session.client('ec2', region_name='us-east-1')
                self.regions = [region['RegionName'] for region in ec2.describe_regions()['Regions']]
                logger.info(f"Using all available regions: {', '.join(self.regions)}")
            except (ClientError, BotoCoreError) as e:
                logger.error(f"Failed to get AWS regions: {str(e)}")
                self.regions = ['us-east-1']  # Default to us-east-1 if region detection fails
        
        # Initialize Security Hub integration if enabled
        self.security_hub = None
        if self.enable_security_hub:
            self.security_hub_region = security_hub_region or self.regions[0]
            try:
                self.security_hub = SecurityHubIntegration(self.session, self.security_hub_region)
                if self.security_hub.enable_security_hub():
                    logger.info(f"Security Hub integration enabled in {self.security_hub_region}")
                else:
                    logger.warning("Failed to enable Security Hub integration")
            except Exception as e:
                logger.error(f"Error initializing Security Hub integration: {str(e)}")
                self.security_hub = None
    
    async def scan(self, services: List[AWSService] = None, export_to_security_hub: bool = True) -> List[AWSFinding]:
        """
        Scan AWS resources for security issues.
        
        Args:
            services: List of AWS services to scan (defaults to all)
            export_to_security_hub: Whether to export findings to AWS Security Hub
            
        Returns:
            List of security findings
        """
        services = services or list(AWSService)
        self.findings = []
        
        # Map service enums to their corresponding scan methods
        service_scan_map = {
            AWSService.IAM: self.scan_iam,
            AWSService.S3: self.scan_s3,
            AWSService.EC2: self.scan_ec2,
            AWSService.RDS: self.scan_rds,
            AWSService.LAMBDA: self.scan_lambda,
            AWSService.ECS: self.scan_ecs,
            AWSService.ECR: self.scan_ecr,
            AWSService.EKS: self.scan_eks,
            AWSService.CLOUDFRONT: self.scan_cloudfront,
            AWSService.CONFIG: self.scan_config,
            AWSService.CLOUDTRAIL: self.scan_cloudtrail,
        }
        
        # Add timestamp to all findings
        scan_timestamp = datetime.now(timezone.utc)
        
        # Scan each service
        for service in services:
            try:
                scan_method = service_scan_map.get(service)
                if scan_method:
                    # Execute the scan method for the service
                    try:
                        await scan_method()
                        logger.info(f"✅ Completed scanning {service.value}")
                    except Exception as e:
                        logger.error(f"❌ Error scanning {service.value}: {str(e)}")
                        continue
            except Exception as e:
                logger.error(f"Error scanning {service.value}: {str(e)}")
        
        # Add timestamp to all findings
        for finding in self.findings:
            if not hasattr(finding, 'timestamp') or not finding.timestamp:
                finding.timestamp = scan_timestamp
        
        # Export findings to Security Hub if enabled
        if export_to_security_hub and self.security_hub and self.findings:
            try:
                result = self.security_hub.import_findings(self.findings)
                if result:
                    logger.info(f"Exported {result.get('SuccessCount', 0)} findings to Security Hub in {self.security_hub_region}")
                    if result.get('FailedCount', 0) > 0:
                        logger.warning(f"Failed to export {result.get('FailedCount', 0)} findings to Security Hub")
            except Exception as e:
                logger.error(f"Error exporting findings to Security Hub: {str(e)}")
                
        return self.findings
    
    async def scan_iam(self) -> None:
        """Scan IAM for security issues."""
        iam = self.session.client('iam')
        
        # Check for root account access keys
        try:
            summary = iam.get_account_summary()
            if summary['SummaryMap']['AccountAccessKeysPresent'] > 0:
                self.findings.append(AWSFinding(
                    service=AWSService.IAM,
                    resource_id="root",
                    finding_type="ROOT_ACCESS_KEYS",
                    severity=AWSSeverity.CRITICAL,
                    description="Root account has access keys",
                    remediation="Remove access keys from the root account and use IAM users with appropriate permissions.",
                    references=[
                        "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#lock-away-credentials"
                    ]
                ))
        except Exception as e:
            logger.error(f"Error checking root account access keys: {str(e)}")
        
        # Check for password policy
        try:
            policy = iam.get_account_password_policy()
            pw_policy = policy['PasswordPolicy']
            
            if not pw_policy.get('MinimumPasswordLength', 0) >= 14:
                self.findings.append(AWSFinding(
                    service=AWSService.IAM,
                    resource_id="account-password-policy",
                    finding_type="WEAK_PASSWORD_POLICY",
                    severity=AWSSeverity.HIGH,
                    description="Password policy is too weak",
                    details={
                        "minimum_password_length": pw_policy.get('MinimumPasswordLength', 0),
                        "require_symbols": pw_policy.get('RequireSymbols', False),
                        "require_numbers": pw_policy.get('RequireNumbers', False),
                        "require_uppercase": pw_policy.get('RequireUppercaseCharacters', False),
                        "require_lowercase": pw_policy.get('RequireLowercaseCharacters', False),
                        "password_reuse_prevention": pw_policy.get('PasswordReusePrevention', 0),
                        "max_password_age": pw_policy.get('MaxPasswordAge', 0)
                    },
                    remediation="Enhance the password policy to require strong passwords.",
                    references=[
                        "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html"
                    ]
                ))
        except iam.exceptions.NoSuchEntityException:
            # No password policy set
            self.findings.append(AWSFinding(
                service=AWSService.IAM,
                resource_id="account-password-policy",
                finding_type="NO_PASSWORD_POLICY",
                severity=AWSSeverity.HIGH,
                description="No password policy is set for IAM users",
                remediation="Create a strong password policy for IAM users.",
                references=[
                    "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html"
                ]
            ))
        except Exception as e:
            logger.error(f"Error checking password policy: {str(e)}")
        
        # Check for unused IAM users
        try:
            users = iam.list_users()['Users']
            for user in users:
                last_used = user.get('PasswordLastUsed', 'Never')
                if last_used == 'Never':
                    # Check if the user has access keys
                    access_keys = iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']
                    if access_keys:
                        self.findings.append(AWSFinding(
                            service=AWSService.IAM,
                            resource_id=user['UserId'],
                            finding_type="UNUSED_IAM_USER",
                            severity=AWSSeverity.MEDIUM,
                            description=f"IAM user {user['UserName']} has never logged in but has access keys",
                            details={
                                "user_name": user['UserName'],
                                "create_date": user['CreateDate'].isoformat(),
                                "access_keys": [key['AccessKeyId'] for key in access_keys]
                            },
                            remediation="Remove or deactivate unused IAM users and their access keys.",
                            references=[
                                "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_finding-unused.html"
                            ]
                        ))
        except Exception as e:
            logger.error(f"Error checking for unused IAM users: {str(e)}")
    
    async def scan_s3(self) -> None:
        """Scan S3 buckets for security issues."""
        s3 = self.session.client('s3')
        
        try:
            buckets = s3.list_buckets()['Buckets']
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                
                # Check bucket encryption
                try:
                    encryption = s3.get_bucket_encryption(Bucket=bucket_name)
                    if not encryption.get('ServerSideEncryptionConfiguration', {}).get('Rules', []):
                        self.findings.append(AWSFinding(
                            service=AWSService.S3,
                            resource_id=bucket_name,
                            finding_type="NO_BUCKET_ENCRYPTION",
                            severity=AWSSeverity.HIGH,
                            description=f"S3 bucket {bucket_name} does not have server-side encryption enabled",
                            remediation="Enable server-side encryption for the S3 bucket.",
                            references=[
                                "https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html"
                            ]
                        ))
                except s3.exceptions.ClientError as e:
                    if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                        self.findings.append(AWSFinding(
                            service=AWSService.S3,
                            resource_id=bucket_name,
                            finding_type="NO_BUCKET_ENCRYPTION",
                            severity=AWSSeverity.HIGH,
                            description=f"S3 bucket {bucket_name} does not have server-side encryption enabled",
                            remediation="Enable server-side encryption for the S3 bucket.",
                            references=[
                                "https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html"
                            ]
                        ))
                
                # Check bucket policy for public access
                try:
                    policy = s3.get_bucket_policy_status(Bucket=bucket_name)
                    if policy['PolicyStatus']['IsPublic']:
                        self.findings.append(AWSFinding(
                            service=AWSService.S3,
                            resource_id=bucket_name,
                            finding_type="PUBLIC_S3_BUCKET",
                            severity=AWSSeverity.HIGH,
                            description=f"S3 bucket {bucket_name} is publicly accessible",
                            remediation="Update the bucket policy to restrict access to authorized users only.",
                            references=[
                                "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
                            ]
                        ))
                except s3.exceptions.ClientError:
                    # No bucket policy or other error
                    pass
                
                # Check for bucket versioning
                try:
                    versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                    if versioning.get('Status') != 'Enabled':
                        self.findings.append(AWSFinding(
                            service=AWSService.S3,
                            resource_id=bucket_name,
                            finding_type="VERSIONING_DISABLED",
                            severity=AWSSeverity.MEDIUM,
                            description=f"S3 bucket {bucket_name} does not have versioning enabled",
                            remediation="Enable versioning to protect against accidental deletions and overwrites.",
                            references=[
                                "https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html"
                            ]
                        ))
                except Exception as e:
                    logger.error(f"Error checking versioning for bucket {bucket_name}: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Error scanning S3 buckets: {str(e)}")
    
    async def scan_ec2(self) -> None:
        """Scan EC2 instances for security issues."""
        for region in self.regions:
            try:
                ec2 = self.session.client('ec2', region_name=region)
                instances = ec2.describe_instances()['Reservations']
                
                for reservation in instances:
                    for instance in reservation['Instances']:
                        instance_id = instance['InstanceId']
                        
                        # Check for public IP addresses
                        public_ip = instance.get('PublicIpAddress')
                        if public_ip:
                            # Check security groups for overly permissive rules
                            for sg in instance.get('SecurityGroups', []):
                                sg_id = sg['GroupId']
                                sg_rules = ec2.describe_security_group_rules(
                                    Filters=[{'Name': 'group-id', 'Values': [sg_id]}]
                                )['SecurityGroupRules']
                                
                                for rule in sg_rules:
                                    if self._is_rule_too_permissive(rule):
                                        self.findings.append(AWSFinding(
                                            service=AWSService.EC2,
                                            resource_id=instance_id,
                                            finding_type="PERMISSIVE_SECURITY_GROUP",
                                            severity=AWSSeverity.HIGH,
                                            description=f"EC2 instance {instance_id} has a permissive security group rule",
                                            details={
                                                "instance_id": instance_id,
                                                "security_group_id": sg_id,
                                                "rule": str(rule)
                                            },
                                            remediation="Update the security group to restrict access to only necessary IP addresses and ports.",
                                            region=region,
                                            references=[
                                                "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security-groups.html"
                                            ]
                                        ))
            
            except Exception as e:
                logger.error(f"Error scanning EC2 instances in {region}: {str(e)}")
    
    async def scan_rds(self) -> None:
        """Scan RDS instances for security issues."""
        for region in self.regions:
            try:
                rds = self.session.client('rds', region_name=region)
                
                # Get all RDS instances
                instances = rds.describe_db_instances()['DBInstances']
                
                for instance in instances:
                    instance_id = instance['DBInstanceIdentifier']
                    
                    # Check if the instance is publicly accessible
                    if instance.get('PubliclyAccessible', False):
                        self.findings.append(AWSFinding(
                            service=AWSService.RDS,
                            resource_id=instance_id,
                            finding_type="PUBLIC_RDS_INSTANCE",
                            severity=AWSSeverity.HIGH,
                            description=f"RDS instance {instance_id} is publicly accessible",
                            details={
                                "instance_arn": instance['DBInstanceArn'],
                                "engine": instance['Engine'],
                                "engine_version": instance['EngineVersion'],
                                "publicly_accessible": True
                            },
                            remediation="Modify the RDS instance to disable public accessibility if not required.",
                            region=region,
                            references=[
                                "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_CommonTasks.Connect.html"
                            ]
                        ))
                    
                    # Check if encryption is enabled
                    if not instance.get('StorageEncrypted', False):
                        self.findings.append(AWSFinding(
                            service=AWSService.RDS,
                            resource_id=instance_id,
                            finding_type="UNENCRYPTED_RDS_INSTANCE",
                            severity=AWSSeverity.HIGH,
                            description=f"RDS instance {instance_id} is not encrypted",
                            details={
                                "instance_arn": instance['DBInstanceArn'],
                                "engine": instance['Engine'],
                                "engine_version": instance['EngineVersion']
                            },
                            remediation="Enable encryption for the RDS instance. This requires a snapshot and restore.",
                            region=region,
                            references=[
                                "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html"
                            ]
                        ))
                    
                    # Check for automatic minor version upgrades
                    if not instance.get('AutoMinorVersionUpgrade', False):
                        self.findings.append(AWSFinding(
                            service=AWSService.RDS,
                            resource_id=instance_id,
                            finding_type="NO_AUTO_MINOR_VERSION_UPGRADE",
                            severity=AWSSeverity.MEDIUM,
                            description=f"RDS instance {instance_id} does not have automatic minor version upgrades enabled",
                            details={
                                "instance_arn": instance['DBInstanceArn'],
                                "engine": instance['Engine'],
                                "engine_version": instance['EngineVersion']
                            },
                            remediation="Enable automatic minor version upgrades to receive important security patches automatically.",
                            region=region,
                            references=[
                                "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_UpgradeDBInstance.Maintenance.html"
                            ]
                        ))
                    
                    # Check backup retention period
                    backup_retention = instance.get('BackupRetentionPeriod', 0)
                    if backup_retention < 7:  # Less than 7 days
                        self.findings.append(AWSFinding(
                            service=AWSService.RDS,
                            resource_id=instance_id,
                            finding_type="INSUFFICIENT_BACKUP_RETENTION",
                            severity=AWSSeverity.MEDIUM,
                            description=f"RDS instance {instance_id} has a backup retention period of {backup_retention} days",
                            details={
                                "instance_arn": instance['DBInstanceArn'],
                                "backup_retention_period": backup_retention,
                                "recommended_minimum": 7
                            },
                            remediation=f"Increase the backup retention period to at least 7 days (currently {backup_retention} days).",
                            region=region,
                            references=[
                                "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html"
                            ]
                        ))
            
            except Exception as e:
                logger.error(f"Error scanning RDS instances in {region}: {str(e)}")
    
    async def scan_lambda(self) -> None:
        """Scan AWS Lambda functions for security issues."""
        for region in self.regions:
            try:
                lambda_client = self.session.client('lambda', region_name=region)
                
                # Get all Lambda functions
                paginator = lambda_client.get_paginator('list_functions')
                
                for page in paginator.paginate():
                    for function in page.get('Functions', []):
                        function_name = function['FunctionName']
                        function_arn = function['FunctionArn']
                        
                        # Check if function is publicly accessible
                        try:
                            policy = lambda_client.get_policy(FunctionName=function_name)
                            policy_doc = json.loads(policy.get('Policy', '{}'))
                            
                            # Check for public access in policy statements
                            for statement in policy_doc.get('Statement', []):
                                if statement.get('Effect') == 'Allow' and \
                                   statement.get('Principal', {}).get('AWS') == '*':
                                    self.findings.append(AWSFinding(
                                        service=AWSService.LAMBDA,
                                        resource_id=function_name,
                                        finding_type="PUBLIC_LAMBDA_FUNCTION",
                                        severity=AWSSeverity.HIGH,
                                        description=f"Lambda function {function_name} is publicly accessible",
                                        details={
                                            "function_arn": function_arn,
                                            "runtime": function.get('Runtime', 'unknown'),
                                            "last_modified": function.get('LastModified', 'unknown')
                                        },
                                        remediation="Update the resource-based policy to restrict access to specific principals.",
                                        region=region,
                                        references=[
                                            "https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html"
                                        ]
                                    ))
                        except lambda_client.exceptions.ResourceNotFoundException:
                            # No resource policy, which is fine
                            pass
                        except Exception as e:
                            logger.error(f"Error checking Lambda function policy for {function_name}: {str(e)}")
                        
                        # Check for environment variables with sensitive data
                        env_vars = function.get('Environment', {}).get('Variables', {})
                        sensitive_keys = [k for k in env_vars.keys() 
                                       if any(term in k.lower() for term in ['key', 'secret', 'password', 'token', 'credential'])]
                        
                        if sensitive_keys:
                            self.findings.append(AWSFinding(
                                service=AWSService.LAMBDA,
                                resource_id=function_name,
                                finding_type="SENSITIVE_ENV_VARIABLES",
                                severity=AWSSeverity.HIGH,
                                description=f"Lambda function {function_name} has potentially sensitive environment variables",
                                details={
                                    "function_arn": function_arn,
                                    "sensitive_keys": sensitive_keys,
                                    "runtime": function.get('Runtime', 'unknown')
                                },
                                remediation="Store sensitive data in AWS Secrets Manager or AWS Systems Manager Parameter Store.",
                                region=region,
                                references=[
                                    "https://docs.aws.amazon.com/secretsmanager/latest/userguide/integrating_csi_driver.html",
                                    "https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-parameter-store.html"
                                ]
                            ))
                        
                        # Check for excessive permissions
                        role_arn = function.get('Role')
                        if role_arn:
                            try:
                                iam = self.session.client('iam')
                                role_name = role_arn.split('/')[-1]
                                
                                # Get attached policies
                                attached_policies = iam.list_attached_role_policies(RoleName=role_name)
                                for policy in attached_policies.get('AttachedPolicies', []):
                                    if policy['PolicyName'] in ['AdministratorAccess', 'AWSLambdaFullAccess']:
                                        self.findings.append(AWSFinding(
                                            service=AWSService.LAMBDA,
                                            resource_id=function_name,
                                            finding_type="OVERLY_PERMISSIVE_LAMBDA_ROLE",
                                            severity=AWSSeverity.HIGH,
                                            description=f"Lambda function {function_name} has an overly permissive IAM role",
                                            details={
                                                "function_arn": function_arn,
                                                "role_arn": role_arn,
                                                "policy_arn": policy['PolicyArn'],
                                                "policy_name": policy['PolicyName']
                                            },
                                            remediation=f"Update the IAM role {role_name} to follow the principle of least privilege.",
                                            region=region,
                                            references=[
                                                "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"
                                            ]
                                        ))
                            except Exception as e:
                                logger.error(f"Error checking IAM role for Lambda function {function_name}: {str(e)}")
            
            except Exception as e:
                logger.error(f"Error scanning Lambda functions in {region}: {str(e)}")
    
    async def scan_config(self) -> None:
        """Scan AWS Config for security and compliance issues."""
        for region in self.regions:
            try:
                config_client = self.session.client('config', region_name=region)
                
                # Check if AWS Config is enabled
                try:
                    config_status = config_client.describe_configuration_recorder_status()
                    recorders = config_status.get('ConfigurationRecordersStatus', [])
                    
                    if not recorders or not any(r.get('recording', False) for r in recorders):
                        self.findings.append(AWSFinding(
                            service=AWSService.CONFIG,
                            resource_id=f"config-{region}",
                            finding_type="CONFIG_RECORDER_DISABLED",
                            severity=AWSSeverity.HIGH,
                            description=f"AWS Config is not enabled in region {region}",
                            details={
                                "region": region,
                                "recorders": recorders
                            },
                            remediation=(
                                "Enable AWS Config to track changes to your AWS resources. "
                                "AWS Config provides detailed historical configuration information that can be "
                                "used for security analysis, compliance auditing, and troubleshooting."
                            ),
                            region=region,
                            references=[
                                "https://docs.aws.amazon.com/config/latest/developerguide/gs-console.html"
                            ]
                        ))
                except config_client.exceptions.NoAvailableConfigurationRecorderException:
                    self.findings.append(AWSFinding(
                        service=AWSService.CONFIG,
                        resource_id=f"config-{region}",
                        finding_type="CONFIG_RECORDER_NOT_FOUND",
                        severity=AWSSeverity.HIGH,
                        description=f"AWS Config is not set up in region {region}",
                        details={"region": region},
                        remediation=(
                            "Set up AWS Config to track changes to your AWS resources. "
                            "This is a critical security control for maintaining visibility into your AWS environment."
                        ),
                        region=region,
                        references=[
                            "https://docs.aws.amazon.com/config/latest/developerguide/gs-console.html"
                        ]
                    ))
                
                # Check for compliance with AWS Config rules
                try:
                    # Get all config rules
                    paginator = config_client.get_paginator('describe_config_rules')
                    for page in paginator.paginate():
                        for rule in page.get('ConfigRules', []):
                            rule_name = rule.get('ConfigRuleName')
                            rule_arn = rule.get('ConfigRuleArn')
                            rule_state = rule.get('ConfigRuleState')
                            
                            # Skip inactive rules
                            if rule_state != 'ACTIVE':
                                continue
                            
                            # Get compliance details for the rule
                            compliance = config_client.get_compliance_details_by_config_rule(
                                ConfigRuleName=rule_name,
                                ComplianceTypes=['NON_COMPLIANT']
                            )
                            
                            non_compliant_resources = compliance.get('EvaluationResults', [])
                            if non_compliant_resources:
                                resource_ids = [r['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceId'] 
                                              for r in non_compliant_resources]
                                
                                self.findings.append(AWSFinding(
                                    service=AWSService.CONFIG,
                                    resource_id=rule_arn,
                                    finding_type="CONFIG_RULE_NON_COMPLIANT",
                                    severity=AWSSeverity.MEDIUM,
                                    description=f"AWS Config rule {rule_name} has {len(non_compliant_resources)} non-compliant resources",
                                    details={
                                        "rule_name": rule_name,
                                        "rule_arn": rule_arn,
                                        "non_compliant_count": len(non_compliant_resources),
                                        "non_compliant_resources": resource_ids[:10],  # Limit to first 10 for brevity
                                        "region": region
                                    },
                                    remediation=(
                                        f"Review and remediate the non-compliant resources for AWS Config rule {rule_name}. "
                                        "Addressing these issues will help ensure your resources are configured according to "
                                        "your organization's security and compliance requirements."
                                    ),
                                    region=region,
                                    references=[
                                        f"https://{region}.console.aws.amazon.com/config/home?region={region}#/rules/rule-details/{rule_name}"
                                    ]
                                ))
                
                except Exception as e:
                    logger.error(f"Error checking AWS Config rules in {region}: {str(e)}")
                
                # Check for delivery channel configuration
                try:
                    channels = config_client.describe_delivery_channels()
                    if not channels.get('DeliveryChannels'):
                        self.findings.append(AWSFinding(
                            service=AWSService.CONFIG,
                            resource_id=f"config-delivery-{region}",
                            finding_type="CONFIG_DELIVERY_CHANNEL_MISSING",
                            severity=AWSSeverity.HIGH,
                            description=f"AWS Config delivery channel is not configured in region {region}",
                            details={"region": region},
                            remediation=(
                                "Configure an AWS Config delivery channel to export configuration snapshots "
                                "to an S3 bucket and send notifications via SNS. This ensures you have a record of "
                                "configuration changes for security and compliance purposes."
                            ),
                            region=region,
                            references=[
                                "https://docs.aws.amazon.com/config/latest/developerguide/gs-console.html"
                            ]
                        ))
                    
                    # Check if delivery channel is properly configured
                    for channel in channels.get('DeliveryChannels', []):
                        if not channel.get('s3BucketName'):
                            self.findings.append(AWSFinding(
                                service=AWSService.CONFIG,
                                resource_id=f"config-delivery-{region}",
                                finding_type="CONFIG_DELIVERY_CHANNEL_INVALID",
                                severity=AWSSeverity.MEDIUM,
                                description=f"AWS Config delivery channel in region {region} is missing S3 bucket configuration",
                                details={
                                    "region": region,
                                    "channel_name": channel.get('name', 'default')
                                },
                                remediation=(
                                    "Configure an S3 bucket for AWS Config delivery channel to store configuration snapshots. "
                                    "This ensures you have a record of configuration changes for security and compliance purposes."
                                ),
                                region=region,
                                references=[
                                    "https://docs.aws.amazon.com/config/latest/developerguide/gs-console.html"
                                ]
                            ))
                
                except Exception as e:
                    logger.error(f"Error checking AWS Config delivery channels in {region}: {str(e)}")
                
            except Exception as e:
                logger.error(f"Error scanning AWS Config in {region}: {str(e)}")
    
    async def scan_cloudfront(self) -> None:
        """Scan CloudFront distributions for security issues."""
        for region in self.regions:
            try:
                cloudfront = self.session.client('cloudfront', region_name=region)
                
                # List all CloudFront distributions
                distributions = cloudfront.list_distributions()
                
                for dist in distributions.get('DistributionList', {}).get('Items', []):
                    try:
                        dist_id = dist['Id']
                        domain_name = dist['DomainName']
                        status = dist['Status']
                        enabled = dist['Enabled']
                        
                        # Check if logging is enabled
                        if not dist.get('Logging', {}).get('Enabled', False):
                            self.findings.append(AWSFinding(
                                service=AWSService.CLOUDFRONT,
                                resource_id=dist_id,
                                finding_type="CLOUDFRONT_LOGGING_DISABLED",
                                severity=AWSSeverity.MEDIUM,
                                description=f"CloudFront distribution {dist_id} does not have access logging enabled",
                                details={
                                    "distribution_id": dist_id,
                                    "domain_name": domain_name,
                                    "status": status,
                                    "enabled": enabled,
                                    "last_modified_time": dist.get('LastModifiedTime', '').isoformat()
                                },
                                remediation=(
                                    "Enable access logging for the CloudFront distribution to track viewer requests. "
                                    "This helps with security analysis, troubleshooting, and compliance requirements."
                                ),
                                region=region,
                                references=[
                                    "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html"
                                ]
                            ))
                        
                        # Check if WAF is enabled
                        if not dist.get('WebACLId'):
                            self.findings.append(AWSFinding(
                                service=AWSService.CLOUDFRONT,
                                resource_id=dist_id,
                                finding_type="CLOUDFRONT_WAF_DISABLED",
                                severity=AWSSeverity.HIGH,
                                description=f"CloudFront distribution {dist_id} does not have WAF enabled",
                                details={
                                    "distribution_id": dist_id,
                                    "domain_name": domain_name,
                                    "status": status
                                },
                                remediation=(
                                    "Enable AWS WAF (Web Application Firewall) for the CloudFront distribution. "
                                    "WAF helps protect your web applications from common web exploits that could affect "
                                    "application availability, compromise security, or consume excessive resources."
                                ),
                                region=region,
                                references=[
                                    "https://docs.aws.amazon.com/waf/latest/developerguide/cloudfront-features.html"
                                ]
                            ))
                        
                        # Check for insecure SSL/TLS protocols
                        viewer_cert = dist.get('ViewerCertificate', {})
                        min_protocol = viewer_cert.get('MinimumProtocolVersion', 'TLSv1')
                        if min_protocol in ['SSLv3', 'TLSv1', 'TLSv1_2016']:
                            self.findings.append(AWSFinding(
                                service=AWSService.CLOUDFRONT,
                                resource_id=dist_id,
                                finding_type="CLOUDFRONT_INSECURE_SSL_PROTOCOL",
                                severity=AWSSeverity.HIGH,
                                description=f"CloudFront distribution {dist_id} is using an insecure minimum SSL/TLS protocol version: {min_protocol}",
                                details={
                                    "distribution_id": dist_id,
                                    "domain_name": domain_name,
                                    "minimum_protocol_version": min_protocol,
                                    "ssl_support_method": viewer_cert.get('SSLSupportMethod', 'N/A'),
                                    "certificate_source": viewer_cert.get('CertificateSource', 'N/A')
                                },
                                remediation=(
                                    "Update the SSL/TLS security policy to use a minimum protocol version of TLSv1.2_2021 or later. "
                                    "Older SSL/TLS protocols have known vulnerabilities and should not be used."
                                ),
                                region=region,
                                references=[
                                    "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html"
                                ]
                            ))
                        
                        # Check for insecure ciphers
                        ssl_protocols = dist.get('ViewerCertificate', {}).get('Ciphers', [])
                        if any(cipher in ssl_protocols for cipher in ['DES-CBC3-SHA', 'RC4-SHA', 'RC4-MD5']):
                            self.findings.append(AWSFinding(
                                service=AWSService.CLOUDFRONT,
                                resource_id=dist_id,
                                finding_type="CLOUDFRONT_INSECURE_CIPHERS",
                                severity=AWSSeverity.HIGH,
                                description=f"CloudFront distribution {dist_id} is using insecure SSL/TLS ciphers",
                                details={
                                    "distribution_id": dist_id,
                                    "domain_name": domain_name,
                                    "insecure_ciphers": [c for c in ssl_protocols if c in ['DES-CBC3-SHA', 'RC4-SHA', 'RC4-MD5']]
                                },
                                remediation=(
                                    "Update the SSL/TLS security policy to use only secure ciphers. "
                                    "Remove insecure ciphers like DES-CBC3-SHA, RC4-SHA, and RC4-MD5 which have known vulnerabilities."
                                ),
                                region=region,
                                references=[
                                    "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html"
                                ]
                            ))
                        
                        # Check for geo-restriction bypass
                        geo_restriction = dist.get('Restrictions', {}).get('GeoRestriction', {})
                        if geo_restriction.get('RestrictionType', 'none') == 'none':
                            self.findings.append(AWSFinding(
                                service=AWSService.CLOUDFRONT,
                                resource_id=dist_id,
                                finding_type="CLOUDFRONT_GEO_RESTRICTION_DISABLED",
                                severity=AWSSeverity.MEDIUM,
                                description=f"CloudFront distribution {dist_id} does not have geo-restriction enabled",
                                details={
                                    "distribution_id": dist_id,
                                    "domain_name": domain_name,
                                    "restriction_type": "none"
                                },
                                remediation=(
                                    "Consider implementing geo-restriction to allow or block specific countries from accessing your content. "
                                    "This can help reduce the attack surface and comply with data sovereignty requirements."
                                ),
                                region=region,
                                references=[
                                    "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/georestrictions.html"
                                ]
                            ))
                        
                        # Check for field-level encryption
                        if not dist.get('DefaultCacheBehavior', {}).get('FieldLevelEncryptionId'):
                            self.findings.append(AWSFinding(
                                service=AWSService.CLOUDFRONT,
                                resource_id=dist_id,
                                finding_type="CLOUDFRONT_FIELD_LEVEL_ENCRYPTION_DISABLED",
                                severity=AWSSeverity.MEDIUM,
                                description=f"CloudFront distribution {dist_id} does not have field-level encryption enabled",
                                details={
                                    "distribution_id": dist_id,
                                    "domain_name": domain_name
                                },
                                remediation=(
                                    "Consider enabling field-level encryption for sensitive data fields. "
                                    "This ensures that specific fields in viewer requests are encrypted at the edge, "
                                    "providing an additional layer of security for sensitive information."
                                ),
                                region=region,
                                references=[
                                    "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/field-level-encryption.html"
                                ]
                            ))
                        
                    except Exception as e:
                        logger.error(f"Error scanning CloudFront distribution {dist.get('Id', 'unknown')}: {str(e)}")
            
            except Exception as e:
                logger.error(f"Error scanning CloudFront in {region}: {str(e)}")
    
    async def scan_eks(self) -> None:
        """Scan EKS (Elastic Kubernetes Service) clusters for security issues."""
        for region in self.regions:
            try:
                eks = self.session.client('eks', region_name=region)
                
                # List all EKS clusters
                clusters = eks.list_clusters()
                
                for cluster_name in clusters.get('clusters', []):
                    try:
                        # Get cluster details
                        cluster = eks.describe_cluster(name=cluster_name)['cluster']
                        cluster_arn = cluster['arn']
                        
                        # Check if cluster logging is enabled
                        if not cluster.get('logging', {}).get('clusterLogging', [{}])[0].get('enabled', False):
                            self.findings.append(AWSFinding(
                                service=AWSService.EKS,
                                resource_id=cluster_name,
                                finding_type="EKS_LOGGING_DISABLED",
                                severity=AWSSeverity.MEDIUM,
                                description=f"EKS cluster {cluster_name} does not have logging enabled",
                                details={
                                    "cluster_arn": cluster_arn,
                                    "status": cluster.get('status', 'UNKNOWN'),
                                    "kubernetes_version": cluster.get('version', 'UNKNOWN'),
                                    "platform_version": cluster.get('platformVersion', 'UNKNOWN'),
                                    "endpoint_public_access": cluster.get('resourcesVpcConfig', {}).get('endpointPublicAccess', False),
                                    "endpoint_private_access": cluster.get('resourcesVpcConfig', {}).get('endpointPrivateAccess', False)
                                },
                                remediation=(
                                    "Enable audit and other important log types for the EKS cluster. "
                                    "This helps with security analysis, compliance, and troubleshooting."
                                ),
                                region=region,
                                references=[
                                    "https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html"
                                ]
                            ))
                        
                        # Check if the cluster endpoint is publicly accessible
                        if cluster.get('resourcesVpcConfig', {}).get('endpointPublicAccess', False):
                            public_access_cidrs = cluster.get('resourcesVpcConfig', {}).get('publicAccessCidrs', ['0.0.0.0/0'])
                            if '0.0.0.0/0' in public_access_cidrs:
                                self.findings.append(AWSFinding(
                                    service=AWSService.EKS,
                                    resource_id=cluster_name,
                                    finding_type="EKS_PUBLIC_ACCESS_ENABLED",
                                    severity=AWSSeverity.HIGH,
                                    description=f"EKS cluster {cluster_name} has public endpoint access from the internet (0.0.0.0/0)",
                                    details={
                                        "cluster_arn": cluster_arn,
                                        "public_access_cidrs": public_access_cidrs,
                                        "status": cluster.get('status', 'UNKNOWN')
                                    },
                                    remediation=(
                                        "Restrict public access to the EKS cluster endpoint by updating the publicAccessCidrs setting. "
                                        "Limit access to specific IP ranges that require access to the cluster."
                                    ),
                                    region=region,
                                    references=[
                                        "https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html"
                                    ]
                                ))
                        
                        # Check if the cluster is running an outdated Kubernetes version
                        current_version = cluster.get('version', '0.0')
                        if current_version != 'UNKNOWN':
                            from packaging import version
                            try:
                                if version.parse(current_version) < version.parse('1.21'):
                                    self.findings.append(AWSFinding(
                                        service=AWSService.EKS,
                                        resource_id=cluster_name,
                                        finding_type="EKS_OUTDATED_VERSION",
                                        severity=AWSSeverity.HIGH,
                                        description=f"EKS cluster {cluster_name} is running an outdated Kubernetes version ({current_version})",
                                        details={
                                            "cluster_arn": cluster_arn,
                                            "current_version": current_version,
                                            "recommended_version": "1.21 or later"
                                        },
                                        remediation=(
                                            "Upgrade the EKS cluster to a supported Kubernetes version. "
                                            "Older versions may have known security vulnerabilities and lack important security features."
                                        ),
                                        region=region,
                                        references=[
                                            "https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html"
                                        ]
                                    ))
                            except Exception as e:
                                logger.warning(f"Could not parse Kubernetes version {current_version}: {str(e)}")
                        
                        # Check for security group issues
                        security_groups = cluster.get('resourcesVpcConfig', {}).get('securityGroupIds', [])
                        if not security_groups:
                            self.findings.append(AWSFinding(
                                service=AWSService.EKS,
                                resource_id=cluster_name,
                                finding_type="EKS_NO_SECURITY_GROUPS",
                                severity=AWSSeverity.HIGH,
                                description=f"EKS cluster {cluster_name} has no security groups attached",
                                details={
                                    "cluster_arn": cluster_arn,
                                    "status": cluster.get('status', 'UNKNOWN')
                                },
                                remediation=(
                                    "Attach appropriate security groups to the EKS cluster to control network traffic. "
                                    "Ensure that the security groups follow the principle of least privilege."
                                ),
                                region=region,
                                references=[
                                    "https://docs.aws.amazon.com/eks/latest/userguide/sec-group-reqs.html"
                                ]
                            ))
                        
                        # Check for unencrypted secrets
                        if not cluster.get('encryptionConfig'):
                            self.findings.append(AWSFinding(
                                service=AWSService.EKS,
                                resource_id=cluster_name,
                                finding_type="EKS_SECRETS_NOT_ENCRYPTED",
                                severity=AWSSeverity.HIGH,
                                description=f"EKS cluster {cluster_name} does not have encryption at rest enabled for Kubernetes secrets",
                                details={
                                    "cluster_arn": cluster_arn,
                                    "status": cluster.get('status', 'UNKNOWN')
                                },
                                remediation=(
                                    "Enable encryption at rest for Kubernetes secrets using AWS Key Management Service (KMS). "
                                    "This ensures that sensitive data stored in etcd is encrypted."
                                ),
                                region=region,
                                references=[
                                    "https://docs.aws.amazon.com/eks/latest/userguide/encryption-at-rest.html"
                                ]
                            ))
                        
                        # Check for outdated platform version
                        platform_version = cluster.get('platformVersion', '')
                        if platform_version and not platform_version.startswith('eks.') and not platform_version.startswith('1.'):
                            self.findings.append(AWSFinding(
                                service=AWSService.EKS,
                                resource_id=cluster_name,
                                finding_type="EKS_OUTDATED_PLATFORM_VERSION",
                                severity=AWSSeverity.MEDIUM,
                                description=f"EKS cluster {cluster_name} is running an outdated platform version",
                                details={
                                    "cluster_arn": cluster_arn,
                                    "platform_version": platform_version,
                                    "status": cluster.get('status', 'UNKNOWN')
                                },
                                remediation=(
                                    "Update the EKS cluster to the latest platform version to ensure you have the latest security patches "
                                    "and features. Platform updates are released regularly by AWS."
                                ),
                                region=region,
                                references=[
                                    "https://docs.aws.amazon.com/eks/latest/userguide/platform-versions.html"
                                ]
                            ))
                        
                    except Exception as e:
                        logger.error(f"Error scanning EKS cluster {cluster_name}: {str(e)}")
            
            except Exception as e:
                logger.error(f"Error scanning EKS in {region}: {str(e)}")
    
    async def scan_ecr(self) -> None:
        """Scan ECR (Elastic Container Registry) for security issues."""
        for region in self.regions:
            try:
                ecr = self.session.client('ecr', region_name=region)
                
                # List all ECR repositories
                paginator = ecr.get_paginator('describe_repositories')
                
                for page in paginator.paginate():
                    for repo in page.get('repositories', []):
                        repo_name = repo['repositoryName']
                        repo_arn = repo['repositoryArn']
                        
                        # Get image scanning configuration
                        try:
                            scan_config = ecr.describe_image_scan_findings(
                                repositoryName=repo_name,
                                imageId={'imageTag': 'latest'}
                            )
                            
                            # Check if image scanning is enabled
                            if not repo.get('imageScanningConfiguration', {}).get('scanOnPush', False):
                                self.findings.append(AWSFinding(
                                    service=AWSService.ECR,
                                    resource_id=repo_name,
                                    finding_type="ECR_SCAN_ON_PUSH_DISABLED",
                                    severity=AWSSeverity.HIGH,
                                    description=f"ECR repository {repo_name} does not have scan on push enabled",
                                    details={
                                        "repository_arn": repo_arn,
                                        "repository_uri": repo.get('repositoryUri', ''),
                                        "created_at": repo.get('createdAt', '').isoformat()
                                    },
                                    remediation="Enable scan on push for the ECR repository to automatically scan images for vulnerabilities.",
                                    region=region,
                                    references=[
                                        "https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html"
                                    ]
                                ))
                            
                            # Check for critical/high severity findings
                            if 'imageScanFindings' in scan_config:
                                findings = scan_config['imageScanFindings']
                                critical_findings = [f for f in findings.get('findings', []) 
                                                   if f.get('severity') in ['CRITICAL', 'HIGH']]
                                
                                if critical_findings:
                                    self.findings.append(AWSFinding(
                                        service=AWSService.ECR,
                                        resource_id=repo_name,
                                        finding_type="ECR_IMAGE_VULNERABILITIES",
                                        severity=AWSSeverity.HIGH,
                                        description=f"ECR repository {repo_name} contains images with {len(critical_findings)} critical/high severity vulnerabilities",
                                        details={
                                            "repository_arn": repo_arn,
                                            "vulnerability_count": len(critical_findings),
                                            "vulnerabilities": [
                                                {
                                                    "severity": f.get('severity'),
                                                    "name": f.get('name'),
                                                    "uri": f.get('uri'),
                                                    "description": f.get('description')
                                                }
                                                for f in critical_findings[:5]  # Limit to first 5 for brevity
                                            ],
                                            "scan_completed_at": findings.get('imageScanCompletedAt', '').isoformat()
                                        },
                                        remediation=(
                                            "Update the base image to a version without these vulnerabilities. "
                                            "Regularly update your images and their dependencies to the latest secure versions. "
                                            "Consider using a vulnerability scanning tool in your CI/CD pipeline."
                                        ),
                                        region=region,
                                        references=[
                                            "https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html",
                                            "https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning-finding-removal.html"
                                        ]
                                    ))
                            
                        except ecr.exceptions.ScanNotFoundException:
                            # No scan results available
                            self.findings.append(AWSFinding(
                                service=AWSService.ECR,
                                resource_id=repo_name,
                                finding_type="ECR_SCAN_NOT_FOUND",
                                severity=AWSSeverity.MEDIUM,
                                description=f"No vulnerability scan results found for images in ECR repository {repo_name}",
                                details={
                                    "repository_arn": repo_arn,
                                    "repository_uri": repo.get('repositoryUri', '')
                                },
                                remediation=(
                                    "Ensure that image scanning is properly configured for this repository. "
                                    "Push a new image with the 'scanOnPush' setting enabled to trigger a scan."
                                ),
                                region=region,
                                references=[
                                    "https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html"
                                ]
                            ))
                        except Exception as e:
                            logger.error(f"Error scanning ECR repository {repo_name}: {str(e)}")
                            
                        # Check for immutable tags
                        try:
                            lifecycle_policy = ecr.get_lifecycle_policy(repositoryName=repo_name)
                            policy_text = json.loads(lifecycle_policy['lifecyclePolicyText'])
                            
                            # Check if there's a rule that prevents image deletion
                            has_immutable_rule = any(
                                rule.get('selection', {}).get('tagStatus') == 'any' and 
                                'expire' in rule.get('action', {})
                                for rule in policy_text.get('rules', [])
                            )
                            
                            if not has_immutable_rule:
                                self.findings.append(AWSFinding(
                                    service=AWSService.ECR,
                                    resource_id=repo_name,
                                    finding_type="ECR_IMMUTABLE_TAGS_DISABLED",
                                    severity=AWSSeverity.MEDIUM,
                                    description=f"ECR repository {repo_name} does not have immutable tags enabled",
                                    details={
                                        "repository_arn": repo_arn,
                                        "repository_uri": repo.get('repositoryUri', '')
                                    },
                                    remediation=(
                                        "Enable immutable tags for the ECR repository to prevent image tags from being overwritten. "
                                        "This helps maintain image immutability and prevents potential supply chain attacks."
                                    ),
                                    region=region,
                                    references=[
                                        "https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-tag-mutability.html"
                                    ]
                                ))
                                
                        except ecr.exceptions.LifecyclePolicyNotFoundException:
                            # No lifecycle policy found
                            self.findings.append(AWSFinding(
                                service=AWSService.ECR,
                                resource_id=repo_name,
                                finding_type="ECR_LIFECYCLE_POLICY_MISSING",
                                severity=AWSSeverity.MEDIUM,
                                description=f"ECR repository {repo_name} does not have a lifecycle policy configured",
                                details={
                                    "repository_arn": repo_arn,
                                    "repository_uri": repo.get('repositoryUri', '')
                                },
                                remediation=(
                                    "Configure a lifecycle policy for the ECR repository to manage the lifecycle of images. "
                                    "This helps control storage usage and automatically clean up old or unused images."
                                ),
                                region=region,
                                references=[
                                    "https://docs.aws.amazon.com/AmazonECR/latest/userguide/LifecyclePolicies.html"
                                ]
                            ))
                        except Exception as e:
                            logger.error(f"Error checking lifecycle policy for ECR repository {repo_name}: {str(e)}")
            
            except Exception as e:
                logger.error(f"Error scanning ECR in {region}: {str(e)}")
    
    async def scan_ecs(self) -> None:
        """Scan ECS (Elastic Container Service) for security issues."""
        for region in self.regions:
            try:
                ecs = self.session.client('ecs', region_name=region)
                ec2 = self.session.client('ec2', region_name=region)
                
                # List all ECS clusters
                clusters = ecs.list_clusters()
                
                for cluster_arn in clusters.get('clusterArns', []):
                    cluster_name = cluster_arn.split('/')[-1]
                    
                    # Get cluster details
                    cluster_details = ecs.describe_clusters(clusters=[cluster_arn])
                    if not cluster_details.get('clusters'):
                        continue
                        
                    cluster = cluster_details['clusters'][0]
                    
                    # Check container insights
                    if not cluster.get('settings', {}).get('name') == 'containerInsights' or \
                       not cluster.get('settings', {}).get('value') == 'enabled':
                        self.findings.append(AWSFinding(
                            service=AWSService.ECS,
                            resource_id=cluster_name,
                            finding_type="CONTAINER_INSIGHTS_DISABLED",
                            severity=AWSSeverity.MEDIUM,
                            description=f"ECS cluster {cluster_name} does not have Container Insights enabled",
                            details={
                                "cluster_arn": cluster_arn,
                                "status": cluster.get('status', 'UNKNOWN'),
                                "running_tasks_count": cluster.get('runningTasksCount', 0),
                                "active_services_count": cluster.get('activeServicesCount', 0)
                            },
                            remediation="Enable Container Insights for better monitoring and troubleshooting of your ECS resources.",
                            region=region,
                            references=[
                                "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/ContainerInsights.html"
                            ]
                        ))
                    
                    # Check for tasks with elevated privileges
                    tasks = ecs.list_tasks(cluster=cluster_arn)
                    for task_arn in tasks.get('taskArns', []):
                        task_details = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])
                        
                        for task in task_details.get('tasks', []):
                            task_definition_arn = task.get('taskDefinitionArn', '')
                            
                            # Skip if we've already checked this task definition
                            if not task_definition_arn:
                                continue
                                
                            # Get task definition details
                            task_def = ecs.describe_task_definition(
                                taskDefinition=task_definition_arn
                            )
                            
                            task_definition = task_def.get('taskDefinition', {})
                            
                            # Check for privileged containers
                            for container in task_definition.get('containerDefinitions', []):
                                if container.get('privileged', False):
                                    self.findings.append(AWSFinding(
                                        service=AWSService.ECS,
                                        resource_id=container.get('name', 'unknown'),
                                        finding_type="PRIVILEGED_CONTAINER",
                                        severity=AWSSeverity.HIGH,
                                        description=f"Privileged container found in ECS task {task_definition_arn}",
                                        details={
                                            "cluster_name": cluster_name,
                                            "task_definition_arn": task_definition_arn,
                                            "container_name": container.get('name', 'unknown'),
                                            "image": container.get('image', 'unknown')
                                        },
                                        remediation="Avoid running containers in privileged mode unless absolutely necessary.",
                                        region=region,
                                        references=[
                                            "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html#container_definition_privileged"
                                        ]
                                    ))
                            
                            # Check task role permissions
                            task_role_arn = task_definition.get('taskRoleArn')
                            if task_role_arn:
                                try:
                                    iam = self.session.client('iam')
                                    role_name = task_role_arn.split('/')[-1]
                                    
                                    # Get attached policies
                                    attached_policies = iam.list_attached_role_policies(RoleName=role_name)
                                    for policy in attached_policies.get('AttachedPolicies', []):
                                        if policy['PolicyName'] in ['AdministratorAccess', 'AmazonEC2ContainerServiceFullAccess']:
                                            self.findings.append(AWSFinding(
                                                service=AWSService.ECS,
                                                resource_id=cluster_name,
                                                finding_type="OVERLY_PERMISSIVE_TASK_ROLE",
                                                severity=AWSSeverity.HIGH,
                                                description=f"ECS task in cluster {cluster_name} has an overly permissive IAM role",
                                                details={
                                                    "task_definition_arn": task_definition_arn,
                                                    "role_arn": task_role_arn,
                                                    "policy_arn": policy['PolicyArn'],
                                                    "policy_name": policy['PolicyName']
                                                },
                                                remediation=f"Update the IAM role {role_name} to follow the principle of least privilege.",
                                                region=region,
                                                references=[
                                                    "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html"
                                                ]
                                            ))
                                except Exception as e:
                                    logger.error(f"Error checking IAM role for ECS task {task_arn}: {str(e)}")
            
            except Exception as e:
                logger.error(f"Error scanning ECS in {region}: {str(e)}")
    
    async def scan_cloudtrail(self) -> None:
        """Scan AWS CloudTrail for security issues."""
        # This is a placeholder for CloudTrail scanning
        # In a real implementation, you would check CloudTrail logs for suspicious activities
        pass
        
    async def scan_kubernetes(self) -> None:
        """Scan EKS clusters for security issues."""
        try:
            logger.info("Scanning EKS clusters for security issues...")
            
            # Initialize EKS client
            eks_client = self.session.client('eks', region_name=self.region)
            
            # List all EKS clusters
            clusters = eks_client.list_clusters()
            
            if not clusters.get('clusters'):
                logger.info("No EKS clusters found in region %s", self.region)
                return
            
            # Scan each cluster
            for cluster_name in clusters['clusters']:
                try:
                    # Get cluster details
                    cluster = eks_client.describe_cluster(name=cluster_name)['cluster']
                    
                    # Initialize Kubernetes scanner with the cluster's kubeconfig
                    kubeconfig = self._get_eks_kubeconfig(cluster_name)
                    k8s_scanner = KubernetesScanner(kubeconfig=kubeconfig)
                    
                    # Run Kubernetes security scan
                    findings = await k8s_scanner.scan_cluster()
                    
                    # Add findings to the results
                    self.findings.extend(findings)
                    
                    logger.info("Scanned EKS cluster: %s (%d findings)", cluster_name, len(findings))
                    
                except Exception as e:
                    logger.error("Error scanning EKS cluster %s: %s", cluster_name, str(e))
                    
        except Exception as e:
            logger.error("Error scanning EKS clusters: %s", str(e))
    
    def _get_eks_kubeconfig(self, cluster_name: str) -> str:
        """Generate a kubeconfig for the specified EKS cluster.
        
        Args:
            cluster_name: Name of the EKS cluster
            
        Returns:
            Path to the generated kubeconfig file
        """
        import tempfile
        import os
        
        # Get cluster details
        eks_client = self.session.client('eks', region_name=self.region)
        cluster = eks_client.describe_cluster(name=cluster_name)['cluster']
        
        # Generate kubeconfig
        kubeconfig = f"""apiVersion: v1
clusters:
- cluster:
    server: {cluster['endpoint']}
    certificate-authority-data: {cluster['certificateAuthority']['data']}
  name: {cluster['arn']}
contexts:
- context:
    cluster: {cluster['arn']}
    user: aws
  name: aws
current-context: aws
kind: Config
preferences: {{}}
users:
- name: aws
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1alpha1
      command: aws-iam-authenticator
      args:
        - "token"
        - "-i"
        - "{cluster_name}"
"""
        # Write kubeconfig to a temporary file
        fd, path = tempfile.mkstemp(suffix='.yaml')
        with os.fdopen(fd, 'w') as f:
            f.write(kubeconfig)
            
        return path
    
    async def scan_cloudtrail(self) -> None:
        """Scan CloudTrail for security issues."""
        for region in self.regions:
            try:
                cloudtrail = self.session.client('cloudtrail', region_name=region)
                
                # Get all CloudTrail trails
                trails = cloudtrail.describe_trails()['trailList']
                
                if not trails:
                    # No CloudTrail trails found
                    self.findings.append(AWSFinding(
                        service=AWSService.CLOUDTRAIL,
                        resource_id="account-trail",
                        finding_type="NO_CLOUDTRAIL_TRAILS",
                        severity=AWSSeverity.HIGH,
                        description="No CloudTrail trails are configured in this region",
                        remediation="Enable CloudTrail to log all API activity in this region.",
                        region=region,
                        references=[
                            "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html"
                        ]
                    ))
                    continue
                
                for trail in trails:
                    trail_name = trail['Name']
                    trail_arn = trail['TrailARN']
                    
                    # Check if multi-region trail
                    if not trail.get('IsMultiRegionTrail', False):
                        self.findings.append(AWSFinding(
                            service=AWSService.CLOUDTRAIL,
                            resource_id=trail_name,
                            finding_type="SINGLE_REGION_TRAIL",
                            severity=AWSSeverity.MEDIUM,
                            description=f"CloudTrail trail {trail_name} is not a multi-region trail",
                            details={
                                "trail_arn": trail_arn,
                                "home_region": trail.get('HomeRegion', 'unknown'),
                                "is_organization_trail": trail.get('IsOrganizationTrail', False)
                            },
                            remediation="Convert the trail to a multi-region trail to ensure all regions are logged.",
                            region=region,
                            references=[
                                "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html"
                            ]
                        ))
                    
                    # Check if log file validation is enabled
                    if not trail.get('LogFileValidationEnabled', False):
                        self.findings.append(AWSFinding(
                            service=AWSService.CLOUDTRAIL,
                            resource_id=trail_name,
                            finding_type="LOG_FILE_VALIDATION_DISABLED",
                            severity=AWSSeverity.MEDIUM,
                            description=f"CloudTrail trail {trail_name} does not have log file validation enabled",
                            details={
                                "trail_arn": trail_arn,
                                "s3_bucket_name": trail.get('S3BucketName', 'unknown'),
                                "s3_key_prefix": trail.get('S3KeyPrefix', 'none')
                            },
                            remediation="Enable log file validation to detect tampering of log files.",
                            region=region,
                            references=[
                                "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html"
                            ]
                        ))
                    
                    # Check if the trail is logging all management events
                    event_selectors = cloudtrail.get_event_selectors(TrailName=trail_name)
                    all_management_events = False
                    
                    for selector in event_selectors.get('EventSelectors', []):
                        if selector.get('IncludeManagementEvents', False) and \
                           selector.get('ReadWriteType', '') == 'All':
                            all_management_events = True
                            break
                    
                    if not all_management_events:
                        self.findings.append(AWSFinding(
                            service=AWSService.CLOUDTRAIL,
                            resource_id=trail_name,
                            finding_type="INSUFFICIENT_LOGGING",
                            severity=AWSSeverity.MEDIUM,
                            description=f"CloudTrail trail {trail_name} is not logging all management events",
                            details={
                                "trail_arn": trail_arn,
                                "event_selectors": str(event_selectors.get('EventSelectors', []))
                            },
                            remediation="Configure the trail to log all management events (both read and write).",
                            region=region,
                            references=[
                                "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-management-events-with-cloudtrail.html"
                            ]
                        ))
                    
                    # Check if CloudTrail is integrated with CloudWatch Logs
                    if not trail.get('CloudWatchLogsLogGroupArn', None):
                        self.findings.append(AWSFinding(
                            service=AWSService.CLOUDTRAIL,
                            resource_id=trail_name,
                            finding_type="NO_CLOUDWATCH_LOGS_INTEGRATION",
                            severity=AWSSeverity.LOW,
                            description=f"CloudTrail trail {trail_name} is not integrated with CloudWatch Logs",
                            details={
                                "trail_arn": trail_arn,
                                "cloud_watch_logs_role_arn": trail.get('CloudWatchLogsRoleArn', 'none')
                            },
                            remediation="Integrate CloudTrail with CloudWatch Logs for better log management and alerting.",
                            region=region,
                            references=[
                                "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html"
                            ]
                        ))
            
            except Exception as e:
                logger.error(f"Error scanning CloudTrail in {region}: {str(e)}")
    
    def _is_rule_too_permissive(self, rule: Dict) -> bool:
        """Check if a security group rule is too permissive."""
        # Check for open to the world (0.0.0.0/0 or ::/0)
        for ip_range in rule.get('IpRanges', []):
            if ip_range.get('CidrIp') == '0.0.0.0/0':
                # Check if it's for a critical port
                from_port = rule.get('FromPort')
                to_port = rule.get('ToPort')
                
                # Common critical ports
                critical_ports = [
                    22,    # SSH
                    21,    # FTP
                    3389,  # RDP
                    1433,  # MS SQL
                    3306,  # MySQL
                    5432,  # PostgreSQL
                    27017, # MongoDB
                    1521,  # Oracle
                    6379,  # Redis
                    9200,  # Elasticsearch
                    5601,  # Kibana
                    80,    # HTTP
                    443,   # HTTPS
                    8080,  # Common HTTP alt
                    8443   # Common HTTPS alt
                ]
                
                # Check if this rule opens any critical ports to the world
                if from_port is not None and to_port is not None:
                    for port in range(from_port, to_port + 1):
                        if port in critical_ports:
                            return True
                
                # If no specific ports are specified, it's open on all ports
                if from_port is None and to_port is None:
                    return True
        
        return False

# Compatibility layer for the existing module system
class Module:
    def __init__(self, config, payload_engine, analyzer, verbose=False):
        self.config = config
        self.payload_engine = payload_engine
        self.analyzer = analyzer
        self.verbose = verbose
        self.findings = []
    
    async def run(self):
        """Run the AWS security scan."""
        try:
            # Get AWS credentials from config
            aws_config = self.config.get('aws', {})
            scanner = AWSScanner(
                access_key=aws_config.get('access_key'),
                secret_key=aws_config.get('secret_key'),
                session_token=aws_config.get('session_token'),
                profile=aws_config.get('profile'),
                regions=aws_config.get('regions')
            )
            
            # Determine which services to scan
            services_to_scan = []
            if self.config.get('scan_iam', True):
                services_to_scan.append(AWSService.IAM)
            if self.config.get('scan_s3', True):
                services_to_scan.append(AWSService.S3)
            if self.config.get('scan_ec2', True):
                services_to_scan.append(AWSService.EC2)
            
            # Run the scan
            self.findings = await scanner.scan(services=services_to_scan)
            
            # Convert findings to the format expected by the framework
            return [
                {
                    'type': finding.finding_type,
                    'resource': finding.resource_id,
                    'service': finding.service.value,
                    'severity': finding.severity.value.upper(),
                    'description': finding.description,
                    'details': finding.details,
                    'remediation': finding.remediation,
                    'region': finding.region or 'global'
                }
                for finding in self.findings
            ]
            
        except Exception as e:
            if self.verbose:
                logger.error(f"Error running AWS security scan: {str(e)}", exc_info=True)
            return []
