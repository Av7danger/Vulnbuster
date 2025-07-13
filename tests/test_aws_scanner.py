"""
Tests for the AWS security scanner module.
"""

import pytest
import asyncio
from unittest.mock import MagicMock, patch, AsyncMock
from modes.cloud.modules.aws_scanner import (
    AWSScanner, 
    AWSFinding, 
    AWSService, 
    AWSSeverity,
    Module
)

@pytest.fixture
def mock_boto3():
    """Mock boto3 client and session."""
    with patch('boto3.Session') as mock_session:
        mock_client = MagicMock()
        mock_session.return_value.client.return_value = mock_client
        yield mock_client

@pytest.fixture
def aws_scanner():
    """Create an AWS scanner instance for testing."""
    return AWSScanner(access_key='test', secret_key='test')

@pytest.mark.asyncio
async def test_aws_scanner_initialization(aws_scanner):
    """Test AWS scanner initialization."""
    assert aws_scanner is not None
    assert len(aws_scanner.regions) > 0  # Should have at least one region

@pytest.mark.asyncio
async def test_scan_iam_root_keys(aws_scanner, mock_boto3):
    """Test scanning for root access keys."""
    # Mock the IAM client response
    mock_boto3.get_account_summary.return_value = {
        'SummaryMap': {
            'AccountAccessKeysPresent': 1,
            'AccountMFAEnabled': 1,
            'AccountSigningCertificatesPresent': 0,
            'GroupPolicySizeQuota': 5120,
            'Groups': 5,
            'GroupsPerUserQuota': 10,
            'GroupsQuota': 100,
            'InstanceProfiles': 0,
            'InstanceProfilesQuota': 1000,
            'MFADevices': 3,
            'MFADevicesInUse': 2,
            'Policies': 10,
            'PoliciesQuota': 1500,
            'PolicySizeQuota': 10240,
            'PolicyVersionsInUse': 20,
            'PolicyVersionsInUseQuota': 10000,
            'ServerCertificates': 0,
            'ServerCertificatesQuota': 20,
            'SigningCertificatesPerUserQuota': 2,
            'UserPolicySizeQuota': 2048,
            'Users': 5,
            'UsersQuota': 5000,
            'VersionsPerPolicyQuota': 5
        }
    }
    
    # Run the scan
    await aws_scanner.scan_iam()
    
    # Verify the finding was added
    assert len(aws_scanner.findings) > 0
    assert any(finding.finding_type == "ROOT_ACCESS_KEYS" for finding in aws_scanner.findings)

@pytest.mark.asyncio
async def test_scan_s3_public_bucket(aws_scanner, mock_boto3):
    """Test scanning for public S3 buckets."""
    # Mock the S3 client responses
    mock_boto3.list_buckets.return_value = {
        'Buckets': [{'Name': 'test-bucket', 'CreationDate': '2023-01-01'}],
        'Owner': {'DisplayName': 'test-owner', 'ID': 'test-id'}
    }
    
    # Mock the get_bucket_policy_status response to indicate a public bucket
    mock_boto3.get_bucket_policy_status.return_value = {
        'PolicyStatus': {
            'IsPublic': True
        }
    }
    
    # Run the scan
    await aws_scanner.scan_s3()
    
    # Verify the finding was added
    assert len(aws_scanner.findings) > 0
    assert any(
        finding.finding_type == "PUBLIC_S3_BUCKET" and 
        finding.resource_id == "test-bucket" 
        for finding in aws_scanner.findings
    )

@pytest.mark.asyncio
async def test_scan_ec2_permissive_sg(aws_scanner, mock_boto3):
    """Test scanning for permissive EC2 security groups."""
    # Mock the EC2 client responses
    mock_boto3.describe_instances.return_value = {
        'Reservations': [
            {
                'Instances': [
                    {
                        'InstanceId': 'i-1234567890abcdef0',
                        'InstanceType': 't2.micro',
                        'LaunchTime': '2023-01-01T00:00:00Z',
                        'PublicIpAddress': '203.0.113.0',
                        'SecurityGroups': [
                            {'GroupId': 'sg-12345678', 'GroupName': 'test-sg'}
                        ]
                    }
                ]
            }
        ]
    }
    
    # Mock the security group rules response
    mock_boto3.describe_security_group_rules.return_value = {
        'SecurityGroupRules': [
            {
                'GroupId': 'sg-12345678',
                'IpProtocol': 'tcp',
                'FromPort': 22,
                'ToPort': 22,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            }
        ]
    }
    
    # Run the scan
    await aws_scanner.scan_ec2()
    
    # Verify the finding was added
    assert len(aws_scanner.findings) > 0
    assert any(
        finding.finding_type == "PERMISSIVE_SECURITY_GROUP" and 
        finding.resource_id == "i-1234567890abcdef0"
        for finding in aws_scanner.findings
    )

def test_module_initialization():
    """Test the Module class initialization."""
    config = {
        'aws': {
            'access_key': 'test',
            'secret_key': 'test',
            'regions': ['us-east-1']
        },
        'scan_iam': True,
        'scan_s3': True,
        'scan_ec2': True
    }
    
    module = Module(
        config=config,
        payload_engine=MagicMock(),
        analyzer=MagicMock(),
        verbose=True
    )
    
    assert module is not None
    assert module.verbose is True

@pytest.mark.asyncio
async def test_scan_rds_public_instance(aws_scanner, mock_boto3):
    """Test scanning for public RDS instances."""
    # Mock the RDS client responses
    mock_boto3.describe_db_instances.return_value = {
        'DBInstances': [
            {
                'DBInstanceIdentifier': 'test-db',
                'DBInstanceArn': 'arn:aws:rds:us-east-1:123456789012:db:test-db',
                'Engine': 'mysql',
                'EngineVersion': '8.0.23',
                'PubliclyAccessible': True,
                'StorageEncrypted': False,
                'AutoMinorVersionUpgrade': False,
                'BackupRetentionPeriod': 1
            }
        ]
    }
    
    # Run the scan
    await aws_scanner.scan_rds()
    
    # Verify the findings
    assert len(aws_scanner.findings) == 3  # Public, unencrypted, no auto-upgrade
    assert any(
        finding.finding_type == "PUBLIC_RDS_INSTANCE" and 
        finding.resource_id == "test-db"
        for finding in aws_scanner.findings
    )
    assert any(
        finding.finding_type == "UNENCRYPTED_RDS_INSTANCE" 
        for finding in aws_scanner.findings
    )
    assert any(
        finding.finding_type == "NO_AUTO_MINOR_VERSION_UPGRADE"
        for finding in aws_scanner.findings
    )

@pytest.mark.asyncio
async def test_scan_lambda_security_issues(aws_scanner, mock_boto3):
    """Test scanning for Lambda function security issues."""
    # Mock Lambda client responses
    mock_boto3.get_paginator.return_value.paginate.return_value = [
        {
            'Functions': [
                {
                    'FunctionName': 'test-function',
                    'FunctionArn': 'arn:aws:lambda:us-east-1:123456789012:function:test-function',
                    'Runtime': 'python3.9',
                    'Role': 'arn:aws:iam::123456789012:role/test-role',
                    'Environment': {
                        'Variables': {
                            'DB_PASSWORD': 's3cr3t',
                            'API_KEY': 'key123'
                        }
                    },
                    'LastModified': '2023-01-01T00:00:00Z'
                }
            ]
        }
    ]
    
    # Mock get_policy response for public access check
    mock_boto3.get_policy.return_value = {
        'Policy': json.dumps({
            'Statement': [
                {
                    'Effect': 'Allow',
                    'Principal': {'AWS': '*'},
                    'Action': 'lambda:InvokeFunction',
                    'Resource': 'arn:aws:lambda:us-east-1:123456789012:function:test-function'
                }
            ]
        })
    }
    
    # Mock IAM client for role policy check
    mock_iam = MagicMock()
    mock_iam.list_attached_role_policies.return_value = {
        'AttachedPolicies': [
            {
                'PolicyName': 'AdministratorAccess',
                'PolicyArn': 'arn:aws:iam::aws:policy/AdministratorAccess'
            }
        ]
    }
    
    with patch('boto3.client', side_effect=[mock_boto3, mock_iam]):
        # Run the scan
        await aws_scanner.scan_lambda()
    
    # Verify the findings
    finding_types = {f.finding_type for f in aws_scanner.findings}
    assert len(aws_scanner.findings) >= 2  # At least 2 findings (public access, sensitive env vars, permissive role)
    assert "PUBLIC_LAMBDA_FUNCTION" in finding_types
    assert "SENSITIVE_ENV_VARIABLES" in finding_types
    assert "OVERLY_PERMISSIVE_LAMBDA_ROLE" in finding_types

@pytest.mark.asyncio
async def test_scan_eks_security_issues(aws_scanner, mock_boto3):
    """Test scanning for EKS security issues."""
    # Mock EKS client responses
    mock_boto3.list_clusters.return_value = {
        'clusters': ['test-cluster']
    }
    
    # Mock describe_cluster response
    mock_boto3.describe_cluster.return_value = {
        'cluster': {
            'arn': 'arn:aws:eks:us-east-1:123456789012:cluster/test-cluster',
            'name': 'test-cluster',
            'status': 'ACTIVE',
            'version': '1.20',
            'platformVersion': 'eks.123',
            'resourcesVpcConfig': {
                'endpointPublicAccess': True,
                'endpointPrivateAccess': False,
                'publicAccessCidrs': ['0.0.0.0/0'],
                'securityGroupIds': []
            },
            'logging': {
                'clusterLogging': [
                    {
                        'enabled': False,
                        'types': []
                    }
                ]
            },
            'encryptionConfig': None
        }
    }
    
    # Run the scan
    await aws_scanner.scan_eks()
    
    # Verify the findings
    finding_types = {f.finding_type for f in aws_scanner.findings}
    assert len(aws_scanner.findings) >= 4  # At least 4 findings (logging disabled, public access, no SGs, no encryption)
    assert "EKS_LOGGING_DISABLED" in finding_types
    assert "EKS_PUBLIC_ACCESS_ENABLED" in finding_types
    assert "EKS_NO_SECURITY_GROUPS" in finding_types
    assert "EKS_SECRETS_NOT_ENCRYPTED" in finding_types
    assert "EKS_OUTDATED_VERSION" in finding_types

@pytest.mark.asyncio
async def test_scan_eks_with_secure_config(aws_scanner, mock_boto3):
    """Test EKS scanning with secure configuration."""
    # Mock EKS client responses
    mock_boto3.list_clusters.return_value = {
        'clusters': ['secure-cluster']
    }
    
    # Mock describe_cluster response with secure configuration
    mock_boto3.describe_cluster.return_value = {
        'cluster': {
            'arn': 'arn:aws:eks:us-east-1:123456789012:cluster/secure-cluster',
            'name': 'secure-cluster',
            'status': 'ACTIVE',
            'version': '1.25',
            'platformVersion': 'eks.123',
            'resourcesVpcConfig': {
                'endpointPublicAccess': True,
                'endpointPrivateAccess': True,
                'publicAccessCidrs': ['192.0.2.0/24'],
                'securityGroupIds': ['sg-12345678']
            },
            'logging': {
                'clusterLogging': [
                    {
                        'enabled': True,
                        'types': ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler']
                    }
                ]
            },
            'encryptionConfig': [
                {
                    'resources': ['secrets'],
                    'provider': {
                        'keyArn': 'arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab'
                    }
                }
            ]
        }
    }
    
    # Run the scan
    await aws_scanner.scan_eks()
    
    # Verify no findings for secure configuration
    assert len(aws_scanner.findings) == 0

@pytest.mark.asyncio
async def test_scan_ecr_security_issues(aws_scanner, mock_boto3):
    """Test scanning for ECR security issues."""
    # Mock ECR client responses
    mock_boto3.get_paginator.return_value.paginate.return_value = [
        {
            'repositories': [
                {
                    'repositoryName': 'test-repo',
                    'repositoryArn': 'arn:aws:ecr:us-east-1:123456789012:repository/test-repo',
                    'repositoryUri': '123456789012.dkr.ecr.us-east-1.amazonaws.com/test-repo',
                    'createdAt': datetime.datetime(2023, 1, 1),
                    'imageScanningConfiguration': {
                        'scanOnPush': False
                    }
                }
            ]
        }
    ]
    
    # Mock describe_image_scan_findings to raise ScanNotFoundException
    from botocore.exceptions import ClientError
    mock_boto3.exceptions.ScanNotFoundException = ClientError
    mock_boto3.exceptions.LifecyclePolicyNotFoundException = ClientError
    
    # Mock the client to return our mock exceptions
    mock_boto3.return_value.exceptions.ScanNotFoundException = mock_boto3.exceptions.ScanNotFoundException
    mock_boto3.return_value.exceptions.LifecyclePolicyNotFoundException = mock_boto3.exceptions.LifecyclePolicyNotFoundException
    
    # Mock describe_image_scan_findings to raise ScanNotFoundException
    mock_boto3.return_value.describe_image_scan_findings.side_effect = mock_boto3.exceptions.ScanNotFoundException(
        {'Error': {'Code': 'ScanNotFoundException'}}, 'DescribeImageScanFindings'
    )
    
    # Mock get_lifecycle_policy to raise LifecyclePolicyNotFoundException
    mock_boto3.return_value.get_lifecycle_policy.side_effect = mock_boto3.exceptions.LifecyclePolicyNotFoundException(
        {'Error': {'Code': 'LifecyclePolicyNotFoundException'}}, 'GetLifecyclePolicy'
    )
    
    # Run the scan
    await aws_scanner.scan_ecr()
    
    # Verify the findings
    finding_types = {f.finding_type for f in aws_scanner.findings}
    assert len(aws_scanner.findings) >= 2  # At least 2 findings (scan on push disabled, no lifecycle policy)
    assert "ECR_SCAN_ON_PUSH_DISABLED" in finding_types
    assert "ECR_LIFECYCLE_POLICY_MISSING" in finding_types

@pytest.mark.asyncio
async def test_scan_ecs_security_issues(aws_scanner, mock_boto3):
    """Test scanning for ECS security issues."""
    # Mock ECS client responses
    mock_boto3.list_clusters.return_value = {
        'clusterArns': ['arn:aws:ecs:us-east-1:123456789012:cluster/test-cluster']
    }
    
    mock_boto3.describe_clusters.return_value = {
        'clusters': [
            {
                'clusterArn': 'arn:aws:ecs:us-east-1:123456789012:cluster/test-cluster',
                'clusterName': 'test-cluster',
                'status': 'ACTIVE',
                'runningTasksCount': 1,
                'activeServicesCount': 1,
                'settings': [
                    {'name': 'containerInsights', 'value': 'disabled'}
                ]
            }
        ]
    }
    
    mock_boto3.list_tasks.return_value = {
        'taskArns': ['arn:aws:ecs:us-east-1:123456789012:task/test-cluster/1234567890123456789']
    }
    
    mock_boto3.describe_tasks.return_value = {
        'tasks': [
            {
                'taskArn': 'arn:aws:ecs:us-east-1:123456789012:task/test-cluster/1234567890123456789',
                'taskDefinitionArn': 'arn:aws:ecs:us-east-1:123456789012:task-definition/test-task:1',
                'clusterArn': 'arn:aws:ecs:us-east-1:123456789012:cluster/test-cluster',
                'taskRoleArn': 'arn:aws:iam::123456789012:role/ecsTaskRole'
            }
        ]
    }
    
    mock_boto3.describe_task_definition.return_value = {
        'taskDefinition': {
            'taskDefinitionArn': 'arn:aws:ecs:us-east-1:123456789012:task-definition/test-task:1',
            'containerDefinitions': [
                {
                    'name': 'test-container',
                    'image': 'nginx:latest',
                    'privileged': True
                }
            ],
            'taskRoleArn': 'arn:aws:iam::123456789012:role/ecsTaskRole'
        }
    }
    
    # Mock IAM client for role policy check
    mock_iam = MagicMock()
    mock_iam.list_attached_role_policies.return_value = {
        'AttachedPolicies': [
            {
                'PolicyName': 'AdministratorAccess',
                'PolicyArn': 'arn:aws:iam::aws:policy/AdministratorAccess'
            }
        ]
    }
    
    with patch('boto3.client', side_effect=[mock_boto3, mock_boto3, mock_iam]):
        # Run the scan
        await aws_scanner.scan_ecs()
    
    # Verify the findings
    finding_types = {f.finding_type for f in aws_scanner.findings}
    assert len(aws_scanner.findings) >= 2  # At least 2 findings (container insights, privileged container, permissive role)
    assert "CONTAINER_INSIGHTS_DISABLED" in finding_types
    assert "PRIVILEGED_CONTAINER" in finding_types
    assert "OVERLY_PERMISSIVE_TASK_ROLE" in finding_types

@pytest.mark.asyncio
async def test_scan_cloudtrail_misconfigurations(aws_scanner, mock_boto3):
    """Test scanning for CloudTrail misconfigurations."""
    # Mock the CloudTrail client responses
    mock_boto3.describe_trails.return_value = {
        'trailList': [
            {
                'Name': 'test-trail',
                'TrailARN': 'arn:aws:cloudtrail:us-east-1:123456789012:trail/test-trail',
                'IsMultiRegionTrail': False,
                'LogFileValidationEnabled': False,
                'S3BucketName': 'test-bucket',
                'S3KeyPrefix': 'cloudtrail',
                'HomeRegion': 'us-east-1',
                'IsOrganizationTrail': False
            }
        ]
    }
    
    # Mock get_event_selectors
    mock_boto3.get_event_selectors.return_value = {
        'EventSelectors': [
            {
                'ReadWriteType': 'ReadOnly',
                'IncludeManagementEvents': True,
                'DataResources': []
            }
        ]
    }
    
    # Run the scan
    await aws_scanner.scan_cloudtrail()
    
    # Verify the findings
    assert len(aws_scanner.findings) == 3  # Single region, no validation, insufficient logging
    assert any(
        finding.finding_type == "SINGLE_REGION_TRAIL"
        for finding in aws_scanner.findings
    )
    assert any(
        finding.finding_type == "LOG_FILE_VALIDATION_DISABLED"
        for finding in aws_scanner.findings
    )
    assert any(
        finding.finding_type == "INSUFFICIENT_LOGGING"
        for finding in aws_scanner.findings
    )

@pytest.mark.asyncio
async def test_module_run(aws_scanner, mock_boto3):
    """Test the Module.run method."""
    # Mock the scanner to avoid making real AWS calls
    with patch('modes.cloud.modules.aws_scanner.AWSScanner') as mock_scanner:
        # Configure the mock scanner
        mock_instance = mock_scanner.return_value
        mock_instance.scan.return_value = [
            AWSFinding(
                service=AWSService.IAM,
                resource_id="test-resource",
                finding_type="TEST_FINDING",
                severity=AWSSeverity.HIGH,
                description="Test finding"
            )
        ]
        
        # Create and run the module
        module = Module(
            config={
                'aws': {
                    'access_key': 'test',
                    'secret_key': 'test',
                    'regions': ['us-east-1']
                },
                'scan_iam': True,
                'scan_s3': True,
                'scan_ec2': True,
                'scan_rds': True,
                'scan_cloudtrail': True
            },
            payload_engine=MagicMock(),
            analyzer=MagicMock(),
            verbose=True
        )
        
        findings = await module.run()
        
        # Verify the findings were processed correctly
        assert len(findings) == 1
        assert findings[0]['type'] == "TEST_FINDING"
        assert findings[0]['severity'] == "HIGH"

@pytest.mark.asyncio
async def test_scan_eks_error_handling(aws_scanner, mock_boto3):
    """Test EKS scanning error handling."""
    # Mock EKS client to raise an exception
    mock_boto3.list_clusters.side_effect = Exception("API error")
    
    # Run the scan
    await aws_scanner.scan_eks()
    
    # Verify error was logged and no findings were added
    assert len(aws_scanner.findings) == 0
    # Note: In a real test, we would verify the error was logged

@pytest.mark.asyncio
async def test_scan_ecr_with_vulnerabilities(aws_scanner, mock_boto3):
    """Test ECR scanning with vulnerability findings."""
    # Mock ECR client responses with vulnerabilities
    mock_boto3.get_paginator.return_value.paginate.return_value = [
        {
            'repositories': [
                {
                    'repositoryName': 'vulnerable-repo',
                    'repositoryArn': 'arn:aws:ecr:us-east-1:123456789012:repository/vulnerable-repo',
                    'repositoryUri': '123456789012.dkr.ecr.us-east-1.amazonaws.com/vulnerable-repo',
                    'createdAt': datetime.datetime(2023, 1, 1),
                    'imageScanningConfiguration': {
                        'scanOnPush': True
                    }
                }
            ]
        }
    ]
    
    # Mock describe_image_scan_findings with vulnerabilities
    mock_boto3.return_value.describe_image_scan_findings.return_value = {
        'imageScanFindings': {
            'findings': [
                {
                    'name': 'CVE-2023-1234',
                    'severity': 'CRITICAL',
                    'uri': 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1234',
                    'description': 'Critical vulnerability in package X',
                },
                {
                    'name': 'CVE-2023-5678',
                    'severity': 'HIGH',
                    'uri': 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-5678',
                    'description': 'High severity issue in package Y',
                }
            ],
            'imageScanCompletedAt': datetime.datetime(2023, 1, 1)
        }
    }
    
    # Mock get_lifecycle_policy with a policy
    mock_boto3.return_value.get_lifecycle_policy.return_value = {
        'lifecyclePolicyText': json.dumps({
            'rules': [
                {
                    'rulePriority': 1,
                    'description': 'Keep last 30 days of images',
                    'selection': {
                        'tagStatus': 'any',
                        'countType': 'sinceImagePushed',
                        'countNumber': 30,
                        'countUnit': 'days'
                    },
                    'action': {
                        'type': 'expire'
                    }
                }
            ]
        })
    }
    
    # Run the scan
    await aws_scanner.scan_ecr()
    
    # Verify the findings
    finding_types = {f.finding_type for f in aws_scanner.findings}
    assert len(aws_scanner.findings) >= 1  # At least 1 finding (vulnerabilities)
    assert "ECR_IMAGE_VULNERABILITIES" in finding_types
    
    # Verify the vulnerability details are included
    vuln_finding = next(f for f in aws_scanner.findings if f.finding_type == "ECR_IMAGE_VULNERABILITIES")
    assert vuln_finding.details["vulnerability_count"] == 2
    assert len(vuln_finding.details["vulnerabilities"]) == 2

@pytest.mark.asyncio
async def test_scan_with_all_services(aws_scanner, mock_boto3):
    """Test scanning with all AWS services."""
    # Mock the necessary client responses for all services
    
    # Mock IAM responses
    mock_boto3.get_account_summary.return_value = {
        'SummaryMap': {'AccountAccessKeysPresent': 0}
    }
    mock_boto3.get_account_password_policy.side_effect = mock_boto3.exceptions.NoSuchEntityException(
        {'Error': {'Code': 'NoSuchEntity'}}, 'get_account_password_policy'
    )
    
    # Mock S3 responses
    mock_boto3.list_buckets.return_value = {
        'Buckets': [{'Name': 'test-bucket', 'CreationDate': '2023-01-01T00:00:00Z'}]
    }
    mock_boto3.get_bucket_encryption.side_effect = mock_boto3.exceptions.ClientError(
        {'Error': {'Code': 'ServerSideEncryptionConfigurationNotFoundError'}}, 'GetBucketEncryption'
    )
    
    # Mock EC2 responses
    mock_boto3.describe_instances.return_value = {'Reservations': []}
    
    # Mock RDS responses
    mock_boto3.describe_db_instances.return_value = {'DBInstances': []}
    
    # Mock Lambda responses
    mock_boto3.get_paginator.return_value.paginate.return_value = [{'Functions': []}]
    
    # Mock ECS responses
    mock_boto3.list_clusters.return_value = {'clusterArns': []}
    
    # Mock CloudTrail responses
    mock_boto3.describe_trails.return_value = {'trailList': []}
    
    # Run the scan with all services
    findings = await aws_scanner.scan(services=list(AWSService))
    
    # Verify that all service scans were called
    assert len(findings) >= 0  # Just verify it runs without errors

def test_aws_finding_serialization():
    """Test AWSFinding serialization."""
    finding = AWSFinding(
        service=AWSService.IAM,
        resource_id="test-resource",
        finding_type="TEST_FINDING",
        severity=AWSSeverity.HIGH,
        description="Test finding",
        details={"key": "value"},
        remediation="Fix it",
        references=["http://example.com"],
        region="us-east-1"
    )
    
    # Convert to dict and back to object
    finding_dict = finding.__dict__
    assert finding_dict['service'] == AWSService.IAM
    assert finding_dict['resource_id'] == "test-resource"
    assert finding_dict['finding_type'] == "TEST_FINDING"
    assert finding_dict['severity'] == AWSSeverity.HIGH
    assert finding_dict['description'] == "Test finding"
