"""
IAM Escalation Analyzer
Lists IAM permissions, matches against known escalation paths, feeds to ai_chain_reasoner.py
"""
import json
import os

def get_aws_permissions():
    try:
        import boto3
        client = boto3.client('iam')
        user = client.get_user()['User']['UserName']
        policies = client.list_attached_user_policies(UserName=user)
        return {'user': user, 'policies': policies}
    except Exception as e:
        return {'error': str(e)}

def get_gcp_permissions():
    try:
        from google.oauth2 import service_account
        from googleapiclient.discovery import build
        credentials = service_account.Credentials.from_service_account_file(os.environ.get('GOOGLE_APPLICATION_CREDENTIALS'))
        service = build('cloudresourcemanager', 'v1', credentials=credentials)
        projects = service.projects().list().execute()
        return {'projects': projects}
    except Exception as e:
        return {'error': str(e)}

ESCALATION_PATHS = [
    'iam:PassRole',
    'iam:CreatePolicy',
    'iam:AttachUserPolicy',
    'iam:PutUserPolicy',
    'iam:UpdateAssumeRolePolicy',
    'iam:CreateAccessKey',
    'iam:AddUserToGroup',
    'iam:CreateLoginProfile',
    'iam:UpdateLoginProfile',
]

def analyze_escalation(permissions):
    findings = []
    for path in ESCALATION_PATHS:
        if path in json.dumps(permissions):
            findings.append(f"Potential escalation via {path}")
    return findings

def feed_to_ai_chain(findings):
    # Stub: In production, this would call ai_chain_reasoner.py
    print("[AI Chain Reasoner] Recommendations:")
    for f in findings:
        print(f" - {f}")

def main():
    import argparse
    parser = argparse.ArgumentParser(description="IAM Escalation Analyzer")
    parser.add_argument('--cloud', choices=['aws', 'gcp'], required=True, help='Cloud provider')
    args = parser.parse_args()
    if args.cloud == 'aws':
        perms = get_aws_permissions()
    else:
        perms = get_gcp_permissions()
    findings = analyze_escalation(perms)
    print(json.dumps({'permissions': perms, 'findings': findings}, indent=2))
    feed_to_ai_chain(findings)

if __name__ == "__main__":
    main() 