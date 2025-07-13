"""
Cloud Function Scanner
Lists Lambda/GCP/Azure functions, analyzes code/config for secrets, wide permissions, SSRF risk.
"""
import json
import os

def list_aws_lambda():
    try:
        import boto3
        client = boto3.client('lambda')
        functions = client.list_functions()['Functions']
        return functions
    except Exception as e:
        return {'error': str(e)}

def list_gcp_functions():
    try:
        from google.oauth2 import service_account
        from googleapiclient.discovery import build
        credentials = service_account.Credentials.from_service_account_file(os.environ.get('GOOGLE_APPLICATION_CREDENTIALS'))
        service = build('cloudfunctions', 'v1', credentials=credentials)
        functions = service.projects().locations().functions().list(parent='projects/-/locations/-').execute()
        return functions
    except Exception as e:
        return {'error': str(e)}

def list_azure_functions():
    # Stub: Azure SDK integration would go here
    return {'note': 'Azure function listing not implemented'}

def analyze_function_config(functions):
    findings = []
    for f in functions if isinstance(functions, list) else []:
        # Check for environment variables with secrets
        env = f.get('Environment', {}).get('Variables', {})
        for k, v in env.items():
            if 'key' in k.lower() or 'secret' in k.lower() or 'token' in k.lower():
                findings.append(f"Function {f.get('FunctionName')} has possible secret in env var {k}")
        # Check for wide permissions (role/arn)
        role = f.get('Role', '')
        if 'admin' in role.lower() or 'root' in role.lower():
            findings.append(f"Function {f.get('FunctionName')} uses privileged role: {role}")
        # SSRF risk: check for http requests in code (stub)
        # In production, download and scan code for requests
    return findings

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Cloud Function Scanner")
    parser.add_argument('--cloud', choices=['aws', 'gcp', 'azure'], required=True, help='Cloud provider')
    args = parser.parse_args()
    if args.cloud == 'aws':
        functions = list_aws_lambda()
    elif args.cloud == 'gcp':
        functions = list_gcp_functions()
    else:
        functions = list_azure_functions()
    findings = analyze_function_config(functions)
    print(json.dumps({'functions': functions, 'findings': findings}, indent=2))

if __name__ == "__main__":
    main() 