"""
CORS Misconfig Scanner
Tests common origins with credentials, wildcard matching, preflight poisoning.
"""
import requests

def test_cors(url):
    origins = [
        'https://evil.com',
        'null',
        'http://localhost',
        'https://subdomain.' + url.split('//')[-1].split('/')[0],
        '*',
    ]
    findings = []
    for origin in origins:
        headers = {
            'Origin': origin,
            'Access-Control-Request-Method': 'GET',
            'Access-Control-Request-Headers': 'X-Test-Header',
        }
        resp = requests.options(url, headers=headers)
        acao = resp.headers.get('Access-Control-Allow-Origin', '')
        acac = resp.headers.get('Access-Control-Allow-Credentials', '')
        if acao == '*' or acao == origin:
            findings.append(f'Origin {origin} allowed: {acao}')
        if acac.lower() == 'true':
            findings.append(f'Credentials allowed for origin {origin}')
        if 'Access-Control-Allow-Headers' in resp.headers and 'X-Test-Header' in resp.headers['Access-Control-Allow-Headers']:
            findings.append(f'Preflight header reflected for origin {origin}')
    return findings

def main():
    import argparse
    parser = argparse.ArgumentParser(description="CORS Misconfig Scanner")
    parser.add_argument('--url', required=True, help='Target URL')
    args = parser.parse_args()
    findings = test_cors(args.url)
    print("[CORS Scan Results]")
    for f in findings:
        print(f" - {f}")

if __name__ == "__main__":
    main() 