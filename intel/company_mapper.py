"""
Company Asset Mapping
Maps company assets using SecurityTrails, GitHub, ASN lookup.
Usage: --company-map NAME
"""
import requests
import sys

def securitytrails_lookup(company, api_key=None):
    # Stub: Replace with real SecurityTrails API call
    if not api_key:
        return {'error': 'No API key provided'}
    resp = requests.get(f'https://api.securitytrails.com/v1/domain/list?search={company}',
                       headers={'APIKEY': api_key})
    if resp.status_code == 200:
        return resp.json()
    return {'error': resp.text}

def github_lookup(company):
    # Stub: Search GitHub orgs
    resp = requests.get(f'https://api.github.com/orgs/{company}/repos')
    if resp.status_code == 200:
        return [repo['html_url'] for repo in resp.json()]
    return []

def asn_lookup(company):
    # Stub: Use a public ASN lookup API
    return {'asn': 'AS12345', 'org': company, 'ips': ['1.2.3.4', '5.6.7.8']}

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Company Asset Mapper")
    parser.add_argument('--company-map', metavar='NAME', help='Company name to map')
    parser.add_argument('--securitytrails-key', help='SecurityTrails API key')
    args = parser.parse_args()
    if args.company_map:
        print(f"[+] Mapping assets for {args.company_map}")
        st = securitytrails_lookup(args.company_map, args.securitytrails_key)
        gh = github_lookup(args.company_map)
        asn = asn_lookup(args.company_map)
        print("[SecurityTrails]", st)
        print("[GitHub]", gh)
        print("[ASN]", asn)

if __name__ == "__main__":
    main() 