"""
Template Injection Scanner
Usage: Enable via --vulns template
"""
import requests
import re

template_payloads = [
    "{{7*7}}",
    "<%= 7*7 %>",
    "{{=7*7}}"
]

patterns = [
    re.compile(r"49"),  # 7*7 = 49
]

def scan_template_injection(url, params):
    findings = []
    for payload in template_payloads:
        for param in params:
            test_params = params.copy()
            test_params[param] = payload
            resp = requests.get(url, params=test_params, timeout=10)
            for pat in patterns:
                if pat.search(resp.text):
                    findings.append(f"Parameter '{param}' reflected template eval: {payload}")
    return findings

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Template Injection Scanner")
    parser.add_argument('--url', required=True, help='Target URL')
    parser.add_argument('--params', nargs='+', help='Parameters to test (key1=value1 key2=value2)')
    parser.add_argument('--vulns', nargs='+', help='Vulnerability modules to run')
    args = parser.parse_args()
    if 'template' in (args.vulns or []):
        params = dict(p.split('=') for p in (args.params or []))
        findings = scan_template_injection(args.url, params)
        if findings:
            print("[!] Template Injection Findings:")
            for f in findings:
                print(f" - {f}")
        else:
            print("[+] No template injection detected.")

if __name__ == "__main__":
    main() 