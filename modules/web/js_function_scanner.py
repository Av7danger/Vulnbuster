"""
JavaScript Function Scanner
Parses inline JavaScript, extracts functions, looks for keys, auth bypass, endpoints.
"""
import re
import requests

def extract_js_functions(js_code):
    # Simple regex for function definitions
    func_pattern = re.compile(r'function\s+(\w+)\s*\(|(\w+)\s*=\s*function\s*\(')
    return set(m for m in func_pattern.findall(js_code) for m in m if m)

def find_keys(js_code):
    # Look for key-like assignments
    return re.findall(r'([A-Za-z0-9_]+_key|key_[A-Za-z0-9_]+)\s*=\s*["\"][^"\"]+["\"]', js_code)

def find_auth_bypass(js_code):
    # Look for suspicious logic
    return re.findall(r'if\s*\(.*(admin|bypass|isAuthenticated|isAdmin).*\)', js_code)

def find_endpoints(js_code):
    # Look for URLs/endpoints
    return re.findall(r'https?://[\w\./\-]+', js_code)

def scan_js(url):
    resp = requests.get(url)
    js_blocks = re.findall(r'<script[^>]*>([\s\S]*?)</script>', resp.text)
    findings = {'functions': set(), 'keys': [], 'auth_bypass': [], 'endpoints': []}
    for js in js_blocks:
        findings['functions'].update(extract_js_functions(js))
        findings['keys'].extend(find_keys(js))
        findings['auth_bypass'].extend(find_auth_bypass(js))
        findings['endpoints'].extend(find_endpoints(js))
    findings['functions'] = list(findings['functions'])
    return findings

def main():
    import argparse
    parser = argparse.ArgumentParser(description="JavaScript Function Scanner")
    parser.add_argument('--url', required=True, help='Target URL')
    args = parser.parse_args()
    findings = scan_js(args.url)
    print("[JS Function Scan Results]")
    for k, v in findings.items():
        print(f"{k}: {v}")

if __name__ == "__main__":
    main() 