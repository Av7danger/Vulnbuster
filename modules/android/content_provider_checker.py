"""
Content Provider Vulnerability Checker
Usage: Enable via --android-check content-provider
"""
import xml.etree.ElementTree as ET
import sys

def check_content_providers(manifest_path):
    findings = []
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    ns = {'android': 'http://schemas.android.com/apk/res/android'}
    for provider in root.findall('.//provider'):
        exported = provider.get('{http://schemas.android.com/apk/res/android}exported')
        name = provider.get('{http://schemas.android.com/apk/res/android}name')
        permission = provider.get('{http://schemas.android.com/apk/res/android}permission')
        if exported == 'true' and not permission:
            findings.append(f"Exported content provider '{name}' without permission protection.")
    return findings

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Content Provider Vulnerability Checker")
    parser.add_argument('--manifest', required=True, help='Path to AndroidManifest.xml')
    parser.add_argument('--android-check', nargs='+', help='Android checks to run')
    args = parser.parse_args()
    if 'content-provider' in (args.android_check or []):
        findings = check_content_providers(args.manifest)
        if findings:
            print("[!] Content Provider Vulnerabilities:")
            for f in findings:
                print(f" - {f}")
        else:
            print("[+] No vulnerable content providers found.")

if __name__ == "__main__":
    main() 