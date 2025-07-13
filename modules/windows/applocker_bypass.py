"""
AppLocker Bypass Detector
Scans for known AppLocker bypass paths and techniques.
"""
import os
import sys

KNOWN_LOCATIONS = [
    r'C:\Windows\Tasks',
    r'C:\Windows\Temp',
    r'C:\Windows\tracing',
    r'C:\Windows\System32',
    r'C:\Users\Public',
    r'C:\ProgramData',
]

BYPASS_TECHNIQUES = [
    'msbuild.exe',
    'regsvr32.exe',
    'installutil.exe',
    'rundll32.exe',
    'wscript.exe',
    'cscript.exe',
    'powershell.exe',
    'wmic.exe',
]

def check_locations():
    findings = []
    for loc in KNOWN_LOCATIONS:
        if os.path.exists(loc):
            findings.append(f"Allowed location: {loc}")
    return findings

def check_bypass_techniques():
    findings = []
    for exe in BYPASS_TECHNIQUES:
        for path in os.environ["PATH"].split(os.pathsep):
            exe_path = os.path.join(path, exe)
            if os.path.exists(exe_path):
                findings.append(f"Bypass binary present: {exe_path}")
    return findings

def main():
    import argparse
    parser = argparse.ArgumentParser(description="AppLocker Bypass Detector")
    args = parser.parse_args()
    findings = check_locations() + check_bypass_techniques()
    if findings:
        print("[!] AppLocker Bypass Findings:")
        for f in findings:
            print(f" - {f}")
    else:
        print("[+] No AppLocker bypasses detected.")

if __name__ == "__main__":
    main() 