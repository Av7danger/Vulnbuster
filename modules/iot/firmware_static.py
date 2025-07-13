"""
Firmware Static Analyzer
Uses binwalk to extract filesystem, scans for hardcoded creds, outdated libs, maps init scripts.
"""
import os
import re
import subprocess

def extract_filesystem(firmware_path, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    subprocess.run(["binwalk", "-e", firmware_path, "-C", out_dir], check=False)

def scan_for_creds(root_dir):
    findings = []
    for dirpath, _, filenames in os.walk(root_dir):
        for f in filenames:
            if f.endswith(('.conf', '.ini', '.txt', 'shadow', 'passwd')):
                with open(os.path.join(dirpath, f), errors='ignore') as file:
                    content = file.read()
                    if re.search(r'password\s*=\s*\w+', content, re.IGNORECASE):
                        findings.append(f"Hardcoded password in {os.path.join(dirpath, f)}")
    return findings

def scan_for_outdated_libs(root_dir):
    findings = []
    for dirpath, _, filenames in os.walk(root_dir):
        for f in filenames:
            if f.endswith(('.so', '.dll')):
                # Stub: In production, check version against CVE DB
                findings.append(f"Library found: {os.path.join(dirpath, f)} (version check stub)")
    return findings

def map_init_scripts(root_dir):
    scripts = []
    for dirpath, _, filenames in os.walk(root_dir):
        for f in filenames:
            if f.startswith('rc') or 'init' in f:
                scripts.append(os.path.join(dirpath, f))
    return scripts

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Firmware Static Analyzer")
    parser.add_argument('--firmware', required=True, help='Path to firmware image')
    parser.add_argument('--out', default='fw_extract', help='Extraction output directory')
    args = parser.parse_args()
    extract_filesystem(args.firmware, args.out)
    creds = scan_for_creds(args.out)
    libs = scan_for_outdated_libs(args.out)
    scripts = map_init_scripts(args.out)
    print("[Firmware Analysis Report]")
    for c in creds:
        print(f"[CRED] {c}")
    for l in libs:
        print(f"[LIB] {l}")
    for s in scripts:
        print(f"[INIT] {s}")

if __name__ == "__main__":
    main() 