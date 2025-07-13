"""
Deep DEX Opcode Analyzer
Extracts classes.dex, decodes opcodes, detects reflection/dynamic loading/suspicious APIs.
Outputs to reports/android_opcode.json
"""
import os
import zipfile
import json
import re
from typing import List

SUSPICIOUS_APIS = [
    'java/lang/reflect',
    'dalvik/system/DexClassLoader',
    'dalvik/system/PathClassLoader',
    'loadClass',
    'getMethod',
    'invoke',
    'exec',
    'Runtime.getRuntime()'
]

def extract_dex_files(apk_path: str, out_dir: str) -> List[str]:
    dex_files = []
    with zipfile.ZipFile(apk_path, 'r') as z:
        for f in z.namelist():
            if f.endswith('.dex'):
                out_path = os.path.join(out_dir, os.path.basename(f))
                with open(out_path, 'wb') as dex_out:
                    dex_out.write(z.read(f))
                dex_files.append(out_path)
    return dex_files

def analyze_dex_opcodes(dex_file: str) -> List[str]:
    findings = []
    try:
        from androguard.core.bytecodes import dvm
        from androguard.core.analysis import analysis
        d = dvm.DalvikVMFormat(open(dex_file, 'rb').read())
        dx = analysis.Analysis(d)
        for method in d.get_methods():
            code = method.get_code()
            if code:
                bytecode = code.get_bc()
                for ins in bytecode.get_instructions():
                    op = ins.get_name()
                    output = ins.get_output()
                    for api in SUSPICIOUS_APIS:
                        if api in output:
                            findings.append(f"{dex_file}: {method.get_name()} uses {api}")
    except ImportError:
        findings.append("Androguard not installed. Please install with 'pip install androguard'.")
    except Exception as e:
        findings.append(f"Error analyzing {dex_file}: {e}")
    return findings

def main():
    import argparse
    parser = argparse.ArgumentParser(description="DEX Opcode Analyzer")
    parser.add_argument('--apk', required=True, help='Path to APK file')
    args = parser.parse_args()
    os.makedirs('reports', exist_ok=True)
    os.makedirs('tmp', exist_ok=True)
    dex_files = extract_dex_files(args.apk, 'tmp')
    all_findings = []
    for dex in dex_files:
        all_findings.extend(analyze_dex_opcodes(dex))
    with open('reports/android_opcode.json', 'w') as f:
        json.dump(all_findings, f, indent=2)
    print(f"[+] Analysis complete. Results in reports/android_opcode.json")

if __name__ == "__main__":
    main() 