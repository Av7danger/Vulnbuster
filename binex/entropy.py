"""
Binary Entropy Analyzer
Uses Shannon entropy to detect packing/obfuscation in binaries.
"""
import sys
import math
import os

def shannon_entropy(data):
    if not data:
        return 0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0
    for c in freq.values():
        p = c / len(data)
        entropy -= p * math.log2(p)
    return entropy

def analyze_sections(binary_path):
    try:
        from elftools.elf.elffile import ELFFile
        with open(binary_path, 'rb') as f:
            elf = ELFFile(f)
            results = []
            for section in elf.iter_sections():
                data = section.data()
                ent = shannon_entropy(data)
                results.append({'section': section.name, 'entropy': ent})
            return results
    except ImportError:
        print("pyelftools not installed. Please install with 'pip install pyelftools'.")
        return []
    except Exception as e:
        print(f"Error: {e}")
        return []

def highlight_abnormal(results, threshold=7.0):
    print("[Entropy Analysis]")
    for r in results:
        flag = "[!]" if r['entropy'] > threshold else "[ ]"
        print(f"{flag} Section {r['section']}: Entropy={r['entropy']:.2f}")
    print("Sections flagged [!] may be packed or obfuscated.")

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Binary Entropy Analyzer")
    parser.add_argument('--bin', required=True, help='Path to binary')
    args = parser.parse_args()
    results = analyze_sections(args.bin)
    highlight_abnormal(results)

if __name__ == "__main__":
    main() 