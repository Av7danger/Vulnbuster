"""
Custom GPT Interface Builder
Usage: --custom-prompt PATH
"""
import sys
import os
from jinja2 import Template

def run_custom_prompt(template_path, context):
    with open(template_path) as f:
        template = Template(f.read())
    prompt = template.render(**context)
    print("[Custom Prompt]")
    print(prompt)

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Custom GPT Interface Runner")
    parser.add_argument('--custom-prompt', help='Path to .j2 prompt template')
    parser.add_argument('--context', nargs='*', help='Context key=value pairs')
    args = parser.parse_args()
    if args.custom_prompt:
        context = dict(pair.split('=') for pair in (args.context or []))
        run_custom_prompt(args.custom_prompt, context)

if __name__ == "__main__":
    main() 