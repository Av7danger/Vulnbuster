#!/usr/bin/env python3
"""
DOM Clobbering and Mutation-XSS Scanner
Usage: Enable via --vulns dom-xss
"""
import asyncio
from playwright.async_api import async_playwright
import sys

async def scan_dom_xss(url):
    findings = []
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        clobber_events = []
        
        async def on_dom_mutation(mutation):
            # Check for script injection or attribute clobbering
            if mutation['type'] == 'childList':
                for node in mutation['addedNodes']:
                    if node.nodeType == 1 and node.tagName.lower() == 'script':
                        clobber_events.append(f"Script tag injected: {node.outerHTML}")
            if mutation['type'] == 'attributes':
                if mutation['attributeName'] in ['src', 'onerror', 'onclick']:
                    clobber_events.append(f"Attribute {mutation['attributeName']} changed on {mutation['target'].outerHTML}")
        
        await page.expose_function("onDomMutation", on_dom_mutation)
        await page.add_init_script('''
            const observer = new MutationObserver(mutations => {
                for (const mutation of mutations) {
                    window.onDomMutation(mutation);
                }
            });
            observer.observe(document, { attributes: true, childList: true, subtree: true });
        ''')
        await page.goto(url)
        await asyncio.sleep(3)  # Wait for DOM events
        if clobber_events:
            findings.extend(clobber_events)
        await browser.close()
    return findings

def main():
    import argparse
    parser = argparse.ArgumentParser(description="DOM Clobbering/Mutation-XSS Scanner")
    parser.add_argument('--url', required=True, help='Target URL')
    parser.add_argument('--vulns', nargs='+', help='Vulnerability modules to run')
    args = parser.parse_args()
    if 'dom-xss' in (args.vulns or []):
        findings = asyncio.run(scan_dom_xss(args.url))
        if findings:
            print("[!] DOM Clobbering/Mutation-XSS Findings:")
            for f in findings:
                print(f" - {f}")
        else:
            print("[+] No DOM clobbering or Mutation-XSS detected.")

if __name__ == "__main__":
    main() 