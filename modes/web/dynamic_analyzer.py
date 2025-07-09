"""
DynamicAnalyzer for Web - Playwright-based dynamic analysis
Detects DOM XSS, client-side redirects, JS-injected forms, and more
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional

try:
    from playwright.async_api import async_playwright
except ImportError:
    async_playwright = None

class DynamicAnalyzer:
    def __init__(self, headless: bool = True, timeout: int = 20):
        self.headless = headless
        self.timeout = timeout

    async def scan_url(self, url: str) -> List[Dict[str, Any]]:
        """Visit a URL, monitor DOM/network/console, and detect client-side issues."""
        findings = []
        if not async_playwright:
            logging.warning("Playwright is not installed. Dynamic analysis unavailable.")
            return findings
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=self.headless)
                context = await browser.new_context()
                page = await context.new_page()
                console_logs = []
                network_requests = []
                dom_mutations = []
                # Monitor console
                page.on("console", lambda msg: console_logs.append(msg.text))
                # Monitor network
                page.on("request", lambda req: network_requests.append(req.url))
                # Monitor DOM mutations (basic)
                await page.expose_function("__dom_mutation__", lambda data: dom_mutations.append(data))
                await page.add_init_script("""
                    new MutationObserver(function(mutations) {
                        window.__dom_mutation__(JSON.stringify(mutations));
                    }).observe(document, {subtree: true, childList: true, attributes: true});
                """)
                await page.goto(url, timeout=self.timeout * 1000)
                await page.wait_for_timeout(2000)
                # Check for DOM XSS (basic)
                if any('alert(' in log or 'xss' in log.lower() for log in console_logs):
                    findings.append({'type': 'dom_xss', 'url': url, 'evidence': console_logs})
                # Check for client-side redirects
                if page.url != url:
                    findings.append({'type': 'client_redirect', 'url': url, 'redirected_to': page.url})
                # Check for suspicious DOM mutations
                if dom_mutations:
                    findings.append({'type': 'dom_mutation', 'url': url, 'mutations': dom_mutations})
                await browser.close()
        except Exception as e:
            logging.warning(f"Dynamic analysis failed for {url}: {e}")
        return findings

    async def scan_form(self, url: str, form: Dict[str, Any], payload: str = '<script>alert(1)</script>') -> List[Dict[str, Any]]:
        """Submit a form with a payload and monitor for DOM XSS or JS issues."""
        findings = []
        if not async_playwright:
            logging.warning("Playwright is not installed. Dynamic analysis unavailable.")
            return findings
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=self.headless)
                context = await browser.new_context()
                page = await context.new_page()
                console_logs = []
                dom_mutations = []
                page.on("console", lambda msg: console_logs.append(msg.text))
                await page.expose_function("__dom_mutation__", lambda data: dom_mutations.append(data))
                await page.add_init_script("""
                    new MutationObserver(function(mutations) {
                        window.__dom_mutation__(JSON.stringify(mutations));
                    }).observe(document, {subtree: true, childList: true, attributes: true});
                """)
                await page.goto(url, timeout=self.timeout * 1000)
                # Fill form fields
                for input_field in form.get('inputs', []):
                    selector = f"[name='{input_field['name']}']"
                    try:
                        await page.fill(selector, payload)
                    except Exception:
                        continue
                # Submit form
                try:
                    await page.click('input[type="submit"], button[type="submit"]')
                except Exception:
                    pass
                await page.wait_for_timeout(2000)
                # Check for DOM XSS
                if any('alert(' in log or 'xss' in log.lower() for log in console_logs):
                    findings.append({'type': 'dom_xss', 'url': url, 'form': form, 'evidence': console_logs})
                if dom_mutations:
                    findings.append({'type': 'dom_mutation', 'url': url, 'form': form, 'mutations': dom_mutations})
                await browser.close()
        except Exception as e:
            logging.warning(f"Dynamic form analysis failed for {url}: {e}")
        return findings 