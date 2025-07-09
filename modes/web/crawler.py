import asyncio
import logging
import re
from typing import List, Set, Dict, Any, Optional
from urllib.parse import urljoin, urlparse, parse_qs
import httpx
from bs4 import BeautifulSoup
import importlib
import aiofiles
import xml.etree.ElementTree as ET

class Crawler:
    def __init__(self, base_url: str, max_depth: int = 3, max_urls: int = 100, 
                 exclude_patterns: Optional[List[str]] = None, 
                 include_patterns: Optional[List[str]] = None,
                 session_manager=None):
        self.base_url = base_url
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.exclude_patterns = exclude_patterns or []
        self.include_patterns = include_patterns or []
        self.session_manager = session_manager
        self.visited_urls: Set[str] = set()
        self.discovered_urls: Set[str] = set()
        self.forms: List[Dict[str, Any]] = []
        self.client = None
        
    async def create_client(self, timeout: int = 30, verify_ssl: bool = True):
        """Create HTTP client"""
        if self.session_manager:
            self.client = await self.session_manager.create_client(timeout, verify_ssl)
        else:
            self.client = httpx.AsyncClient(
                timeout=timeout,
                verify=verify_ssl,
                follow_redirects=True
            )
        return self.client
    
    async def close_client(self):
        """Close HTTP client"""
        if self.client:
            await self.client.aclose()
            self.client = None
    
    def should_crawl_url(self, url: str) -> bool:
        """Check if URL should be crawled based on patterns"""
        # Check exclude patterns
        for pattern in self.exclude_patterns:
            if re.search(pattern, url):
                return False
        
        # Check include patterns (if any)
        if self.include_patterns:
            for pattern in self.include_patterns:
                if re.search(pattern, url):
                    return True
            return False
        
        return True
    
    def is_same_domain(self, url: str) -> bool:
        """Check if URL is in same domain as base URL"""
        try:
            base_domain = urlparse(self.base_url).netloc
            url_domain = urlparse(url).netloc
            return base_domain == url_domain
        except:
            return False
    
    async def fetch_page(self, url: str) -> Optional[httpx.Response]:
        """Fetch a single page"""
        try:
            if not self.client:
                await self.create_client()
            
            if self.session_manager:
                response = await self.session_manager.make_request('GET', url)
            else:
                response = await self.client.get(url)
            
            return response
        except Exception as e:
            logging.debug(f"Failed to fetch {url}: {e}")
            return None
    
    async def fetch_page_js(self, url: str, timeout: int = 30) -> Optional[str]:
        """Fetch a page using Playwright for JS rendering. Returns HTML as string."""
        try:
            playwright_spec = importlib.util.find_spec("playwright.async_api")
            if playwright_spec is None:
                logging.warning("Playwright is not installed. JS rendering is unavailable.")
                return None
            from playwright.async_api import async_playwright
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context()
                page = await context.new_page()
                await page.goto(url, timeout=timeout * 1000)
                html = await page.content()
                await browser.close()
                return html
        except Exception as e:
            logging.warning(f"Playwright JS fetch failed for {url}: {e}")
            return None

    def extract_urls(self, html: str, base_url: str) -> List[str]:
        """Extract URLs from HTML content"""
        urls = set()
        
        # Extract from href attributes
        href_pattern = r'href=["\']([^"\']+)["\']'
        for match in re.findall(href_pattern, html):
            url = urljoin(base_url, match)
            if self.is_same_domain(url):
                urls.add(url)
        
        # Extract from src attributes
        src_pattern = r'src=["\']([^"\']+)["\']'
        for match in re.findall(src_pattern, html):
            url = urljoin(base_url, match)
            if self.is_same_domain(url):
                urls.add(url)
        
        # Extract from action attributes (forms)
        action_pattern = r'action=["\']([^"\']+)["\']'
        for match in re.findall(action_pattern, html):
            url = urljoin(base_url, match)
            if self.is_same_domain(url):
                urls.add(url)
        
        return list(urls)
    
    def extract_forms(self, html: str, page_url: str) -> List[Dict[str, Any]]:
        """Extract forms from HTML content"""
        forms = []
        soup = BeautifulSoup(html, 'html.parser')
        
        for form in soup.find_all('form'):
            form_data = {
                'action': urljoin(page_url, form.get('action', '')),
                'method': form.get('method', 'GET').upper(),
                'inputs': [],
                'page_url': page_url
            }
            
            # Extract input fields
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', ''),
                    'required': input_tag.get('required') is not None
                }
                
                if input_tag.name == 'select':
                    # Extract options for select elements
                    options = []
                    for option in input_tag.find_all('option'):
                        options.append({
                            'value': option.get('value', ''),
                            'text': option.get_text(strip=True)
                        })
                    input_data['options'] = options
                
                form_data['inputs'].append(input_data)
            
            forms.append(form_data)
        
        return forms
    
    async def crawl_page(self, url: str, depth: int = 0, use_js: bool = False) -> List[str]:
        """Crawl a single page and return discovered URLs. Optionally use JS rendering."""
        if depth > self.max_depth or len(self.discovered_urls) >= self.max_urls:
            return []
        if url in self.visited_urls or not self.should_crawl_url(url):
            return []
        self.visited_urls.add(url)
        logging.debug(f"Crawling {url} (depth: {depth}, js={use_js})")
        html = None
        if use_js:
            html = await self.fetch_page_js(url)
        if not html:
            response = await self.fetch_page(url)
            if not response or response.status_code != 200:
                return []
            html = response.text
        discovered_urls = self.extract_urls(html, url)
        page_forms = self.extract_forms(html, url)
        self.forms.extend(page_forms)
        new_urls = []
        for discovered_url in discovered_urls:
            if (discovered_url not in self.visited_urls and 
                discovered_url not in self.discovered_urls and
                self.should_crawl_url(discovered_url)):
                self.discovered_urls.add(discovered_url)
                new_urls.append(discovered_url)
        return new_urls

    async def parse_sitemap(self, sitemap_url: Optional[str] = None) -> List[str]:
        """Parse sitemap.xml and return discovered URLs."""
        sitemap_url = sitemap_url or urljoin(self.base_url, '/sitemap.xml')
        urls = []
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(sitemap_url, timeout=10)
                if resp.status_code == 200:
                    tree = ET.fromstring(resp.text)
                    for url_elem in tree.findall('.//{*}loc'):
                        url = url_elem.text.strip()
                        if url and self.is_same_domain(url):
                            urls.append(url)
                    logging.info(f"Parsed {len(urls)} URLs from sitemap.xml")
        except Exception as e:
            logging.info(f"No sitemap.xml or failed to parse: {e}")
        return urls

    async def parse_robots(self, robots_url: Optional[str] = None) -> List[str]:
        """Parse robots.txt and return disallowed paths."""
        robots_url = robots_url or urljoin(self.base_url, '/robots.txt')
        disallowed = []
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(robots_url, timeout=10)
                if resp.status_code == 200:
                    for line in resp.text.splitlines():
                        if line.strip().lower().startswith('disallow:'):
                            path = line.split(':', 1)[1].strip()
                            if path:
                                disallowed.append(path)
                    logging.info(f"Parsed {len(disallowed)} disallowed paths from robots.txt")
        except Exception as e:
            logging.info(f"No robots.txt or failed to parse: {e}")
        return disallowed

    async def login(self, login_url: Optional[str] = None, username: Optional[str] = None, password: Optional[str] = None, use_js: bool = False) -> bool:
        """Perform login and maintain session. Returns True if successful."""
        login_url = login_url or self.base_url
        username = username or getattr(self, 'login_username', None)
        password = password or getattr(self, 'login_password', None)
        if not username or not password:
            logging.info("No login credentials provided; skipping login.")
            return False
        if use_js:
            # Playwright-based login for JS forms
            try:
                from playwright.async_api import async_playwright
                async with async_playwright() as p:
                    browser = await p.chromium.launch(headless=True)
                    context = await browser.new_context()
                    page = await context.new_page()
                    await page.goto(login_url)
                    # Try to find username/password fields and submit
                    await page.fill('input[type="text"], input[name*="user" i]', username)
                    await page.fill('input[type="password"]', password)
                    await page.click('input[type="submit"], button[type="submit"]')
                    await page.wait_for_timeout(2000)
                    # Extract cookies
                    cookies = await context.cookies()
                    self.js_cookies = cookies
                    await browser.close()
                    logging.info("Login via Playwright completed.")
                    return True
            except Exception as e:
                logging.warning(f"Playwright login failed: {e}")
                return False
        else:
            # Static form login with httpx
            try:
                async with httpx.AsyncClient(follow_redirects=True) as client:
                    resp = await client.get(login_url)
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    form = soup.find('form')
                    if not form:
                        logging.warning("No login form found.")
                        return False
                    action = form.get('action') or login_url
                    method = form.get('method', 'post').lower()
                    data = {}
                    for input_tag in form.find_all('input'):
                        name = input_tag.get('name')
                        if not name:
                            continue
                        if 'user' in name.lower():
                            data[name] = username
                        elif 'pass' in name.lower():
                            data[name] = password
                        else:
                            data[name] = input_tag.get('value', '')
                    submit_url = urljoin(login_url, action)
                    if method == 'post':
                        login_resp = await client.post(submit_url, data=data)
                    else:
                        login_resp = await client.get(submit_url, params=data)
                    if login_resp.status_code in (200, 302):
                        self.client = client
                        self.session_cookies = client.cookies
                        logging.info("Login via httpx completed.")
                        return True
                    else:
                        logging.warning(f"Login failed: {login_resp.status_code}")
                        return False
            except Exception as e:
                logging.warning(f"Static login failed: {e}")
                return False

    async def crawl(self, use_js: bool = False, use_sitemap: bool = True, use_robots: bool = True, login_first: bool = False, login_url: Optional[str] = None, username: Optional[str] = None, password: Optional[str] = None) -> List[str]:
        """Main crawling method. Optionally perform login before crawling."""
        if login_first:
            logged_in = await self.login(login_url=login_url, username=username, password=password, use_js=use_js)
            if not logged_in:
                logging.warning("Login failed or not performed; continuing unauthenticated.")
        logging.info(f"Starting crawl of {self.base_url} (js={use_js}, sitemap={use_sitemap}, robots={use_robots})")
        try:
            urls_to_crawl = [self.base_url]
            if use_sitemap:
                sitemap_urls = await self.parse_sitemap()
                urls_to_crawl.extend([u for u in sitemap_urls if u not in urls_to_crawl])
            disallowed = []
            if use_robots:
                disallowed = await self.parse_robots()
            depth = 0
            while urls_to_crawl and depth <= self.max_depth:
                new_urls = []
                tasks = []
                for url in urls_to_crawl[:10]:
                    if any(urlparse(url).path.startswith(d) for d in disallowed):
                        continue
                    task = asyncio.create_task(self.crawl_page(url, depth, use_js=use_js))
                    tasks.append(task)
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for result in results:
                    if isinstance(result, list):
                        new_urls.extend(result)
                urls_to_crawl = new_urls
                depth += 1
                logging.info(f"Crawl depth {depth}: discovered {len(new_urls)} new URLs")
                if len(self.discovered_urls) >= self.max_urls:
                    logging.info(f"Reached maximum URL limit ({self.max_urls})")
                    break
            all_urls = list(self.discovered_urls)
            logging.info(f"Crawl completed. Found {len(all_urls)} URLs and {len(self.forms)} forms")
            return all_urls
        finally:
            await self.close_client()
    
    def get_forms(self) -> List[Dict[str, Any]]:
        """Get discovered forms"""
        return self.forms.copy()
    
    def get_crawl_stats(self) -> Dict[str, Any]:
        """Get crawling statistics"""
        return {
            'base_url': self.base_url,
            'visited_urls': len(self.visited_urls),
            'discovered_urls': len(self.discovered_urls),
            'forms_found': len(self.forms),
            'max_depth': self.max_depth,
            'max_urls': self.max_urls
        } 