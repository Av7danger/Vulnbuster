import re
import hashlib
import logging
import random
import string
import time
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
import difflib
from colorama import Fore, Style, init

# Initialize colorama
init()

# Color mappings for different severity levels
SEVERITY_COLORS = {
    'critical': Fore.RED,
    'high': Fore.MAGENTA,
    'medium': Fore.YELLOW,
    'low': Fore.CYAN,
    'info': Fore.GREEN,
    'debug': Fore.WHITE
}

# Common User-Agent strings
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0'
]

# Header templates
HEADER_TEMPLATES = [
    {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    }
]

def print_banner():
    """Print WebBlood banner"""
    banner = (
        f"{Fore.RED}__        __    _     ____  _                 _ \n"
        f"\\ \\      / /_ _| |__ | __ )| | ___   __ _  __| |\n"
        f" \\ \\ /\\ / / _` | '_ \\|  _ \\| |/ _ \\ / _` |/ _` |\n"
        f"  \\ V  V / (_| | |_) | |_) | | (_) | (_| | (_| |\n"
        f"   \\_/\\_/ \\__,_|_.__/|____/|_|\\___/ \\__,_|\\__,_|\n"
        f"{Style.RESET_ALL}WebBlood - Weaponized Web Exploitation Framework\n"
    )
    print(banner)

def color_print(msg: str, level: str = 'info'):
    """Print colored message based on severity level"""
    color = SEVERITY_COLORS.get(level, Fore.WHITE)
    print(f"{color}{msg}{Style.RESET_ALL}")

def setup_logging(verbose: bool = False):
    """Setup logging configuration"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='[%(asctime)s] %(levelname)s: %(message)s',
        datefmt='%H:%M:%S'
    )

def random_user_agent() -> str:
    """Get random User-Agent string"""
    return random.choice(USER_AGENTS)

def random_headers() -> Dict[str, str]:
    """Generate random headers"""
    headers = {}
    for template in HEADER_TEMPLATES:
        headers.update(template)
    headers['User-Agent'] = random_user_agent()
    return headers

def jitter_delay(base_delay: float = 0.5, jitter: float = 0.5):
    """Add jitter to delays to avoid detection"""
    delay = base_delay + random.uniform(0, jitter)
    time.sleep(delay)

class Utils:
    @staticmethod
    def extract_urls_from_text(text: str) -> List[str]:
        """Extract URLs from text content"""
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        return re.findall(url_pattern, text)
    
    @staticmethod
    def extract_parameters_from_url(url: str) -> Dict[str, List[str]]:
        """Extract parameters from URL"""
        parsed = urlparse(url)
        return parse_qs(parsed.query)
    
    @staticmethod
    def build_url_with_params(base_url: str, params: Dict[str, str]) -> str:
        """Build URL with parameters"""
        parsed = urlparse(base_url)
        query_params = parse_qs(parsed.query)
        
        # Update with new parameters
        for key, value in params.items():
            query_params[key] = [value]
        
        # Rebuild query string
        new_query = urlencode(query_params, doseq=True)
        
        # Rebuild URL
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
    
    @staticmethod
    def normalize_url(url: str) -> str:
        """Normalize URL for comparison"""
        # Remove trailing slash
        if url.endswith('/'):
            url = url[:-1]
        
        # Ensure scheme
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        return url.lower()
    
    @staticmethod
    def is_same_domain(url1: str, url2: str) -> bool:
        """Check if two URLs are in the same domain"""
        try:
            domain1 = urlparse(url1).netloc
            domain2 = urlparse(url2).netloc
            return domain1 == domain2
        except:
            return False
    
    @staticmethod
    def http_diff(response1: str, response2: str, threshold: float = 0.8) -> Dict[str, Any]:
        """Compare two HTTP responses and return diff analysis"""
        diff_result = {
            'similarity': 0.0,
            'differences': [],
            'significant_change': False
        }
        
        # Calculate similarity using difflib
        similarity = difflib.SequenceMatcher(None, response1, response2).ratio()
        diff_result['similarity'] = similarity
        
        # Find differences
        differ = difflib.Differ()
        diff = list(differ.compare(response1.splitlines(), response2.splitlines()))
        
        differences = []
        for line in diff:
            if line.startswith('+ ') or line.startswith('- '):
                differences.append(line)
        
        diff_result['differences'] = differences
        diff_result['significant_change'] = similarity < threshold
        
        return diff_result
    
    @staticmethod
    def calculate_response_hash(response_text: str) -> str:
        """Calculate hash of response content"""
        return hashlib.md5(response_text.encode()).hexdigest()
    
    @staticmethod
    def extract_forms_from_html(html: str) -> List[Dict[str, Any]]:
        """Extract forms from HTML content"""
        forms = []
        
        # Simple regex-based extraction
        form_pattern = r'<form[^>]*>(.*?)</form>'
        action_pattern = r'action=["\']([^"\']+)["\']'
        method_pattern = r'method=["\']([^"\']+)["\']'
        input_pattern = r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>'
        
        for form_match in re.finditer(form_pattern, html, re.DOTALL | re.IGNORECASE):
            form_html = form_match.group(0)
            
            # Extract form attributes
            action_match = re.search(action_pattern, form_html, re.IGNORECASE)
            method_match = re.search(method_pattern, form_html, re.IGNORECASE)
            
            form_data = {
                'action': action_match.group(1) if action_match else '',
                'method': method_match.group(1).upper() if method_match else 'GET',
                'inputs': []
            }
            
            # Extract input fields
            for input_match in re.finditer(input_pattern, form_html, re.IGNORECASE):
                input_name = input_match.group(1)
                form_data['inputs'].append(input_name)
            
            forms.append(form_data)
        
        return forms
    
    @staticmethod
    def generate_wordlist(base_words: List[str], mutations: Optional[List[str]] = None) -> List[str]:
        """Generate wordlist with mutations"""
        if mutations is None:
            mutations = ['', '.php', '.html', '.asp', '.aspx', '.jsp']
        
        wordlist = []
        for word in base_words:
            wordlist.append(word)
            for mutation in mutations:
                wordlist.append(word + mutation)
        
        return wordlist
    
    @staticmethod
    def generate_random_string(length: int = 8) -> str:
        """Generate random string"""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
    
    @staticmethod
    def detect_waf(response_headers: Dict[str, str], response_body: str) -> Optional[str]:
        """Detect Web Application Firewall"""
        waf_indicators = {
            'cloudflare': ['cf-ray', 'cloudflare'],
            'akamai': ['akamai', 'aka-debug'],
            'incapsula': ['incap_ses', 'visid_incap'],
            'f5': ['bigip', 'f5_'],
            'barracuda': ['barra_counter_session'],
            'mod_security': ['mod_security', 'modsecurity'],
            'sucuri': ['sucuri', 'sucuri-js']
        }
        
        headers_str = ' '.join(response_headers.values()).lower()
        body_lower = response_body.lower()
        
        for waf_name, indicators in waf_indicators.items():
            for indicator in indicators:
                if indicator in headers_str or indicator in body_lower:
                    return waf_name
        
        return None
    
    @staticmethod
    def extract_emails_from_text(text: str) -> List[str]:
        """Extract email addresses from text"""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        return re.findall(email_pattern, text)
    
    @staticmethod
    def extract_ips_from_text(text: str) -> List[str]:
        """Extract IP addresses from text"""
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        return re.findall(ip_pattern, text)
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename for safe file operations"""
        # Remove or replace unsafe characters
        unsafe_chars = '<>:"/\\|?*'
        for char in unsafe_chars:
            filename = filename.replace(char, '_')
        
        # Limit length
        if len(filename) > 255:
            filename = filename[:255]
        
        return filename
    
    @staticmethod
    def parse_http_headers(headers_str: str) -> Dict[str, str]:
        """Parse HTTP headers string to dictionary"""
        headers = {}
        for line in headers_str.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        return headers
    
    @staticmethod
    def format_bytes(bytes_value: int) -> str:
        """Format bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.1f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.1f} TB"
    
    @staticmethod
    def calculate_entropy(data: str) -> float:
        """Calculate Shannon entropy of data"""
        import math
        
        if not data:
            return 0.0
        
        # Count character frequencies
        char_count = {}
        for char in data:
            char_count[char] = char_count.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        length = len(data)
        for count in char_count.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    @staticmethod
    def detect_encoding_pattern(data: str) -> str:
        """Detect encoding pattern in data"""
        patterns = {
            'base64': r'^[A-Za-z0-9+/]*={0,2}$',
            'hex': r'^[0-9a-fA-F]+$',
            'url_encoded': r'%[0-9a-fA-F]{2}',
            'unicode': r'\\u[0-9a-fA-F]{4}',
            'html_entities': r'&[a-zA-Z]+;|&#[0-9]+;'
        }
        
        for encoding, pattern in patterns.items():
            if re.search(pattern, data):
                return encoding
        
        return 'plain'
    
    @staticmethod
    def extract_js_endpoints(js_content: str) -> List[str]:
        """Extract API endpoints from JavaScript code"""
        endpoints = []
        
        # Common patterns for API endpoints
        patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/v\d+/[^"\']+)["\']',
            r'["\'](/rest/[^"\']+)["\']',
            r'["\'](/graphql[^"\']*)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'\.get\(["\']([^"\']+)["\']',
            r'\.post\(["\']([^"\']+)["\']'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            endpoints.extend(matches)
        
        return list(set(endpoints))  # Remove duplicates
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """Validate URL format"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    @staticmethod
    def get_domain_from_url(url: str) -> str:
        """Extract domain from URL"""
        try:
            return urlparse(url).netloc
        except:
            return ""
    
    @staticmethod
    def is_internal_ip(ip: str) -> bool:
        """Check if IP is internal/private"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            
            first_octet = int(parts[0])
            second_octet = int(parts[1])
            
            # Private IP ranges
            if first_octet == 10:
                return True
            elif first_octet == 172 and 16 <= second_octet <= 31:
                return True
            elif first_octet == 192 and second_octet == 168:
                return True
            elif first_octet == 127:
                return True
            
            return False
        except:
            return False 