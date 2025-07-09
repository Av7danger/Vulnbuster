import asyncio
import json
import logging
from typing import Dict, Any, Optional, List
import httpx
from urllib.parse import urlparse

class SessionManager:
    def __init__(self, cookies_file: Optional[str] = None, headers: Optional[Dict[str, str]] = None):
        self.cookies_file = cookies_file
        self.headers = headers or {}
        self.session_cookies = {}
        self.auth_tokens = {}
        self.session_data = {}
        self.client = None
        
        # Load existing cookies if file exists
        if cookies_file:
            self.load_cookies()
    
    def load_cookies(self):
        """Load cookies from file"""
        if not self.cookies_file:
            return
            
        try:
            with open(self.cookies_file, 'r') as f:
                self.session_cookies = json.load(f)
            logging.info(f"Loaded cookies from {self.cookies_file}")
        except FileNotFoundError:
            logging.info(f"Cookie file {self.cookies_file} not found, starting fresh")
        except Exception as e:
            logging.error(f"Error loading cookies: {e}")
    
    def save_cookies(self):
        """Save cookies to file"""
        if not self.cookies_file:
            return
        
        try:
            with open(self.cookies_file, 'w') as f:
                json.dump(self.session_cookies, f, indent=2)
            logging.info(f"Saved cookies to {self.cookies_file}")
        except Exception as e:
            logging.error(f"Error saving cookies: {e}")
    
    async def create_client(self, timeout: int = 30, verify_ssl: bool = True, 
                          proxy: Optional[str] = None) -> httpx.AsyncClient:
        """Create HTTP client with session configuration"""
        limits = httpx.Limits(max_keepalive_connections=5, max_connections=10)
        
        client_kwargs = {
            'timeout': timeout,
            'verify': verify_ssl,
            'limits': limits,
            'follow_redirects': True
        }
        
        if proxy:
            client_kwargs['proxies'] = proxy
        
        self.client = httpx.AsyncClient(**client_kwargs)
        return self.client
    
    async def close_client(self):
        """Close HTTP client"""
        if self.client:
            await self.client.aclose()
            self.client = None
    
    def get_cookies_for_domain(self, url: str) -> Dict[str, str]:
        """Get cookies for specific domain"""
        domain = urlparse(url).netloc
        return self.session_cookies.get(domain, {})
    
    def set_cookies_for_domain(self, url: str, cookies: Dict[str, str]):
        """Set cookies for specific domain"""
        domain = urlparse(url).netloc
        if domain not in self.session_cookies:
            self.session_cookies[domain] = {}
        
        self.session_cookies[domain].update(cookies)
        self.save_cookies()
    
    def get_headers(self) -> Dict[str, str]:
        """Get session headers"""
        return self.headers.copy()
    
    def set_header(self, key: str, value: str):
        """Set session header"""
        self.headers[key] = value
    
    def set_auth_token(self, token_type: str, token: str):
        """Set authentication token"""
        self.auth_tokens[token_type] = token
        
        # Auto-set Authorization header for common token types
        if token_type.lower() in ['bearer', 'jwt']:
            self.set_header('Authorization', f'Bearer {token}')
        elif token_type.lower() == 'api_key':
            self.set_header('X-API-Key', token)
    
    def get_auth_token(self, token_type: str) -> Optional[str]:
        """Get authentication token"""
        return self.auth_tokens.get(token_type)
    
    async def login(self, login_url: str, credentials: Dict[str, str], 
                   method: str = 'POST') -> bool:
        """Perform login and capture session"""
        try:
            if not self.client:
                await self.create_client()
            
            # Prepare request
            if method.upper() == 'POST':
                response = await self.client.post(login_url, data=credentials)
            else:
                response = await self.client.get(login_url, params=credentials)
            
            if response.status_code in [200, 302, 303]:
                # Extract cookies from response
                cookies = dict(response.cookies)
                if cookies:
                    self.set_cookies_for_domain(login_url, cookies)
                
                # Check for common auth tokens in response
                self._extract_auth_tokens(response)
                
                logging.info(f"Login successful to {login_url}")
                return True
            else:
                logging.warning(f"Login failed to {login_url}, status: {response.status_code}")
                return False
                
        except Exception as e:
            logging.error(f"Login error: {e}")
            return False
    
    def _extract_auth_tokens(self, response: httpx.Response):
        """Extract authentication tokens from response"""
        # Check for JWT in response body
        try:
            data = response.json()
            if 'token' in data:
                self.set_auth_token('jwt', data['token'])
            elif 'access_token' in data:
                self.set_auth_token('jwt', data['access_token'])
        except:
            pass
        
        # Check for tokens in headers
        auth_header = response.headers.get('authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            self.set_auth_token('bearer', token)
    
    async def make_request(self, method: str, url: str, **kwargs) -> httpx.Response:
        """Make HTTP request with session data"""
        if not self.client:
            await self.create_client()
        
        # Add session cookies
        domain_cookies = self.get_cookies_for_domain(url)
        if domain_cookies:
            if 'cookies' not in kwargs:
                kwargs['cookies'] = {}
            kwargs['cookies'].update(domain_cookies)
        
        # Add session headers
        if 'headers' not in kwargs:
            kwargs['headers'] = {}
        kwargs['headers'].update(self.get_headers())
        
        # Make request
        if self.client:
            response = await self.client.request(method, url, **kwargs)
            
            # Update cookies from response
            if response.cookies:
                new_cookies = dict(response.cookies)
                if new_cookies:
                    self.set_cookies_for_domain(url, new_cookies)
            
            return response
        else:
            raise RuntimeError("HTTP client not initialized")
    
    def get_session_info(self) -> Dict[str, Any]:
        """Get session information"""
        return {
            'cookies': self.session_cookies,
            'headers': self.headers,
            'auth_tokens': list(self.auth_tokens.keys()),
            'domains_with_cookies': list(self.session_cookies.keys())
        }
    
    def clear_session(self):
        """Clear all session data"""
        self.session_cookies = {}
        self.auth_tokens = {}
        self.session_data = {}
        if self.cookies_file:
            self.save_cookies()
        logging.info("Session data cleared")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.client:
            asyncio.create_task(self.close_client()) 