import re
import logging

class CSRFHelper:
    def __init__(self, token_name='csrf_token'):
        self.token_name = token_name
        self.last_token = None

    def extract_token(self, html):
        # Extract CSRF token from HTML input fields
        match = re.search(rf'name=["\']{self.token_name}["\'][^>]*value=["\']([^"\']+)["\']', html)
        if match:
            self.last_token = match.group(1)
            return self.last_token
        return None

    def inject_token(self, data):
        # Inject CSRF token into POST data
        if not self.last_token:
            logging.warning('No CSRF token available to inject.')
            return data
        data[self.token_name] = self.last_token
        return data

    def is_token_missing(self, html):
        # Check if CSRF token is missing from form
        return self.token_name not in html

    def refresh_token(self, session, url):
        # Fetch a new CSRF token from a given URL
        try:
            resp = session.get(url)
            return self.extract_token(resp.text)
        except Exception as e:
            logging.error(f'CSRF token refresh failed: {e}')
            return None 