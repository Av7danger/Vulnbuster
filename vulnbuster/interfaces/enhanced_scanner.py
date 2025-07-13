""
Enhanced Scanner Interface with HTTP Client

This module provides an enhanced version of the Scanner class with built-in
HTTP client capabilities, including rate limiting, retries, and hooks.
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, TypeVar, Union, Awaitable

from aiohttp import ClientResponse
from typing_extensions import Literal

from .scanner import (
    DEFAULT_TIMEOUT,
    DEFAULT_RETRY_ATTEMPTS,
    DEFAULT_RETRY_DELAY,
    DEFAULT_MAX_RETRY_DELAY,
    DEFAULT_RATE_LIMIT,
    DEFAULT_CONCURRENCY,
    DEFAULT_MAX_REDIRECTS,
    COMMON_HEADERS,
    Headers,
    Params,
    RequestData,
    RequestHook,
    ResponseHook,
    ScanContext,
    ScanResult,
)

# Type variable for generic methods
T = TypeVar('T')

class EnhancedScanner(ABC):
    """Enhanced base class for scanner implementations with HTTP client capabilities.
    
    This class provides a foundation for building security scanners with built-in
    HTTP client functionality, including rate limiting, retries, and hooks.
    """
    
    # Scanner metadata
    name: str = "enhanced_scanner"
    version: str = "0.1.0"
    description: str = "Enhanced scanner class with HTTP client"
    
    # Supported scan types
    supported_scan_types: Set[str] = set()
    
    # Default configuration
    default_config: Dict[str, Any] = {
        'http': {
            'base_url': None,
            'timeout': DEFAULT_TIMEOUT,
            'max_retries': DEFAULT_RETRY_ATTEMPTS,
            'retry_delay': DEFAULT_RETRY_DELAY,
            'max_retry_delay': DEFAULT_MAX_RETRY_DELAY,
            'rate_limit': DEFAULT_RATE_LIMIT,
            'max_concurrent': DEFAULT_CONCURRENCY,
            'verify_ssl': True,
            'follow_redirects': True,
            'max_redirects': DEFAULT_MAX_REDIRECTS,
            'proxy': None,
            'headers': {},
        },
        'scanner': {
            'enabled': True,
            'tags': [],
            'metadata': {},
        },
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the scanner with the given configuration.
        
        Args:
            config: Scanner configuration that will be merged with default_config.
                   Can contain HTTP client settings under the 'http' key.
        """
        # Initialize with default config
        self.config = {**self.default_config}
        
        # Deep merge the provided config
        if config:
            self._deep_merge(self.config, config)
        
        # Initialize HTTP client
        self._http_client = None
    
    @abstractmethod
    async def scan(self, target: str, context: Optional[ScanContext] = None) -> ScanResult:
        """Perform a scan of the target.
        
        Args:
            target: The target to scan (URL, hostname, IP, etc.)
            context: Optional scan context
            
        Returns:
            ScanResult containing the scan findings
        """
        pass
    
    # HTTP Client Methods
    
    @property
    def http(self) -> 'HTTPClient':
        """Get the HTTP client instance, initializing it if necessary."""
        if self._http_client is None:
            from .http_client import HTTPClient
            self._http_client = HTTPClient(**self.config.get('http', {}))
        return self._http_client
    
    async def setup(self) -> None:
        """Set up the scanner and its HTTP client."""
        await self.http.setup()
    
    async def teardown(self) -> None:
        """Clean up the scanner and its HTTP client."""
        if self._http_client:
            await self._http_client.teardown()
            self._http_client = None
    
    # HTTP convenience methods
    
    async def get(self, url: str, **kwargs) -> ClientResponse:
        """Send a GET request using the scanner's HTTP client."""
        return await self.http.get(url, **kwargs)
    
    async def post(self, url: str, **kwargs) -> ClientResponse:
        """Send a POST request using the scanner's HTTP client."""
        return await self.http.post(url, **kwargs)
    
    async def put(self, url: str, **kwargs) -> ClientResponse:
        """Send a PUT request using the scanner's HTTP client."""
        return await self.http.put(url, **kwargs)
    
    async def delete(self, url: str, **kwargs) -> ClientResponse:
        """Send a DELETE request using the scanner's HTTP client."""
        return await self.http.delete(url, **kwargs)
    
    async def head(self, url: str, **kwargs) -> ClientResponse:
        """Send a HEAD request using the scanner's HTTP client."""
        return await self.http.head(url, **kwargs)
    
    async def options(self, url: str, **kwargs) -> ClientResponse:
        """Send an OPTIONS request using the scanner's HTTP client."""
        return await self.http.options(url, **kwargs)
    
    async def patch(self, url: str, **kwargs) -> ClientResponse:
        """Send a PATCH request using the scanner's HTTP client."""
        return await self.http.patch(url, **kwargs)
    
    # Utility methods
    
    def _deep_merge(self, base: Dict[str, Any], update: Dict[str, Any]) -> None:
        """Recursively merge two dictionaries."""
        for key, value in update.items():
            if (key in base and isinstance(base[key], dict) and 
                    isinstance(value, dict)):
                self._deep_merge(base[key], value)
            else:
                base[key] = value
    
    # Scanner interface compatibility methods
    
    async def validate_config(self) -> bool:
        """Validate the scanner configuration.
        
        Returns:
            bool: True if the configuration is valid, False otherwise
        """
        return True
    
    def get_scan_types(self) -> Set[str]:
        """Get the set of supported scan types.
        
        Returns:
            Set of supported scan type identifiers
        """
        return self.supported_scan_types
    
    def supports_scan_type(self, scan_type: str) -> bool:
        """Check if the scanner supports a specific scan type.
        
        Args:
            scan_type: The scan type to check
            
        Returns:
            bool: True if the scan type is supported, False otherwise
        """
        return scan_type in self.supported_scan_types


class EnhancedActiveScanner(EnhancedScanner):
    """Enhanced base class for active scanners with HTTP client capabilities."""
    
    async def scan(self, target: str, context: Optional[ScanContext] = None) -> ScanResult:
        """Perform an active scan of the target."""
        result = ScanResult(target=target, start_time=time.time())
        ctx = context or ScanContext(target=target, config=self.config)
        
        try:
            await self.setup()
            await self.run_scan(target, result, ctx)
            result.status = ScanStatus.COMPLETED
        except Exception as e:
            result.status = ScanStatus.FAILED
            result.error = str(e)
            if ctx.config.get('debug', False):
                import traceback
                result.error += f"\n\n{traceback.format_exc()}"
        finally:
            result.end_time = time.time()
            await self.teardown()
        
        return result
    
    @abstractmethod
    async def run_scan(self, target: str, result: ScanResult, context: ScanContext) -> None:
        """Run the active scan.
        
        Args:
            target: The target to scan
            result: ScanResult to populate with findings
            context: Scan context with HTTP session and other resources
        """
        pass


class EnhancedPassiveScanner(EnhancedScanner):
    """Enhanced base class for passive scanners with HTTP client capabilities."""
    
    async def scan(self, target: str, context: Optional[ScanContext] = None) -> ScanResult:
        """Perform a passive scan of the target."""
        result = ScanResult(target=target, start_time=time.time())
        
        try:
            await self.setup()
            await self.run_scan(target, result, context or ScanContext(target=target, config=self.config))
            result.status = ScanStatus.COMPLETED
        except Exception as e:
            result.status = ScanStatus.FAILED
            result.error = str(e)
            if context and context.config.get('debug', False):
                import traceback
                result.error += f"\n\n{traceback.format_exc()}"
        finally:
            result.end_time = time.time()
            await self.teardown()
        
        return result
    
    @abstractmethod
    async def run_scan(self, target: str, result: ScanResult, context: ScanContext) -> None:
        """Run the passive scan.
        
        Args:
            target: The target to scan
            result: ScanResult to populate with findings
            context: Scan context
        """
        pass
