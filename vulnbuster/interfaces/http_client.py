""
HTTP Client Module for VulnBuster

This module provides an enhanced HTTP client with rate limiting, retry logic,
and request/response hooks for use in security scanning operations.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set, TypeVar, Union

import aiohttp
from aiohttp import ClientResponse, ClientSession, ClientTimeout, TCPConnector
from typing_extensions import TypeAlias

from .scanner import (
    DEFAULT_CONCURRENCY,
    DEFAULT_MAX_REDIRECTS,
    DEFAULT_MAX_RETRY_DELAY,
    DEFAULT_RATE_LIMIT,
    DEFAULT_RETRY_ATTEMPTS,
    DEFAULT_RETRY_DELAY,
    DEFAULT_TIMEOUT,
    COMMON_HEADERS,
    Headers,
    Params,
    RequestData,
    RequestHook,
    ResponseHook,
    Url,
)

# Type variables
T = TypeVar('T')

# Configure logging
logger = logging.getLogger(__name__)

class RateLimiter:
    """Rate limiter using token bucket algorithm for controlling request rates."""
    
    def __init__(
        self,
        rate: float = DEFAULT_RATE_LIMIT,
        capacity: Optional[int] = None,
        clock: Optional[Callable[[], float]] = None
    ):
        """Initialize the rate limiter.
        
        Args:
            rate: Number of requests per second
            capacity: Maximum number of tokens in the bucket
            clock: Function returning current time in seconds
        """
        self.rate = float(rate)
        self.capacity = capacity or int(rate * 2)  # Default to 2x rate for burst
        self._tokens = self.capacity
        self._last_update = (clock or time.time)()
        self._lock = asyncio.Lock()
        self._clock = clock or time.time

    async def acquire(self, tokens: int = 1) -> float:
        """Acquire tokens from the bucket.
        
        Args:
            tokens: Number of tokens to acquire
            
        Returns:
            float: Time waited for the tokens (if any)
        """
        async with self._lock:
            now = self._clock()
            elapsed = now - self._last_update
            
            # Add tokens based on elapsed time
            if elapsed > 0:
                new_tokens = elapsed * self.rate
                self._tokens = min(self.capacity, self._tokens + new_tokens)
                self._last_update = now
            
            # If not enough tokens, calculate wait time
            if tokens > self._tokens:
                deficit = tokens - self._tokens
                wait_time = deficit / self.rate
                self._tokens = 0
                self._last_update += wait_time
                await asyncio.sleep(wait_time)
                return wait_time
            
            # Enough tokens available
            self._tokens -= tokens
            return 0.0

    async def __aenter__(self) -> 'RateLimiter':
        """Context manager entry."""
        await self.acquire()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit."""
        pass


class HTTPClient(ABC):
    """Base HTTP client with rate limiting, retries, and hooks."""
    
    def __init__(
        self,
        base_url: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_RETRY_ATTEMPTS,
        retry_delay: float = DEFAULT_RETRY_DELAY,
        max_retry_delay: float = DEFAULT_MAX_RETRY_DELAY,
        rate_limit: float = DEFAULT_RATE_LIMIT,
        max_concurrent: int = DEFAULT_CONCURRENCY,
        verify_ssl: bool = True,
        follow_redirects: bool = True,
        max_redirects: int = DEFAULT_MAX_REDIRECTS,
        proxy: Optional[str] = None,
    ):
        """Initialize the HTTP client.
        
        Args:
            base_url: Base URL for all requests
            headers: Default headers for all requests
            timeout: Default timeout in seconds
            max_retries: Maximum number of retry attempts
            retry_delay: Initial delay between retries in seconds
            max_retry_delay: Maximum delay between retries in seconds
            rate_limit: Maximum requests per second
            max_concurrent: Maximum concurrent requests
            verify_ssl: Verify SSL certificates
            follow_redirects: Follow HTTP redirects
            max_redirects: Maximum number of redirects to follow
            proxy: Proxy URL (e.g., 'http://user:pass@proxy:port')
        """
        self.base_url = base_url.rstrip('/') if base_url else None
        self.headers = dict(headers or COMMON_HEADERS)
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.max_retry_delay = max_retry_delay
        self.rate_limit = rate_limit
        self.max_concurrent = max_concurrent
        self.verify_ssl = verify_ssl
        self.follow_redirects = follow_redirects
        self.max_redirects = max_redirects
        self.proxy = proxy
        
        # Internal state
        self._session: Optional[ClientSession] = None
        self._rate_limiter: Optional[RateLimiter] = None
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._request_hooks: List[RequestHook] = []
        self._response_hooks: List[ResponseHook] = []
    
    async def setup(self) -> None:
        """Set up the HTTP client resources."""
        if self._session is None or self._session.closed:
            timeout = ClientTimeout(total=self.timeout)
            connector = TCPConnector(
                verify_ssl=self.verify_ssl,
                limit=self.max_concurrent,
                limit_per_host=self.max_concurrent,
                force_close=False,
                enable_cleanup_closed=True,
            )
            
            self._session = ClientSession(
                base_url=self.base_url or '',
                headers=self.headers,
                timeout=timeout,
                connector=connector,
                auto_decompress=True,
                trust_env=True,
            )
        
        if self._rate_limiter is None:
            self._rate_limiter = RateLimiter(rate=self.rate_limit)
        
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.max_concurrent)
    
    async def teardown(self) -> None:
        """Clean up HTTP client resources."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None
        
        self._rate_limiter = None
        self._semaphore = None
    
    def add_request_hook(self, hook: RequestHook) -> None:
        """Add a request hook that will be called before each request.
        
        Args:
            hook: Async function that takes a RequestContext
        """
        self._request_hooks.append(hook)
    
    def add_response_hook(self, hook: ResponseHook) -> None:
        """Add a response hook that will be called after each response.
        
        Args:
            hook: Async function that takes a ResponseContext
        """
        self._response_hooks.append(hook)
    
    async def request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[Params] = None,
        data: Optional[RequestData] = None,
        json_data: Optional[Any] = None,
        headers: Optional[Headers] = None,
        cookies: Optional[Dict[str, str]] = None,
        allow_redirects: Optional[bool] = None,
        timeout: Optional[float] = None,
        verify_ssl: Optional[bool] = None,
        proxy: Optional[str] = None,
        **kwargs: Any,
    ) -> ClientResponse:
        """Make an HTTP request with retry, rate limiting, and hooks.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: Target URL (can be relative if base_url is set)
            params: URL query parameters
            data: Request body data
            json_data: JSON-serializable data (alternative to data)
            headers: Request headers
            cookies: Cookies to include in the request
            allow_redirects: Whether to follow redirects
            timeout: Request timeout in seconds
            verify_ssl: Verify SSL certificates
            proxy: Proxy URL
            **kwargs: Additional arguments for aiohttp.ClientSession.request
            
        Returns:
            aiohttp.ClientResponse: The HTTP response
            
        Raises:
            aiohttp.ClientError: If the request fails after all retries
        """
        if self._session is None:
            await self.setup()
        
        # Apply defaults
        allow_redirects = self.follow_redirects if allow_redirects is None else allow_redirects
        timeout_val = ClientTimeout(total=timeout or self.timeout)
        verify_ssl_val = self.verify_ssl if verify_ssl is None else verify_ssl
        proxy_val = proxy or self.proxy
        
        # Create request context
        req_ctx = RequestContext(
            method=method.upper(),
            url=url,
            headers=dict(headers or {}),
            params=params,
            data=data,
            json=json_data,
            cookies=cookies or {},
            allow_redirects=allow_redirects,
            timeout=timeout_val.total,
            verify_ssl=verify_ssl_val,
            proxy=proxy_val,
            metadata={
                'start_time': time.time(),
                'attempt': 1,
                'max_attempts': self.max_retries + 1,  # +1 for initial attempt
            }
        )
        
        # Execute request with retry logic
        return await self._execute_request_with_retry(req_ctx, **kwargs)
    
    async def _execute_request_with_retry(
        self,
        req_ctx: RequestContext,
        **kwargs: Any,
    ) -> ClientResponse:
        """Execute a request with retry logic."""
        last_exc = None
        
        for attempt in range(1, self.max_retries + 2):  # +1 for initial attempt
            try:
                # Apply rate limiting
                if self._rate_limiter:
                    await self._rate_limiter.acquire()
                
                # Apply concurrency control
                if self._semaphore:
                    async with self._semaphore:
                        return await self._execute_single_request(req_ctx, **kwargs)
                else:
                    return await self._execute_single_request(req_ctx, **kwargs)
                    
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                last_exc = e
                if attempt > self.max_retries:
                    break
                    
                # Calculate delay with exponential backoff and jitter
                delay = min(
                    self.retry_delay * (2 ** (attempt - 1)),
                    self.max_retry_delay
                )
                jitter = random.uniform(0.8, 1.2)
                delay *= jitter
                
                logger.warning(
                    f"Request failed (attempt {attempt}/{self.max_retries + 1}): "
                    f"{str(e)}. Retrying in {delay:.2f}s..."
                )
                
                await asyncio.sleep(delay)
                req_ctx.attempt += 1
                
        # If we get here, all retries failed
        raise aiohttp.ClientError(
            f"Request failed after {self.max_retries + 1} attempts: {str(last_exc)}"
        ) from last_exc
    
    async def _execute_single_request(
        self,
        req_ctx: RequestContext,
        **kwargs: Any,
    ) -> ClientResponse:
        """Execute a single HTTP request."""
        if self._session is None:
            raise RuntimeError("Session not initialized")
        
        # Call request hooks
        for hook in self._request_hooks:
            await hook(req_ctx)
        
        # Prepare request arguments
        req_kwargs: Dict[str, Any] = {
            'method': req_ctx.method,
            'url': req_ctx.url,
            'params': req_ctx.params,
            'headers': req_ctx.headers,
            'cookies': req_ctx.cookies,
            'allow_redirects': req_ctx.allow_redirects,
            'timeout': ClientTimeout(total=req_ctx.timeout),
            'proxy': req_ctx.proxy,
            'verify_ssl': req_ctx.verify_ssl,
            **kwargs
        }
        
        # Add data or json based on what was provided
        if req_ctx.data is not None:
            req_kwargs['data'] = req_ctx.data
        elif req_ctx.json is not None:
            req_kwargs['json'] = req_ctx.json
        
        start_time = time.time()
        
        try:
            # Make the actual HTTP request
            response = await self._session.request(**req_kwargs)
            
            # Read response content
            content = await response.read()
            elapsed = time.time() - start_time
            
            # Create response context
            resp_ctx = ResponseContext(
                url=str(response.url),
                status=response.status,
                headers=dict(response.headers),
                content=content,
                request=req_ctx,
                elapsed=elapsed,
                cookies=dict(response.cookies),
                metadata={
                    'status': response.status,
                    'elapsed': elapsed,
                    'content_type': response.content_type,
                    'content_length': response.content_length,
                    'is_redirect': response.status in (301, 302, 303, 307, 308)
                }
            )
            
            # Call response hooks
            for hook in self._response_hooks:
                await hook(resp_ctx)
            
            # Reset response to be read again
            response._body = content
            response._content = content
            response._content_consumed = False
            
            return response
            
        except Exception as e:
            elapsed = time.time() - start_time
            error_ctx = ResponseContext(
                url=req_ctx.url,
                status=0,
                headers={},
                content=b'',
                request=req_ctx,
                elapsed=elapsed,
                metadata={
                    'error': str(e),
                    'error_type': type(e).__name__,
                    'elapsed': elapsed
                }
            )
            
            # Call response hooks with error context
            for hook in self._response_hooks:
                await hook(error_ctx)
            
            raise
    
    # Convenience methods for common HTTP methods
    
    async def get(
        self,
        url: str,
        *,
        params: Optional[Params] = None,
        headers: Optional[Headers] = None,
        **kwargs: Any,
    ) -> ClientResponse:
        """Send a GET request."""
        return await self.request('GET', url, params=params, headers=headers, **kwargs)
    
    async def post(
        self,
        url: str,
        *,
        data: Optional[RequestData] = None,
        json_data: Optional[Any] = None,
        headers: Optional[Headers] = None,
        **kwargs: Any,
    ) -> ClientResponse:
        """Send a POST request."""
        return await self.request(
            'POST',
            url,
            data=data,
            json_data=json_data,
            headers=headers,
            **kwargs
        )
    
    async def put(
        self,
        url: str,
        *,
        data: Optional[RequestData] = None,
        json_data: Optional[Any] = None,
        headers: Optional[Headers] = None,
        **kwargs: Any,
    ) -> ClientResponse:
        """Send a PUT request."""
        return await self.request(
            'PUT',
            url,
            data=data,
            json_data=json_data,
            headers=headers,
            **kwargs
        )
    
    async def delete(
        self,
        url: str,
        *,
        headers: Optional[Headers] = None,
        **kwargs: Any,
    ) -> ClientResponse:
        """Send a DELETE request."""
        return await self.request('DELETE', url, headers=headers, **kwargs)
    
    async def head(
        self,
        url: str,
        *,
        headers: Optional[Headers] = None,
        **kwargs: Any,
    ) -> ClientResponse:
        """Send a HEAD request."""
        return await self.request('HEAD', url, headers=headers, **kwargs)
    
    async def options(
        self,
        url: str,
        *,
        headers: Optional[Headers] = None,
        **kwargs: Any,
    ) -> ClientResponse:
        """Send an OPTIONS request."""
        return await self.request('OPTIONS', url, headers=headers, **kwargs)
    
    async def patch(
        self,
        url: str,
        *,
        data: Optional[RequestData] = None,
        json_data: Optional[Any] = None,
        headers: Optional[Headers] = None,
        **kwargs: Any,
    ) -> ClientResponse:
        """Send a PATCH request."""
        return await self.request(
            'PATCH',
            url,
            data=data,
            json_data=json_data,
            headers=headers,
            **kwargs
        )

    # Context manager support
    
    async def __aenter__(self) -> 'HTTPClient':
        """Enter the async context manager."""
        await self.setup()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit the async context manager."""
        await self.teardown()
