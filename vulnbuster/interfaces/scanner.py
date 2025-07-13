"""
Scanner Interface

This module defines the scanner interface and related types for the VulnBuster security scanner.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import re
import time
import uuid
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum, auto
from functools import wraps, lru_cache
from typing import (
    Any, Callable, Dict, List, Optional, Set, Tuple, Type, TypeVar, Union,
    Awaitable, AsyncIterator, AsyncGenerator, cast
)
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode, quote_plus, parse_qs

import aiohttp
import aiohttp.typedefs
import backoff
from backoff import expo
from typing_extensions import ParamSpec, TypeAlias, TypedDict, Literal

# Type variables for generic functions
T = TypeVar('T')
P = ParamSpec('P')
R = TypeVar('R')

# Type aliases
Url: TypeAlias = str
Headers: TypeAlias = Dict[str, str]
Params: TypeAlias = Dict[str, Union[str, int, float, bool, None]]
QueryParams: TypeAlias = Dict[str, List[str]]
JsonData: TypeAlias = Union[Dict[str, Any], List[Any], str, int, float, bool, None]
RequestData: TypeAlias = Union[Dict[str, Any], str, bytes, None]
RequestMethod = Literal['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
HttpMethod = Literal['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT']
RequestHook = Callable[['RequestContext'], Awaitable[None]]
ResponseHook = Callable[['ResponseContext'], Awaitable[None]]

# Constants
DEFAULT_USER_AGENT = 'VulnBuster/1.0 (+https://github.com/VulnBuster/VulnBuster)'
DEFAULT_TIMEOUT = 30.0
DEFAULT_RETRY_ATTEMPTS = 3
DEFAULT_RETRY_DELAY = 1.0
DEFAULT_MAX_RETRY_DELAY = 30.0
DEFAULT_RATE_LIMIT = 10  # requests per second
DEFAULT_CONCURRENCY = 10  # max concurrent requests
DEFAULT_MAX_REDIRECTS = 5

# Common HTTP headers
COMMON_HEADERS = {
    'User-Agent': DEFAULT_USER_AGENT,
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Cache-Control': 'max-age=0',
}

# Common MIME types
MIME_TYPES = {
    'html': 'text/html',
    'json': 'application/json',
    'xml': 'application/xml',
    'form': 'application/x-www-form-urlencoded',
    'multipart': 'multipart/form-data',
    'text': 'text/plain',
}

# Common file extensions (simplified for brevity)
FILE_EXTENSIONS = {
    'php', 'asp', 'aspx', 'jsp', 'do', 'action', 'cgi', 'pl', 'py', 'rb', 'go', 'js',
    'html', 'htm', 'xhtml', 'shtml', 'phtml', 'json', 'xml', 'yml', 'yaml', 'ini', 'conf',
    'config', 'env', 'htaccess', 'htpasswd', 'gitignore', 'dockerfile', 'makefile',
    'sql', 'db', 'log', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'
}

# Configure logging
logger = logging.getLogger(__name__)

@dataclass
class RequestContext:
    """Context for request hooks and tracking request state."""
    method: str
    url: str
    headers: Headers = field(default_factory=dict)
    params: Optional[Params] = None
    data: Optional[Union[Dict[str, Any], str, bytes]] = None
    json: Optional[JsonData] = None
    cookies: Optional[Dict[str, str]] = None
    allow_redirects: bool = True
    timeout: float = DEFAULT_TIMEOUT
    verify_ssl: bool = True
    proxy: Optional[str] = None
    tags: Optional[Dict[str, str]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    attempt: int = 1
    max_attempts: int = DEFAULT_RETRY_ATTEMPTS
    
    def __post_init__(self):
        """Initialize request context with default headers if not provided."""
        if not self.headers:
            self.headers = dict(COMMON_HEADERS)
        
        # Set Content-Type if not specified and data is provided
        if self.data and 'Content-Type' not in self.headers:
            if isinstance(self.data, (dict, list)):
                self.headers['Content-Type'] = 'application/x-www-form-urlencoded'
            elif isinstance(self.data, str):
                self.headers['Content-Type'] = 'text/plain'
            elif isinstance(self.data, bytes):
                self.headers['Content-Type'] = 'application/octet-stream'
        
        # Set Accept header if not specified
        if 'Accept' not in self.headers:
            self.headers['Accept'] = '*/*'

@dataclass
class ResponseContext:
    """Context for response hooks and tracking response state."""
    url: str
    status: int
    headers: Headers
    content: bytes
    request: RequestContext
    elapsed: float
    cookies: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    
    @property
    def text(self) -> str:
        """Get response content as text."""
        try:
            return self.content.decode('utf-8', errors='replace')
        except UnicodeDecodeError:
            return str(self.content)[2:-1]  # Convert bytes to string safely
    
    def json(self) -> Any:
        """Parse response content as JSON."""
        try:
            return json.loads(self.content)
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse JSON response: {e}")
            return None
    
    @property
    def is_success(self) -> bool:
        """Check if the response status indicates success (2xx)."""
        return 200 <= self.status < 300
    
    @property
    def is_redirect(self) -> bool:
        """Check if the response is a redirect (3xx)."""
        return 300 <= self.status < 400
    
    @property
    def is_client_error(self) -> bool:
        """Check if the response indicates a client error (4xx)."""
        return 400 <= self.status < 500
    
    @property
    def is_server_error(self) -> bool:
        """Check if the response indicates a server error (5xx)."""
        return 500 <= self.status < 600

class ScanStatus(str, Enum):
    """Scan status enumeration."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class ScanSeverity(str, Enum):
    """Vulnerability severity levels."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ScanConfidence(str, Enum):
    """Confidence level of a scan finding."""
    CERTAIN = "certain"
    FIRM = "firm"
    TENTATIVE = "tentative"

@dataclass
class ScanResult:
    """Container for scan results."""
    
    # Target information
    target: str
    start_time: float
    end_time: Optional[float] = None
    
    # Findings
    findings: List[Dict[str, Any]] = field(default_factory=list)
    
    # Metrics
    metrics: Dict[str, Any] = field(default_factory=dict)
    
    # Status
    status: ScanStatus = ScanStatus.PENDING
    error: Optional[str] = None
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def duration(self) -> Optional[float]:
        """Get the scan duration in seconds."""
        if self.end_time and self.start_time:
            return self.end_time - self.start_time
        return None
    
    def add_finding(
        self,
        title: str,
        description: str,
        severity: ScanSeverity,
        confidence: ScanConfidence,
        details: Optional[Dict[str, Any]] = None,
        request: Optional[Dict[str, Any]] = None,
        response: Optional[Dict[str, Any]] = None,
        remediation: Optional[str] = None,
        references: Optional[List[str]] = None,
        cwe: Optional[int] = None,
        cve: Optional[str] = None,
        cvss: Optional[float] = None,
        tags: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Add a new finding to the scan results.
        
        Args:
            title: Short title of the finding
            description: Detailed description of the finding
            severity: Severity level of the finding
            confidence: Confidence level of the finding
            details: Additional details about the finding
            request: The HTTP request that triggered the finding (if applicable)
            response: The HTTP response that contained the finding (if applicable)
            remediation: Recommended remediation steps
            references: List of reference URLs
            cwe: CWE ID (if applicable)
            cve: CVE ID (if applicable)
            cvss: CVSS score (if applicable)
            tags: List of tags for the finding
            
        Returns:
            The created finding dictionary
        """
        finding = {
            'id': f"finding_{len(self.findings) + 1}",
            'title': title,
            'description': description,
            'severity': severity.value,
            'confidence': confidence.value,
            'timestamp': self.end_time or time.time(),
            'details': details or {},
            'request': request,
            'response': response,
            'remediation': remediation,
            'references': references or [],
            'cwe': cwe,
            'cve': cve,
            'cvss': cvss,
            'tags': tags or []
        }
        
        self.findings.append(finding)
        return finding
    
    def add_metric(self, name: str, value: Any, tags: Optional[Dict[str, str]] = None) -> None:
        """Add a metric to the scan results.
        
        Args:
            name: Name of the metric
            value: Value of the metric
            tags: Optional tags for the metric
        """
        if name not in self.metrics:
            self.metrics[name] = []
            
        self.metrics[name].append({
            'value': value,
            'timestamp': time.time(),
            'tags': tags or {}
        })

@dataclass
class ScanContext:
    """Context for a scan operation."""
    
    # Target information
    target: str
    
    # Configuration
    config: Dict[str, Any]
    
    # Shared resources
    session: Any  # HTTP session or similar
    
    # State
    is_cancelled: bool = False
    
    # Progress tracking
    progress: float = 0.0  # 0.0 to 1.0
    status_message: str = ""
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def check_cancelled(self) -> bool:
        """Check if the scan has been cancelled."""
        return self.is_cancelled
    
    def update_progress(self, progress: float, message: str = "") -> None:
        """Update the scan progress.
        
        Args:
            progress: Progress value between 0.0 and 1.0
            message: Optional status message
        """
        self.progress = max(0.0, min(1.0, progress))
        if message:
            self.status_message = message

class Scanner(ABC):
    """Base class for scanner implementations."""
    
    # Scanner metadata
    name: str = "base_scanner"
    version: str = "0.1.0"
    description: str = "Base scanner class"
    
    # Supported scan types
    supported_scan_types: Set[str] = set()
    
    # Default configuration
    default_config: Dict[str, Any] = {}
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the scanner.
        
        Args:
            config: Scanner configuration
        """
        self.config = {**self.default_config, **(config or {})}
    
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
    
    async def setup(self) -> None:
        """Perform any necessary setup before scanning."""
        pass
    
    async def teardown(self) -> None:
        """Perform any necessary cleanup after scanning."""
        pass
    
    def validate_config(self) -> bool:
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


class PassiveScanner(Scanner):
    """Base class for passive scanners that don't send any requests."""
    
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


class ActiveScanner(Scanner):
    """Base class for active scanners that send requests to the target."""
    
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


# Import time at the end to avoid circular imports
import time
