"""
VulnBuster Configuration Module

This module provides a robust configuration management system for the VulnBuster
security testing framework. It handles loading, validating, and providing access
to configuration settings from multiple sources including environment variables,
configuration files, and direct Python code.

Key Features:
- Type-safe configuration with Pydantic models
- Environment variable support with automatic type conversion
- Configuration file support (JSON/YAML)
- Nested configuration structure
- Default values with sensible defaults
- Validation and error reporting

Example Usage:
    # Load configuration from file
    config = load_config("config.yaml")

    # Access configuration values
    timeout = config.scanner.timeout
    log_level = config.logging.level
"""

import json
import os
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Type, TypeVar, Union, get_args, get_origin
from enum import Enum
from pydantic import BaseModel, Field, validator, root_validator, ValidationError

# Type variable for generic type hints
T = TypeVar('T')

# Configure module logger
logger = logging.getLogger(__name__)

class LogLevel(str, Enum):
    """Available log levels for the application.
    
    Attributes:
        DEBUG: Detailed debug information
        INFO: General operational information
        WARNING: Indication of potential issues
        ERROR: Errors that might still allow the application to continue
        CRITICAL: Severe errors that prevent the application from continuing
    """
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    
    @classmethod
    def _missing_(cls, value: object) -> 'LogLevel':
        """Handle case-insensitive log level lookup."""
        if not isinstance(value, str):
            return None
            
        value = value.upper()
        for level in cls:
            if level.value == value:
                return level
        return None

class ScanMode(str, Enum):
    """Available scan modes for the application.
    
    Attributes:
        WEB: Web application scanning
        NETWORK: Network infrastructure scanning
        MOBILE: Mobile application scanning
        CLOUD: Cloud infrastructure scanning
        ALL: Enable all scan modes
    """
    WEB = "web"
    NETWORK = "network"
    MOBILE = "mobile"
    CLOUD = "cloud"
    ALL = "all"
    
    @classmethod
    def _missing_(cls, value: object) -> 'ScanMode':
        """Handle case-insensitive scan mode lookup."""
        if not isinstance(value, str):
            return None
            
        value = value.lower()
        for mode in cls:
            if mode.value == value:
                return mode
        return None

class AuthConfig(BaseModel):
    """Authentication configuration for the VulnBuster application.
    
    Attributes:
        enabled: Whether authentication is enabled
        username: Username for basic authentication
        password: Password for basic authentication
        token: API token for token-based authentication
        oauth_config: Configuration for OAuth authentication
    """
    enabled: bool = Field(
        default=True,
        description="Enable or disable authentication"
    )
    username: Optional[str] = Field(
        default=None,
        description="Username for basic authentication",
        min_length=1
    )
    password: Optional[str] = Field(
        default=None,
        description="Password for basic authentication",
        min_length=1
    )
    token: Optional[str] = Field(
        default=None,
        description="API token for token-based authentication",
        min_length=1
    )
    oauth_config: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Configuration for OAuth authentication"
    )
    
    @validator('oauth_config')
    def validate_oauth_config(cls, v: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Validate OAuth configuration if provided."""
        if v is not None and not isinstance(v, dict):
            raise ValueError("OAuth config must be a dictionary")
        return v

class LoggingConfig(BaseModel):
    """Logging configuration for the application.
    
    Attributes:
        level: Minimum logging level
        file: Path to the log file (if file logging is enabled)
        max_size: Maximum log file size in MB before rotation
        backup_count: Number of backup log files to keep
        console: Whether to log to console
        format: Log message format string
    """
    level: LogLevel = Field(
        default=LogLevel.INFO,
        description="Minimum logging level"
    )
    file: Optional[Path] = Field(
        default=None,
        description="Path to the log file (if file logging is enabled)"
    )
    max_size: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Maximum log file size in MB before rotation"
    )
    backup_count: int = Field(
        default=5,
        ge=0,
        description="Number of backup log files to keep"
    )
    console: bool = Field(
        default=True,
        description="Whether to log to console"
    )
    format: str = Field(
        default="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        description="Log message format string"
    )
    
    @validator('file')
    def validate_log_file(cls, v: Optional[Path]) -> Optional[Path]:
        """Validate log file path and ensure directory exists."""
        if v is not None:
            try:
                v = v.absolute()
                v.parent.mkdir(parents=True, exist_ok=True)
                return v
            except (OSError, TypeError) as e:
                logger.warning(f"Invalid log file path '{v}': {e}")
                return None
        return v

class DatabaseConfig(BaseModel):
    """Database configuration for the application.
    
    Attributes:
        url: Database connection URL
        echo: Whether to log all SQL statements
        pool_size: The size of the database connection pool
        max_overflow: Maximum overflow size of the connection pool
        connect_args: Additional connection arguments
        pool_pre_ping: Enable connection liveness checks
        pool_recycle: Recycle connections after this many seconds
    """
    url: str = Field(
        default="sqlite:///vulnbuster.db",
        description="Database connection URL (e.g., sqlite:///vulnbuster.db or postgresql://user:pass@localhost/dbname)"
    )
    echo: bool = Field(
        default=False,
        description="If True, log all SQL statements"
    )
    pool_size: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Size of the database connection pool"
    )
    max_overflow: int = Field(
        default=20,
        ge=0,
        description="Maximum overflow size of the connection pool"
    )
    connect_args: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional connection arguments passed to the database driver"
    )
    pool_pre_ping: bool = Field(
        default=True,
        description="Enable connection liveness checks"
    )
    pool_recycle: int = Field(
        default=3600,
        ge=0,
        description="Recycle connections after this many seconds"
    )
    
    @validator('url')
    def validate_url(cls, v: str) -> str:
        """Validate database URL format."""
        if not v:
            raise ValueError("Database URL cannot be empty")
        
        # Basic URL validation
        if '://' not in v:
            raise ValueError("Invalid database URL format. Must be in format 'dialect+driver://user:pass@host/dbname'")
        
        return v

class GraphQLConfig(BaseModel):
    """Configuration for the GraphQL scanner module.
    
    Attributes:
        enabled: Enable/disable GraphQL scanning
        max_depth: Maximum query depth for GraphQL introspection
        max_queries: Maximum number of queries to generate
        include_deprecated: Include deprecated fields in scanning
        test_mutations: Test GraphQL mutations
        test_subscriptions: Test GraphQL subscriptions
        fuzz_parameters: Enable parameter fuzzing
        fuzz_depth: Depth of fuzzing for nested objects
        ai_suggest_chains: Enable AI-suggested query chains
        timeout: Request timeout in seconds
        batch_size: Number of queries to send in a batch
    """
    enabled: bool = Field(
        default=True,
        description="Enable or disable GraphQL scanning"
    )
    max_depth: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Maximum query depth for GraphQL introspection"
    )
    max_queries: int = Field(
        default=50,
        ge=1,
        le=1000,
        description="Maximum number of queries to generate"
    )
    include_deprecated: bool = Field(
        default=False,
        description="Include deprecated fields in scanning"
    )
    test_mutations: bool = Field(
        default=False,
        description="Test GraphQL mutations (use with caution)"
    )
    test_subscriptions: bool = Field(
        default=False,
        description="Test GraphQL subscriptions (experimental)"
    )
    fuzz_parameters: bool = Field(
        default=True,
        description="Enable parameter fuzzing"
    )
    fuzz_depth: int = Field(
        default=2,
        ge=1,
        le=5,
        description="Depth of fuzzing for nested objects"
    )
    ai_suggest_chains: bool = Field(
        default=True,
        description="Enable AI-suggested query chains"
    )
    timeout: int = Field(
        default=30,
        ge=1,
        description="Request timeout in seconds"
    )
    batch_size: int = Field(
        default=5,
        ge=1,
        le=50,
        description="Number of queries to send in a batch"
    )

class MFAConfig(BaseModel):
    """Configuration for the Multi-Factor Authentication testing module.
    
    Attributes:
        enabled: Enable/disable MFA testing
        test_bypass: Test MFA bypass techniques
        test_otp_reuse: Test OTP code reuse
        test_bruteforce: Test OTP brute force attempts
        max_bruteforce_attempts: Maximum brute force attempts
        detect_otp_fields: Auto-detect OTP fields
        validate_mfa_mechanisms: Validate MFA implementations
        fingerprint_bypass_techniques: Fingerprint bypass techniques
        rate_limit: Requests per second for MFA testing
        timeout: Request timeout in seconds
    """
    enabled: bool = Field(
        default=True,
        description="Enable or disable MFA testing"
    )
    test_bypass: bool = Field(
        default=True,
        description="Test MFA bypass techniques"
    )
    test_otp_reuse: bool = Field(
        default=True,
        description="Test if OTP codes can be reused"
    )
    test_bruteforce: bool = Field(
        default=True,
        description="Test OTP brute force attempts"
    )
    max_bruteforce_attempts: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Maximum number of brute force attempts"
    )
    detect_otp_fields: bool = Field(
        default=True,
        description="Auto-detect OTP fields in web forms"
    )
    validate_mfa_mechanisms: bool = Field(
        default=True,
        description="Validate MFA implementation security"
    )
    fingerprint_bypass_techniques: bool = Field(
        default=True,
        description="Fingerprint bypass techniques"
    )
    rate_limit: int = Field(
        default=5,
        ge=1,
        le=100,
        description="Maximum requests per second for MFA testing"
    )
    timeout: int = Field(
        default=30,
        ge=1,
        description="Request timeout in seconds"
    )
    
    @validator('max_bruteforce_attempts')
    def validate_max_attempts(cls, v: int, values: Dict[str, Any]) -> int:
        """Validate maximum brute force attempts."""
        if v > 50 and not values.get('test_bruteforce'):
            logger.warning(
                "High max_bruteforce_attempts (%d) with test_bruteforce disabled. "
                "Set test_bruteforce=True to enable testing.", v
            )
        return v

class OpenAPIConfig(BaseModel):
    """Configuration for the OpenAPI/Swagger scanner module.
    
    Attributes:
        enabled: Enable/disable OpenAPI scanning
        auto_discover: Auto-discover OpenAPI/Swagger specs
        test_unauthenticated: Test unauthenticated endpoints
        test_unauthorized: Test unauthorized access
        fuzz_parameters: Enable parameter fuzzing
        max_test_cases: Maximum test cases to generate
        include_optional_params: Include optional parameters in tests
        test_invalid_types: Test with invalid parameter types
        test_sql_injection: Test for SQL injection
        test_xss: Test for XSS vulnerabilities
        request_timeout: Request timeout in seconds
        rate_limit: Maximum requests per second
        follow_redirects: Follow HTTP redirects
        verify_ssl: Verify SSL certificates
    """
    enabled: bool = Field(
        default=True,
        description="Enable or disable OpenAPI scanning"
    )
    auto_discover: bool = Field(
        default=True,
        description="Auto-discover OpenAPI/Swagger specifications"
    )
    test_unauthenticated: bool = Field(
        default=True,
        description="Test unauthenticated endpoints"
    )
    test_unauthorized: bool = Field(
        default=True,
        description="Test unauthorized access"
    )
    fuzz_parameters: bool = Field(
        default=True,
        description="Enable parameter fuzzing"
    )
    max_test_cases: int = Field(
        default=100,
        ge=1,
        le=1000,
        description="Maximum number of test cases to generate"
    )
    include_optional_params: bool = Field(
        default=True,
        description="Include optional parameters in generated test cases"
    )
    test_invalid_types: bool = Field(
        default=True,
        description="Test with invalid parameter types"
    )
    test_sql_injection: bool = Field(
        default=True,
        description="Test for SQL injection vulnerabilities"
    )
    test_xss: bool = Field(
        default=True,
        description="Test for XSS (Cross-Site Scripting) vulnerabilities"
    )
    request_timeout: int = Field(
        default=30,
        ge=1,
        description="Request timeout in seconds"
    )
    rate_limit: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Maximum requests per second"
    )
    follow_redirects: bool = Field(
        default=True,
        description="Follow HTTP redirects"
    )
    verify_ssl: bool = Field(
        default=True,
        description="Verify SSL certificates"
    )
    
    @validator('max_test_cases')
    def validate_max_test_cases(cls, v: int) -> int:
        """Warn about potential performance impact with many test cases."""
        if v > 500:
            logger.warning(
                "High max_test_cases (%d) may impact performance. "
                "Consider reducing this number for large APIs.", v
            )
        return v

class ScannerConfig(BaseModel):
    """Scanner configuration for the VulnBuster application.
    
    This class contains configuration options for the vulnerability scanner,
    including general settings and module-specific configurations.
    
    Attributes:
        threads: Number of concurrent scanner threads
        timeout: Default request timeout in seconds
        retries: Number of retry attempts for failed requests
        user_agent: User-Agent string for HTTP requests
        rate_limit: Maximum requests per second
        proxy: Optional proxy configuration (e.g., http://proxy:port)
        follow_redirects: Whether to follow HTTP redirects
        verify_ssl: Verify SSL certificates
        graphql: GraphQL scanner configuration
        mfa: MFA testing configuration
        openapi: OpenAPI/Swagger scanner configuration
    """
    # General settings
    threads: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Number of concurrent scanner threads"
    )
    timeout: int = Field(
        default=30,
        ge=1,
        description="Default request timeout in seconds"
    )
    retries: int = Field(
        default=3,
        ge=0,
        le=10,
        description="Number of retry attempts for failed requests"
    )
    user_agent: str = Field(
        default="VulnBuster/1.0",
        description="User-Agent string for HTTP requests"
    )
    rate_limit: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Maximum requests per second"
    )
    proxy: Optional[str] = Field(
        default=None,
        description="Proxy configuration (e.g., http://proxy:port)",
        regex=r'^https?://[\w.-]+(:\d+)?$'
    )
    follow_redirects: bool = Field(
        default=True,
        description="Whether to follow HTTP redirects"
    )
    verify_ssl: bool = Field(
        default=True,
        description="Verify SSL certificates"
    )
    
    # Module configurations
    graphql: GraphQLConfig = Field(
        default_factory=GraphQLConfig,
        description="GraphQL scanner configuration"
    )
    mfa: MFAConfig = Field(
        default_factory=MFAConfig,
        description="MFA testing configuration"
    )
    openapi: OpenAPIConfig = Field(
        default_factory=OpenAPIConfig,
        description="OpenAPI/Swagger scanner configuration"
    )
    
    @validator('proxy')
    def validate_proxy(cls, v: Optional[str]) -> Optional[str]:
        """Validate proxy URL format if provided."""
        if v and not v.startswith(('http://', 'https://')):
            raise ValueError("Proxy URL must start with http:// or https://")
        return v

class PluginConfig(BaseModel):
    """Configuration for a VulnBuster plugin.
    
    Attributes:
        enabled: Whether the plugin is enabled
        config: Plugin-specific configuration options
        priority: Execution priority (lower numbers execute first)
        version: Minimum required plugin version
    """
    enabled: bool = Field(
        default=True,
        description="Enable or disable the plugin"
    )
    config: Dict[str, Any] = Field(
        default_factory=dict,
        description="Plugin-specific configuration options"
    )
    priority: int = Field(
        default=50,
        ge=1,
        le=100,
        description="Execution priority (lower numbers execute first)"
    )
    version: Optional[str] = Field(
        default=None,
        description="Minimum required plugin version",
        regex=r'^\d+(\.\d+){0,2}(-[a-zA-Z0-9.]+)?$'
    )
    
    @validator('config')
    def validate_config(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        """Validate plugin configuration."""
        if not isinstance(v, dict):
            raise ValueError("Plugin config must be a dictionary")
        return v
    
    @validator('version')
    def validate_version(cls, v: Optional[str]) -> Optional[str]:
        """Normalize version string if provided."""
        if v is not None:
            return v.strip().lstrip('v')
        return v

class Config(BaseModel):
    """Main configuration model for VulnBuster."""
    # Core settings
    debug: bool = False
    mode: ScanMode = ScanMode.WEB
    target: str
    
    # Authentication
    auth: AuthConfig = Field(default_factory=AuthConfig)
    
    # Logging
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    
    # Database
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    
    # Scanner
    scanner: ScannerConfig = Field(default_factory=ScannerConfig)
    
    # Plugins
    
    class Config:
        extra = "forbid"  # Don't allow extra fields
        validate_assignment = True  # Validate on attribute assignment
        arbitrary_types_allowed = True  # Allow Path objects, etc.
        json_encoders = {
            Path: str,  # Convert Path objects to strings in .json()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Config':
        """Create a Config instance from a dictionary.
        
        Args:
            data: Dictionary containing configuration data
            
        Returns:
            Config: A new Config instance
            
        Raises:
            ValidationError: If the configuration is invalid
        """
        return cls.parse_obj(data)
    
    @classmethod
    def from_file(cls, file_path: Union[str, Path]) -> 'Config':
        """Load configuration from a JSON or YAML file.
        
        Args:
            file_path: Path to the configuration file
            
        Returns:
            Config: A new Config instance
            
        Raises:
            FileNotFoundError: If the file doesn't exist
            ValidationError: If the configuration is invalid
        """
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"Config file not found: {file_path}")
            
        suffix = file_path.suffix.lower()
        
        try:
            if suffix in ('.yaml', '.yml'):
                import yaml
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
            elif suffix == '.json':
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            else:
                raise ValueError(f"Unsupported config file format: {suffix}. Use .json or .yaml")
                
            return cls.from_dict(data)
            
        except Exception as e:
            raise ValueError(f"Error loading config from {file_path}: {e}") from e
    
    def to_dict(self, **kwargs) -> Dict[str, Any]:
        """Convert the configuration to a dictionary.
        
        Args:
            **kwargs: Additional arguments to pass to dict()
            
        Returns:
            Dict[str, Any]: Dictionary representation of the configuration
        """
        return self.dict(**kwargs)
    
    def to_file(self, file_path: Union[str, Path], **kwargs) -> None:
        """Save the configuration to a file.
        
        Args:
            file_path: Path to save the configuration file
            **kwargs: Additional arguments to pass to json() or yaml.dump()
            
        Raises:
            ValueError: If the file format is not supported
        """
        file_path = Path(file_path)
        suffix = file_path.suffix.lower()
        
        try:
            if suffix in ('.yaml', '.yml'):
                import yaml
                data = self.dict(**kwargs)
                with open(file_path, 'w', encoding='utf-8') as f:
                    yaml.safe_dump(data, f, default_flow_style=False, **kwargs)
            elif suffix == '.json':
                with open(file_path, 'w', encoding='utf-8') as f:
                    self.json(f, **kwargs)
            else:
                raise ValueError(f"Unsupported config file format: {suffix}. Use .json or .yaml")
                
        except Exception as e:
            raise ValueError(f"Error saving config to {file_path}: {e}") from e
    
    @root_validator(pre=True)
    def load_from_env(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        """Load values from environment variables if not explicitly set.
        
        This validator processes environment variables that match the pattern
        VULNBUSTER_* and maps them to configuration values.
        
        Args:
            values: Current configuration values
            
        Returns:
            Dict[str, Any]: Updated configuration values
            
        Raises:
            ValueError: If an environment variable has an invalid value
        """
        env_mapping = {
            # Core settings
            'debug': ('VULNBUSTER_DEBUG', bool, False),
            'target': ('VULNBUSTER_TARGET', str, None),
            'mode': ('VULNBUSTER_MODE', ScanMode, ScanMode.WEB),
            
            # Logging
            'logging.level': ('VULNBUSTER_LOG_LEVEL', LogLevel, LogLevel.INFO),
            'logging.file': ('VULNBUSTER_LOG_FILE', str, None),
            'logging.max_size': ('VULNBUSTER_LOG_MAX_SIZE', int, 10),
            'logging.backup_count': ('VULNBUSTER_LOG_BACKUP_COUNT', int, 5),
            'logging.console': ('VULNBUSTER_LOG_CONSOLE', bool, True),
            
            # Authentication
            'auth.enabled': ('VULNBUSTER_AUTH_ENABLED', bool, True),
            'auth.username': ('VULNBUSTER_AUTH_USERNAME', str, None),
            'auth.password': ('VULNBUSTER_AUTH_PASSWORD', str, None),
            'auth.token': ('VULNBUSTER_AUTH_TOKEN', str, None),
            
            # Scanner
            'scanner.threads': ('VULNBUSTER_THREADS', int, 10),
            'scanner.timeout': ('VULNBUSTER_TIMEOUT', int, 30),
            'scanner.retries': ('VULNBUSTER_RETRIES', int, 3),
            'scanner.rate_limit': ('VULNBUSTER_RATE_LIMIT', int, 10),
            'scanner.user_agent': ('VULNBUSTER_USER_AGENT', str, 'VulnBuster/1.0'),
            'scanner.proxy': ('VULNBUSTER_PROXY', str, None),
            'scanner.follow_redirects': ('VULNBUSTER_FOLLOW_REDIRECTS', bool, True),
            'scanner.verify_ssl': ('VULNBUSTER_VERIFY_SSL', bool, True),
            
            # GraphQL Scanner
            'scanner.graphql.enabled': ('VULNBUSTER_GRAPHQL_ENABLED', bool, True),
            'scanner.graphql.max_depth': ('VULNBUSTER_GRAPHQL_MAX_DEPTH', int, 5),
            'scanner.graphql.max_queries': ('VULNBUSTER_GRAPHQL_MAX_QUERIES', int, 50),
            'scanner.graphql.include_deprecated': ('VULNBUSTER_GRAPHQL_INCLUDE_DEPRECATED', bool, False),
            'scanner.graphql.test_mutations': ('VULNBUSTER_GRAPHQL_TEST_MUTATIONS', bool, False),
            'scanner.graphql.test_subscriptions': ('VULNBUSTER_GRAPHQL_TEST_SUBSCRIPTIONS', bool, False),
            'scanner.graphql.fuzz_parameters': ('VULNBUSTER_GRAPHQL_FUZZ_PARAMETERS', bool, True),
            'scanner.graphql.fuzz_depth': ('VULNBUSTER_GRAPHQL_FUZZ_DEPTH', int, 2),
            'scanner.graphql.ai_suggest_chains': ('VULNBUSTER_GRAPHQL_AI_SUGGEST_CHAINS', bool, True),
            'scanner.graphql.timeout': ('VULNBUSTER_GRAPHQL_TIMEOUT', int, 30),
            'scanner.graphql.batch_size': ('VULNBUSTER_GRAPHQL_BATCH_SIZE', int, 5),
            
            # MFA Scanner
            'scanner.mfa.enabled': ('VULNBUSTER_MFA_ENABLED', bool, True),
            'scanner.mfa.test_bypass': ('VULNBUSTER_MFA_TEST_BYPASS', bool, True),
            'scanner.mfa.test_otp_reuse': ('VULNBUSTER_MFA_TEST_OTP_REUSE', bool, True),
            'scanner.mfa.test_bruteforce': ('VULNBUSTER_MFA_TEST_BRUTEFORCE', bool, True),
            'scanner.mfa.max_bruteforce_attempts': ('VULNBUSTER_MFA_MAX_BRUTEFORCE_ATTEMPTS', int, 10),
            'scanner.mfa.detect_otp_fields': ('VULNBUSTER_MFA_DETECT_OTP_FIELDS', bool, True),
            'scanner.mfa.validate_mfa_mechanisms': ('VULNBUSTER_MFA_VALIDATE_MECHANISMS', bool, True),
            'scanner.mfa.fingerprint_bypass_techniques': ('VULNBUSTER_MFA_FINGERPRINT_BYPASS', bool, True),
            'scanner.mfa.rate_limit': ('VULNBUSTER_MFA_RATE_LIMIT', int, 5),
            'scanner.mfa.timeout': ('VULNBUSTER_MFA_TIMEOUT', int, 30),
            
            # OpenAPI Scanner
            'scanner.openapi.enabled': ('VULNBUSTER_OPENAPI_ENABLED', bool, True),
            'scanner.openapi.auto_discover': ('VULNBUSTER_OPENAPI_AUTO_DISCOVER', bool, True),
            'scanner.openapi.test_unauthenticated': ('VULNBUSTER_OPENAPI_TEST_UNAUTHENTICATED', bool, True),
            'scanner.openapi.test_unauthorized': ('VULNBUSTER_OPENAPI_TEST_UNAUTHORIZED', bool, True),
            'scanner.openapi.fuzz_parameters': ('VULNBUSTER_OPENAPI_FUZZ_PARAMETERS', bool, True),
            'scanner.openapi.max_test_cases': ('VULNBUSTER_OPENAPI_MAX_TEST_CASES', int, 100),
            'scanner.openapi.include_optional_params': ('VULNBUSTER_OPENAPI_INCLUDE_OPTIONAL_PARAMS', bool, True),
            'scanner.openapi.test_invalid_types': ('VULNBUSTER_OPENAPI_TEST_INVALID_TYPES', bool, True),
            'scanner.openapi.test_sql_injection': ('VULNBUSTER_OPENAPI_TEST_SQL_INJECTION', bool, True),
            'scanner.openapi.test_xss': ('VULNBUSTER_OPENAPI_TEST_XSS', bool, True),
            'scanner.openapi.request_timeout': ('VULNBUSTER_OPENAPI_REQUEST_TIMEOUT', int, 30),
            'scanner.openapi.rate_limit': ('VULNBUSTER_OPENAPI_RATE_LIMIT', int, 10),
            'scanner.openapi.follow_redirects': ('VULNBUSTER_OPENAPI_FOLLOW_REDIRECTS', bool, True),
            'scanner.openapi.verify_ssl': ('VULNBUSTER_OPENAPI_VERIFY_SSL', bool, True),
            
            # Database
            'database.url': ('VULNBUSTER_DATABASE_URL', str, 'sqlite:///vulnbuster.db'),
            'database.echo': ('VULNBUSTER_DATABASE_ECHO', bool, False),
            'database.pool_size': ('VULNBUSTER_DATABASE_POOL_SIZE', int, 10),
            'database.max_overflow': ('VULNBUSTER_DATABASE_MAX_OVERFLOW', int, 20),
            'database.pool_pre_ping': ('VULNBUSTER_DATABASE_POOL_PRE_PING', bool, True),
            'database.pool_recycle': ('VULNBUSTER_DATABASE_POOL_RECYCLE', int, 3600),
        }
        
        # Process environment variables
        for field_path, (env_var, field_type, default) in env_mapping.items():
            # Skip if already set in values
            if field_path in values:
                continue
                
            # Check if environment variable exists
            if env_var not in os.environ:
                continue
                
            value = os.environ[env_var]
            
            try:
                # Handle different types
                if field_type == bool:
                    # Handle boolean values from strings
                    if value.lower() in ('true', '1', 't', 'y', 'yes'):
                        parsed_value = True
                    elif value.lower() in ('false', '0', 'f', 'n', 'no'):
                        parsed_value = False
                    else:
                        raise ValueError(f"Invalid boolean value: {value}")
                elif issubclass(field_type, Enum):
                    # Handle enum values
                    parsed_value = field_type(value)
                else:
                    # Handle basic types (int, float, str, etc.)
                    parsed_value = field_type(value)
                
                # Set the value
                set_nested_value(values, field_path, parsed_value)
                
            except (ValueError, KeyError, TypeError) as e:
                logger.warning("Invalid value for %s: %s", env_var, e)
                if default is not None:
                    set_nested_value(values, field_path, default)
        
        return values

def get_nested_value(d: Dict[str, Any], path: str, default: Any = None) -> Any:
    """Get a nested dictionary value using dot notation.
    
    Args:
        d: Dictionary to get value from
        path: Dot-separated path to the value (e.g., 'scanner.timeout')
        default: Default value if path doesn't exist
        
    Returns:
        The value at the specified path, or default if not found
    """
    keys = path.split('.')
    try:
        for key in keys:
            d = d[key]
        return d
    except (KeyError, TypeError):
        return default

def load_config(file_path: Optional[Union[str, Path]] = None, **kwargs) -> 'Config':
    """Load configuration from a file or environment variables.
    
    This is the main entry point for loading configuration. It will:
    1. Load from the specified file if provided
    2. Fall back to environment variables
    3. Use default values for any missing settings
    
    Args:
        file_path: Path to a JSON or YAML configuration file
        **kwargs: Additional configuration overrides
        
    Returns:
        Config: A new Config instance
        
    Raises:
        FileNotFoundError: If the specified config file doesn't exist
        ValidationError: If the configuration is invalid
    """
    # If file path is provided, load from file
    if file_path:
        config = Config.from_file(file_path)
    else:
        # Try to load from default locations if no file specified
        default_paths = [
            Path("vulnbuster.yaml"),
            Path("vulnbuster.yml"),
            Path("config/vulnbuster.yaml"),
            Path("config/vulnbuster.yml"),
            Path("/etc/vulnbuster/config.yaml"),
            Path.home() / ".config/vulnbuster/config.yaml",
        ]
        
        config = None
        for path in default_paths:
            if path.exists():
                try:
                    config = Config.from_file(path)
                    logger.info("Loaded configuration from %s", path)
                    break
                except Exception as e:
                    logger.warning("Error loading config from %s: %s", path, e)
        
        # Fall back to environment variables and defaults
        if config is None:
            config = Config(
                target=os.environ.get("VULNBUSTER_TARGET", "http://localhost"),
                **kwargs
            )
            logger.info("Using default configuration with environment overrides")
    
    # Apply any additional overrides
    if kwargs:
        for key, value in kwargs.items():
            setattr(config, key, value)
    
    return config


def get_config() -> 'Config':
    """Get the current configuration instance."""
    return load_config()


# Initialize default config with required fields
default_config = Config(target="http://localhost")
