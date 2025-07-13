""
Plugin Interface

This module defines the base plugin interface and related types.
"""

from abc import ABC, abstractmethod
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Type, TypeVar, Generic
from dataclasses import dataclass

from ..core import VulnBusterApp

T = TypeVar('T')

class PluginType(Enum):
    """Enumeration of plugin types."""
    SCANNER = auto()
    REPORTER = auto()
    AUTH = auto()
    PARSER = auto()
    EXPLOIT = auto()
    UTILITY = auto()
    CUSTOM = auto()

class Plugin(ABC):
    """Base class for all VulnBuster plugins."""
    
    # Plugin metadata
    name: str = "base_plugin"
    version: str = "0.1.0"
    description: str = "Base plugin class"
    plugin_type: PluginType = PluginType.CUSTOM
    
    # Plugin configuration schema (can be overridden by subclasses)
    config_schema: Dict = {}
    
    def __init__(self, app: Optional[VulnBusterApp] = None, **kwargs):
        """Initialize the plugin.
        
        Args:
            app: The VulnBuster application instance.
            **kwargs: Additional configuration options.
        """
        self.app = app
        self.config = kwargs
        self._enabled = True
    
    @property
    def is_enabled(self) -> bool:
        """Check if the plugin is enabled."""
        return self._enabled
    
    def enable(self) -> None:
        """Enable the plugin."""
        self._enabled = True
    
    def disable(self) -> None:
        """Disable the plugin."""
        self._enabled = False
    
    async def initialize(self) -> None:
        """Initialize the plugin.
        
        This method is called when the application starts up.
        Subclasses should override this to perform any initialization.
        """
        pass
    
    async def shutdown(self) -> None:
        """Shut down the plugin.
        
        This method is called when the application is shutting down.
        Subclasses should override this to perform any cleanup.
        """
        pass
    
    def validate_config(self) -> bool:
        """Validate the plugin configuration.
        
        Returns:
            bool: True if the configuration is valid, False otherwise.
        """
        # Default implementation checks required fields in config_schema
        if not self.config_schema:
            return True
            
        for field, field_info in self.config_schema.items():
            if field_info.get('required', False) and field not in self.config:
                return False
                
        return True
    
    def __str__(self) -> str:
        """Return a string representation of the plugin."""
        return f"{self.name} v{self.version} ({self.plugin_type.name})"


class Scanner(Plugin):
    """Base class for scanner plugins."""
    
    plugin_type = PluginType.SCANNER
    
    @abstractmethod
    async def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Perform a scan of the target.
        
        Args:
            target: The target to scan (URL, hostname, IP, etc.)
            **kwargs: Additional scan options.
            
        Returns:
            A dictionary containing scan results.
        """
        pass


class Reporter(Plugin):
    """Base class for reporter plugins."""
    
    plugin_type = PluginType.REPORTER
    
    @abstractmethod
    async def generate_report(self, scan_results: List[Dict], **kwargs) -> str:
        """Generate a report from scan results.
        
        Args:
            scan_results: List of scan results.
            **kwargs: Additional report options.
            
        Returns:
            The generated report as a string.
        """
        pass


class AuthProvider(Plugin):
    """Base class for authentication provider plugins."""
    
    plugin_type = PluginType.AUTH
    
    @abstractmethod
    async def authenticate(self, **kwargs) -> Dict[str, Any]:
        """Authenticate with the target.
        
        Args:
            **kwargs: Authentication parameters.
            
        Returns:
            A dictionary containing authentication tokens/credentials.
        """
        pass
    
    @abstractmethod
    async def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        """Refresh an authentication token.
        
        Args:
            refresh_token: The refresh token.
            
        Returns:
            A new set of tokens/credentials.
        """
        pass


@dataclass
class PluginInfo:
    """Container for plugin metadata."""
    
    name: str
    version: str
    description: str
    plugin_type: PluginType
    plugin_class: Type[Plugin]
    config_schema: Dict = None
    
    @classmethod
    def from_plugin(cls, plugin_class: Type[Plugin]) -> 'PluginInfo':
        """Create a PluginInfo instance from a plugin class."""
        return cls(
            name=plugin_class.name,
            version=plugin_class.version,
            description=plugin_class.description,
            plugin_type=plugin_class.plugin_type,
            plugin_class=plugin_class,
            config_schema=getattr(plugin_class, 'config_schema', {})
        )
