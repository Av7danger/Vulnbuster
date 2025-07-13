"""
Enhanced Plugin System

This module provides an enhanced plugin system for VulnBuster with improved
scanner integration, type hints, and better error handling.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import (
    Any, Awaitable, Callable, Dict, Generic, List, Optional, 
    Set, Type, TypeVar, Union, get_type_hints
)

from .scanner import (
    ScanResult, ScanContext, ScanSeverity, ScanConfidence,
    DEFAULT_TIMEOUT, DEFAULT_RETRY_ATTEMPTS, DEFAULT_RATE_LIMIT,
    DEFAULT_CONCURRENCY, DEFAULT_MAX_REDIRECTS
)
from .http_client import HTTPClient
from ..core import VulnBusterApp

# Type variables
P = TypeVar('P', bound='Plugin')

class PluginType(Enum):
    """Enumeration of plugin types with hierarchical support."""
    # Core plugin types
    SCANNER = "scanner"
    REPORTER = "reporter"
    AUTH = "auth"
    PARSER = "parser"
    EXPLOIT = "exploit"
    UTILITY = "utility"
    CUSTOM = "custom"
    
    # Scanner sub-types
    SCANNER_ACTIVE = "scanner.active"
    SCANNER_PASSIVE = "scanner.passive"
    SCANNER_AUTH = "scanner.auth"
    
    # Reporter sub-types
    REPORTER_HTML = "reporter.html"
    REPORTER_JSON = "reporter.json"
    REPORTER_MARKDOWN = "reporter.markdown"
    
    def is_scanner(self) -> bool:
        """Check if this is a scanner plugin type."""
        return self.value.startswith("scanner")
    
    def is_reporter(self) -> bool:
        """Check if this is a reporter plugin type."""
        return self.value.startswith("reporter")


class Plugin(ABC):
    """Base class for all VulnBuster plugins.
    
    Plugins are the building blocks of VulnBuster's extensible architecture.
    They can add new scanning capabilities, reporting formats, authentication
    methods, and more.
    """
    
    # Plugin metadata
    name: str = "base_plugin"
    version: str = "0.1.0"
    description: str = "Base plugin class"
    author: str = ""
    license: str = "MIT"
    
    # Plugin type and compatibility
    plugin_type: PluginType = PluginType.CUSTOM
    min_vulnbuster_version: str = "0.1.0"
    
    # Dependencies (package_name: version_spec)
    dependencies: Dict[str, str] = {}
    
    # Plugin configuration schema (JSON Schema format)
    config_schema: Dict[str, Any] = {
        "type": "object",
        "properties": {
            "enabled": {"type": "boolean", "default": True},
            "priority": {"type": "integer", "default": 100, "minimum": 0, "maximum": 1000}
        },
        "additionalProperties": True
    }
    
    def __init__(self, app: Optional[VulnBusterApp] = None, **kwargs):
        """Initialize the plugin.
        
        Args:
            app: The VulnBuster application instance.
            **kwargs: Additional configuration options that will be merged with defaults.
        """
        self.app = app
        self._logger = logging.getLogger(f"vulnbuster.plugins.{self.name}")
        self._enabled = True
        self._initialized = False
        
        # Process configuration
        self.config = self._process_config(kwargs)
        
        # Initialize HTTP client if needed
        self._http: Optional[HTTPClient] = None
    
    def _process_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Process and validate plugin configuration.
        
        Args:
            config: Raw configuration dictionary.
            
        Returns:
            Processed configuration with defaults applied.
        """
        # TODO: Add JSON Schema validation
        processed = {}
        
        # Apply defaults from schema
        if "properties" in self.config_schema:
            for prop, schema in self.config_schema["properties"].items():
                if "default" in schema:
                    processed[prop] = schema["default"]
        
        # Override with provided config
        processed.update(config)
        return processed
    
    @property
    def http(self) -> HTTPClient:
        """Get the HTTP client for this plugin."""
        if self._http is None:
            # Create a new HTTP client with plugin-specific settings
            http_config = self.config.get("http", {})
            self._http = HTTPClient(**http_config)
            
            # Set user agent to identify the plugin
            if "headers" not in http_config:
                self._http.headers["User-Agent"] = (
                    f"VulnBuster/{self.name}/{self.version} "
                    f"(+https://github.com/yourorg/vulnbuster)"
                )
        return self._http
    
    @property
    def is_enabled(self) -> bool:
        """Check if the plugin is enabled.
        
        Returns:
            bool: True if the plugin is enabled, False otherwise.
        """
        return self._enabled and self.config.get("enabled", True)
    
    @is_enabled.setter
    def is_enabled(self, value: bool) -> None:
        """Enable or disable the plugin.
        
        Args:
            value: Whether to enable or disable the plugin.
        """
        if not isinstance(value, bool):
            raise ValueError("is_enabled must be a boolean")
        self._enabled = value
        self._logger.debug("%s plugin %s", "Enabled" if value else "Disabled", self.name)
    
    async def initialize(self) -> None:
        """Initialize the plugin.
        
        This method is called when the plugin is loaded. It should be overridden
        by subclasses to perform any necessary setup.
        """
        if self._initialized:
            return
            
        self._logger.debug("Initializing %s plugin", self.name)
        
        # Initialize HTTP client if needed
        if self._http is not None:
            await self._http.setup()
            
        self._initialized = True
        self._logger.info("Plugin %s v%s initialized", self.name, self.version)
    
    async def cleanup(self) -> None:
        """Clean up resources used by the plugin.
        
        This method is called when the plugin is unloaded. It should be overridden
        by subclasses to perform any necessary cleanup.
        """
        if not self._initialized:
            return
            
        self._logger.debug("Cleaning up %s plugin", self.name)
        
        # Clean up HTTP client if it exists
        if self._http is not None:
            await self._http.teardown()
            self._http = None
            
        self._initialized = False
        self._logger.info("Plugin %s cleaned up", self.name)


class ScannerPlugin(Plugin):
    """Base class for scanner plugins.
    
    Scanner plugins add new scanning capabilities to VulnBuster.
    They can be either active (sending requests) or passive (analyzing data).
    """
    
    plugin_type = PluginType.SCANNER
    
    # Default configuration for scanner plugins
    config_schema = {
        **Plugin.config_schema,
        "properties": {
            **Plugin.config_schema["properties"],
            "rate_limit": {"type": "number", "default": 10, "minimum": 0.1},
            "timeout": {"type": "number", "default": 30, "minimum": 1},
            "max_retries": {"type": "integer", "default": 3, "minimum": 0},
            "verify_ssl": {"type": "boolean", "default": True},
            "follow_redirects": {"type": "boolean", "default": True},
            "max_redirects": {"type": "integer", "default": 5, "minimum": 0},
        }
    }
    
    async def scan(self, target: str, context: Optional[ScanContext] = None) -> ScanResult:
        """Perform a scan of the target.
        
        Args:
            target: The target to scan (URL, hostname, IP, etc.)
            context: Optional scan context
            
        Returns:
            ScanResult containing the scan findings
        """
        result = ScanResult(target=target)
        
        try:
            await self.initialize()
            await self.run_scan(target, result, context or ScanContext(target=target, config=self.config))
            result.status = "completed"
        except Exception as e:
            result.status = "failed"
            result.error = str(e)
            self._logger.exception("Scan failed for %s", target)
        
        return result
    
    @abstractmethod
    async def run_scan(self, target: str, result: ScanResult, context: ScanContext) -> None:
        """Run the scan (implemented by subclasses).
        
        Args:
            target: The target to scan
            result: ScanResult to populate with findings
            context: Scan context with configuration and shared resources
        """
        pass


class ActiveScannerPlugin(ScannerPlugin):
    """Base class for active scanner plugins.
    
    Active scanners send requests to the target system.
    """
    
    plugin_type = PluginType.SCANNER_ACTIVE
    
    async def run_scan(self, target: str, result: ScanResult, context: ScanContext) -> None:
        """Run an active scan."""
        raise NotImplementedError("Active scanner must implement run_scan")


class PassiveScannerPlugin(ScannerPlugin):
    """Base class for passive scanner plugins.
    
    Passive scanners analyze data without sending requests to the target.
    """
    
    plugin_type = PluginType.SCANNER_PASSIVE
    
    async def run_scan(self, target: str, result: ScanResult, context: ScanContext) -> None:
        """Run a passive scan."""
        raise NotImplementedError("Passive scanner must implement run_scan")


class PluginManager:
    """Manages loading and accessing plugins."""
    
    def __init__(self, app: VulnBusterApp):
        """Initialize the plugin manager.
        
        Args:
            app: The VulnBuster application instance.
        """
        self.app = app
        self._logger = logging.getLogger("vulnbuster.plugins.manager")
        self._plugins: Dict[str, Plugin] = {}
        self._plugin_paths: List[Path] = []
        self._initialized = False
    
    async def load_plugin(self, plugin_class: Type[P], **kwargs) -> P:
        """Load and initialize a plugin.
        
        Args:
            plugin_class: The plugin class to load.
            **kwargs: Additional configuration options.
            
        Returns:
            The loaded and initialized plugin instance.
            
        Raises:
            ValueError: If a plugin with the same name is already loaded.
            RuntimeError: If the plugin fails to initialize.
        """
        # Create plugin instance
        plugin = plugin_class(app=self.app, **kwargs)
        
        # Check for duplicate names
        if plugin.name in self._plugins:
            raise ValueError(f"A plugin with name '{plugin.name}' is already loaded")
        
        # Initialize the plugin
        try:
            await plugin.initialize()
            self._plugins[plugin.name] = plugin
            self._logger.info("Loaded plugin: %s v%s", plugin.name, plugin.version)
            return plugin
        except Exception as e:
            await plugin.cleanup()
            raise RuntimeError(f"Failed to initialize plugin {plugin.name}: {str(e)}") from e
    
    async def unload_plugin(self, plugin_name: str) -> None:
        """Unload and clean up a plugin.
        
        Args:
            plugin_name: The name of the plugin to unload.
            
        Raises:
            KeyError: If no plugin with the given name is loaded.
        """
        if plugin_name not in self._plugins:
            raise KeyError(f"No plugin with name '{plugin_name}' is loaded")
            
        plugin = self._plugins[plugin_name]
        await plugin.cleanup()
        del self._plugins[plugin_name]
        self._logger.info("Unloaded plugin: %s", plugin_name)
    
    def get_plugin(self, name: str) -> Plugin:
        """Get a plugin by name.
        
        Args:
            name: The name of the plugin to get.
            
        Returns:
            The plugin instance.
            
        Raises:
            KeyError: If no plugin with the given name is loaded.
        """
        if name not in self._plugins:
            raise KeyError(f"No plugin with name '{name}' is loaded")
        return self._plugins[name]
    
    def get_plugins_by_type(self, plugin_type: Union[PluginType, str]) -> List[Plugin]:
        """Get all plugins of a specific type or matching a type prefix.
        
        Args:
            plugin_type: The type of plugins to get (can be a PluginType or string).
            
        Returns:
            A list of plugin instances matching the type.
        """
        type_str = plugin_type.value if isinstance(plugin_type, PluginType) else str(plugin_type)
        return [
            p for p in self._plugins.values() 
            if (isinstance(p.plugin_type, PluginType) and p.plugin_type.value.startswith(type_str)) or
               (isinstance(p.plugin_type, str) and p.plugin_type.startswith(type_str))
        ]
    
    async def initialize_all(self) -> None:
        """Initialize all loaded plugins.
        
        Raises:
            RuntimeError: If any plugin fails to initialize.
        """
        if self._initialized:
            return
            
        self._logger.info("Initializing all plugins...")
        
        # Sort plugins by priority (higher priority first)
        plugins = sorted(
            self._plugins.values(),
            key=lambda p: p.config.get("priority", 100),
            reverse=True
        )
        
        # Initialize each plugin
        for plugin in plugins:
            if not plugin.is_enabled:
                self._logger.debug("Skipping disabled plugin: %s", plugin.name)
                continue
                
            try:
                await plugin.initialize()
                self._logger.debug("Initialized plugin: %s", plugin.name)
            except Exception as e:
                self._logger.error("Failed to initialize plugin %s: %s", plugin.name, str(e), exc_info=True)
                plugin.is_enabled = False
                
        self._initialized = True
        self._logger.info("All plugins initialized")
    
    async def cleanup_all(self) -> None:
        """Clean up all loaded plugins."""
        if not self._initialized:
            return
            
        self._logger.info("Cleaning up all plugins...")
        
        # Clean up plugins in reverse order of initialization
        for plugin in reversed(list(self._plugins.values())):
            try:
                if hasattr(plugin, 'is_initialized') and not plugin.is_initialized:
                    continue
                    
                await plugin.cleanup()
                self._logger.debug("Cleaned up plugin: %s", plugin.name)
            except Exception as e:
                self._logger.error("Error cleaning up plugin %s: %s", plugin.name, str(e), exc_info=True)
        
        self._initialized = False
        self._logger.info("All plugins cleaned up")
