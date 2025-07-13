"""
VulnBuster Core Module

This module contains the core functionality of the VulnBuster application,
including the main application class and core components.
"""

import asyncio
import logging
from pathlib import Path
from typing import Dict, List, Optional, Type, Any, AsyncIterator, Callable, Awaitable, Union
from enum import Enum, auto
from dataclasses import dataclass, field
from contextlib import asynccontextmanager

from ..config import Config, get_config
from ..interfaces.plugin import Plugin, PluginType

# Configure logging
logger = logging.getLogger(__name__)

class AppState(Enum):
    """Application state enum."""
    CREATED = auto()
    INITIALIZING = auto()
    READY = auto()
    RUNNING = auto()
    STOPPING = auto()
    STOPPED = auto()
    ERROR = auto()

@dataclass
class ScanResult:
    """Container for scan results."""
    target: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

class VulnBusterApp:
    """Main VulnBuster application class."""
    
    def __init__(self, config: Optional[Config] = None):
        """Initialize the VulnBuster application.
        
        Args:
            config: Optional configuration. If not provided, the global config will be used.
        """
        self.config = config or get_config()
        self.state = AppState.CREATED
        self.plugins: Dict[str, Plugin] = {}
        self._event_handlers: Dict[str, List[Callable]] = {}
        self._scan_results: List[ScanResult] = []
        self._shutdown_event = asyncio.Event()
    
    async def initialize(self) -> None:
        """Initialize the application and all plugins."""
        if self.state != AppState.CREATED:
            raise RuntimeError(f"Cannot initialize application in state: {self.state}")
        
        self.state = AppState.INITIALIZING
        logger.info("Initializing VulnBuster...")
        
        try:
            # Initialize plugins
            await self._initialize_plugins()
            
            # Emit initialized event
            await self.emit('initialized')
            
            self.state = AppState.READY
            logger.info("VulnBuster initialized and ready")
            
        except Exception as e:
            self.state = AppState.ERROR
            logger.exception("Failed to initialize VulnBuster")
            raise
    
    async def _initialize_plugins(self) -> None:
        """Initialize all registered plugins."""
        logger.debug("Initializing plugins...")
        
        # Sort plugins by priority (if defined)
        plugins_to_init = sorted(
            self.plugins.values(),
            key=lambda p: getattr(p, 'priority', 100)
        )
        
        # Initialize each plugin
        for plugin in plugins_to_init:
            try:
                logger.debug(f"Initializing plugin: {plugin.name}")
                await plugin.initialize(self)
                logger.info(f"Plugin initialized: {plugin.name}")
            except Exception as e:
                logger.error(f"Failed to initialize plugin {plugin.name}: {e}")
                if self.config.debug:
                    logger.exception("Plugin initialization error:")
    
    async def run_scan(self, target: Optional[str] = None) -> List[ScanResult]:
        """Run a vulnerability scan.
        
        Args:
            target: Optional target to scan. If not provided, uses the configured target.
            
        Returns:
            List of scan results.
        """
        if self.state != AppState.READY:
            raise RuntimeError(f"Cannot run scan in state: {self.state}")
        
        target = target or self.config.target
        if not target:
            raise ValueError("No target specified")
        
        self.state = AppState.RUNNING
        self._shutdown_event.clear()
        
        logger.info(f"Starting scan of target: {target}")
        
        try:
            # Emit scan started event
            await self.emit('scan_started', {'target': target})
            
            # Create a new scan result
            result = ScanResult(target=target)
            
            # Run scanner plugins
            scanner_plugins = [p for p in self.plugins.values() 
                             if getattr(p, 'plugin_type', None) == PluginType.SCANNER]
            
            # Execute scanners in parallel
            scanner_tasks = [
                self._run_plugin_scan(plugin, target, result)
                for plugin in scanner_plugins
            ]
            
            # Wait for all scanners to complete
            await asyncio.gather(*scanner_tasks)
            
            # Add to results
            self._scan_results.append(result)
            
            # Emit scan completed event
            await self.emit('scan_completed', {'target': target, 'result': result})
            
            logger.info(f"Scan completed for target: {target}")
            return [result]
            
        except asyncio.CancelledError:
            logger.info("Scan was cancelled")
            raise
            
        except Exception as e:
            self.state = AppState.ERROR
            logger.error(f"Scan failed: {e}")
            if self.config.debug:
                logger.exception("Scan error:")
            raise
            
        finally:
            self.state = AppState.READY
    
    async def _run_plugin_scan(self, plugin: 'Plugin', target: str, result: ScanResult) -> None:
        """Run a scan using a specific plugin."""
        try:
            logger.debug(f"Running plugin: {plugin.name}")
            plugin_result = await plugin.scan(target)
            
            if plugin_result:
                result.findings.extend(plugin_result.get('findings', []))
                result.metrics.update(plugin_result.get('metrics', {}))
                
        except Exception as e:
            logger.error(f"Plugin {plugin.name} failed: {e}")
            if self.config.debug:
                logger.exception("Plugin error:")
    
    async def shutdown(self) -> None:
        """Shut down the application and all plugins."""
        if self.state in (AppState.STOPPING, AppState.STOPPED):
            return
            
        self.state = AppState.STOPPING
        logger.info("Shutting down VulnBuster...")
        
        try:
            # Signal shutdown to all components
            self._shutdown_event.set()
            
            # Shutdown plugins
            for plugin in self.plugins.values():
                try:
                    if hasattr(plugin, 'shutdown'):
                        await plugin.shutdown()
                except Exception as e:
                    logger.error(f"Error shutting down plugin {plugin.name}: {e}")
            
            # Emit shutdown event
            await self.emit('shutdown')
            
            self.state = AppState.STOPPED
            logger.info("VulnBuster has been shut down")
            
        except Exception as e:
            self.state = AppState.ERROR
            logger.error(f"Error during shutdown: {e}")
            raise
    
    def register_plugin(self, plugin: 'Plugin') -> None:
        """Register a plugin with the application.
        
        Args:
            plugin: The plugin to register.
            
        Raises:
            ValueError: If a plugin with the same name is already registered.
        """
        if plugin.name in self.plugins:
            raise ValueError(f"Plugin with name '{plugin.name}' is already registered")
        
        self.plugins[plugin.name] = plugin
        logger.debug(f"Registered plugin: {plugin.name}")
    
    def unregister_plugin(self, plugin_name: str) -> None:
        """Unregister a plugin.
        
        Args:
            plugin_name: The name of the plugin to unregister.
        """
        if plugin_name in self.plugins:
            del self.plugins[plugin_name]
            logger.debug(f"Unregistered plugin: {plugin_name}")
    
    def on(self, event: str) -> Callable:
        """Decorator to register an event handler.
        
        Args:
            event: The event name to handle.
            
        Returns:
            A decorator function.
        """
        def decorator(handler: Callable) -> Callable:
            if event not in self._event_handlers:
                self._event_handlers[event] = []
            self._event_handlers[event].append(handler)
            return handler
        return decorator
    
    async def emit(self, event: str, data: Optional[Dict] = None) -> None:
        """Emit an event to all registered handlers.
        
        Args:
            event: The event name.
            data: Optional event data.
        """
        if event not in self._event_handlers:
            return
            
        data = data or {}
        
        for handler in self._event_handlers[event]:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(**data)
                else:
                    handler(**data)
            except Exception as e:
                logger.error(f"Error in event handler for '{event}': {e}")
                if self.config.debug:
                    logger.exception("Event handler error:")
    
    @property
    def is_running(self) -> bool:
        """Check if the application is running a scan."""
        return self.state == AppState.RUNNING
    
    @property
    def is_ready(self) -> bool:
        """Check if the application is ready to run scans."""
        return self.state == AppState.READY
    
    @property
    def scan_count(self) -> int:
        """Get the number of completed scans."""
        return len(self._scan_results)
    
    def get_scan_results(self) -> List[ScanResult]:
        """Get all scan results."""
        return self._scan_results.copy()
    
    def clear_results(self) -> None:
        """Clear all scan results."""
        self._scan_results.clear()

# Global application instance
_app_instance: Optional[VulnBusterApp] = None

def get_app(config: Optional[Config] = None) -> VulnBusterApp:
    """Get or create the global application instance.
    
    Args:
        config: Optional configuration to use when creating the instance.
        
    Returns:
        The global VulnBusterApp instance.
    """
    global _app_instance
    
    if _app_instance is None:
        _app_instance = VulnBusterApp(config)
    
    return _app_instance
