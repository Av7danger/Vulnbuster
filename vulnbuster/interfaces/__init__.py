""
VulnBuster Interfaces Package

This package contains the core interfaces used throughout the VulnBuster application.
"""

# Re-export interfaces for easier access
from .plugin import Plugin, PluginType
from .scanner import Scanner, ScanResult, ScanContext
from .reporter import Reporter, ReportFormat
from .auth_provider import AuthProvider

__all__ = [
    'Plugin',
    'PluginType',
    'Scanner',
    'ScanResult',
    'ScanContext',
    'Reporter',
    'ReportFormat',
    'AuthProvider',
]
