"""
Reporter Interface

This module defines the reporter interface for generating reports from scan results.
"""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Dict, List, Optional, Union, BinaryIO
from pathlib import Path

class ReportFormat(str, Enum):
    """Supported report formats."""
    HTML = "html"
    MARKDOWN = "markdown"
    JSON = "json"
    TEXT = "text"

class Reporter(ABC):
    """Base class for report generators."""
    
    def __init__(self, output: Optional[Union[str, Path, BinaryIO]] = None):
        self.output = output
    
    @abstractmethod
    async def generate(self, results: List[Dict], **kwargs) -> str:
        """Generate a report from scan results."""
        pass
    
    async def save(self, report: str) -> None:
        """Save the report to the output destination."""
        if not self.output:
            return
            
        if isinstance(self.output, (str, Path)):
            with open(self.output, 'w', encoding='utf-8') as f:
                f.write(report)
        elif hasattr(self.output, 'write'):
            self.output.write(report)
            if hasattr(self.output, 'flush'):
                self.output.flush()

class JSONReporter(Reporter):
    """JSON report generator."""
    
    async def generate(self, results: List[Dict], **kwargs) -> str:
        """Generate a JSON report."""
        import json
        return json.dumps({"results": results}, indent=2)

class HTMLReporter(Reporter):
    """HTML report generator."""
    
    async def generate(self, results: List[Dict], **kwargs) -> str:
        """Generate an HTML report."""
        html = ["<html><body><h1>Scan Results</h1><ul>"]
        for result in results:
            html.append(f"<li>{result.get('title', 'No title')}</li>")
        html.append("</ul></body></html>")
        return "\n".join(html)

def get_reporter(format: str, **kwargs) -> Reporter:
    """Get a reporter by format."""
    reporters = {
        "json": JSONReporter,
        "html": HTMLReporter
    }
    return reporters.get(format.lower(), JSONReporter)(**kwargs)