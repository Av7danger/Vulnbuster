"""
Enhanced Reporter Interface

This module provides an enhanced reporting system for VulnBuster with support for
multiple output formats, templates, and advanced features.
"""

from __future__ import annotations

import abc
import json
import logging
import os
import re
import sys
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Any, BinaryIO, Dict, List, Optional, Type, Union, cast

import jinja2
from pydantic import BaseModel, Field, validator

# Configure logging
logger = logging.getLogger(__name__)

class ReportFormat(str, Enum):
    """Supported report formats."""
    HTML = "html"
    MARKDOWN = "markdown"
    JSON = "json"
    SARIF = "sarif"
    TEXT = "text"
    PDF = "pdf"

class ReportSeverity(str, Enum):
    """Severity levels for report findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ReportConfidence(str, Enum):
    """Confidence levels for report findings."""
    CERTAIN = "certain"
    FIRM = "firm"
    TENTATIVE = "tentative"

@dataclass
class ReportFinding:
    """Represents a single finding in a report."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    description: str = ""
    severity: ReportSeverity = ReportSeverity.INFO
    confidence: ReportConfidence = ReportConfidence.TENTATIVE
    location: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    cwe: Optional[int] = None
    cve: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    risk_score: Optional[float] = None

@dataclass
class ReportMetadata:
    """Metadata about the report."""
    title: str = "VulnBuster Scan Report"
    description: str = ""
    version: str = "1.0.0"
    generated_at: datetime = field(default_factory=datetime.utcnow)
    generator: str = "VulnBuster"
    generator_uri: str = "https://github.com/yourorg/vulnbuster"
    generator_version: str = "1.0.0"
    scan_duration: float = 0.0
    scan_target: str = ""
    scan_id: str = field(default_factory=lambda: f"scan_{uuid.uuid4().hex[:8]}")
    custom_fields: Dict[str, Any] = field(default_factory=dict)

class ReportSummary(BaseModel):
    """Summary statistics for a report."""
    total_findings: int = 0
    findings_by_severity: Dict[str, int] = Field(
        default_factory=lambda: {sev.value: 0 for sev in ReportSevering}
    )
    findings_by_confidence: Dict[str, int] = Field(
        default_factory=lambda: {conf.value: 0 for conf in ReportConfidence}
    )
    scan_duration: float = 0.0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

class ReportOptions(BaseModel):
    """Options for report generation."""
    format: ReportFormat = ReportFormat.HTML
    output_file: Optional[Union[str, Path]] = None
    template: Optional[Union[str, Path]] = None
    min_severity: Optional[ReportSeverity] = None
    include_evidence: bool = True
    include_remediation: bool = True
    include_references: bool = True
    include_cvss: bool = True
    include_risk_score: bool = True
    custom_styles: Optional[Dict[str, Any]] = None
    custom_templates_dir: Optional[Union[str, Path]] = None

class BaseReporter(abc.ABC):
    """Base class for all reporters."""
    
    def __init__(self, options: Optional[ReportOptions] = None):
        self.options = options or ReportOptions()
        self._template_env: Optional[jinja2.Environment] = None
        
    @property
    def template_env(self) -> jinja2.Environment:
        """Get the Jinja2 template environment."""
        if self._template_env is None:
            # Set up template paths
            template_paths = [
                Path("templates"),
                Path(__file__).parent / "templates",
            ]
            
            if self.options.custom_templates_dir:
                template_paths.insert(0, Path(self.options.custom_templates_dir))
            
            # Filter out non-existent paths
            template_paths = [str(p) for p in template_paths if p.exists()]
            
            self._template_env = jinja2.Environment(
                loader=jinja2.FileSystemLoader(template_paths),
                autoescape=jinja2.select_autoescape(['html', 'xml']),
                trim_blocks=True,
                lstrip_blocks=True,
            )
            
            # Add custom filters
            self._template_env.filters['to_json'] = json.dumps
            self._template_env.filters['format_datetime'] = self._format_datetime
            
        return self._template_env
    
    def _format_datetime(self, value: datetime, fmt: str = "%Y-%m-%d %H:%M:%S %Z") -> str:
        """Format a datetime object as a string."""
        return value.strftime(fmt)
    
    async def generate(self, findings: List[ReportFinding], metadata: ReportMetadata) -> str:
        """Generate a report from the given findings and metadata.
        
        Args:
            findings: List of findings to include in the report
            metadata: Metadata about the report
            
        Returns:
            The generated report as a string
        """
        # Filter findings by severity if specified
        if self.options.min_severity:
            min_severity_level = ReportSeverity(self.options.min_severity)
            severity_levels = list(ReportSeverity)
            min_level_index = severity_levels.index(min_severity_level)
            findings = [
                f for f in findings
                if severity_levels.index(ReportSeverity(f.severity)) <= min_level_index
            ]
        
        # Generate summary
        summary = self._generate_summary(findings, metadata)
        
        # Generate the report content
        return await self._generate_report(findings, metadata, summary)
    
    def _generate_summary(self, findings: List[ReportFinding], metadata: ReportMetadata) -> ReportSummary:
        """Generate a summary of the findings."""
        summary = ReportSummary(
            total_findings=len(findings),
            scan_duration=metadata.scan_duration,
            start_time=metadata.generated_at,
            end_time=datetime.utcnow()
        )
        
        # Count findings by severity and confidence
        for finding in findings:
            summary.findings_by_severity[finding.severity] += 1
            summary.findings_by_confidence[finding.confidence] += 1
            
        return summary
    
    @abc.abstractmethod
    async def _generate_report(
        self,
        findings: List[ReportFinding],
        metadata: ReportMetadata,
        summary: ReportSummary
    ) -> str:
        """Generate the report content (implemented by subclasses)."""
        pass
    
    async def save(self, report: str, output_path: Optional[Union[str, Path]] = None) -> None:
        """Save the report to a file or stream.
        
        Args:
            report: The report content to save
            output_path: Optional path to save the report to. If not provided,
                        uses the path from options.output_file.
        """
        output_path = output_path or self.options.output_file
        if not output_path:
            return
            
        try:
            if hasattr(output_path, 'write'):
                # It's a file-like object
                output_path.write(report)
                if hasattr(output_path, 'flush'):
                    output_path.flush()
            else:
                # It's a path
                output_path = Path(output_path)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(report, encoding='utf-8')
                
            logger.info("Report saved to %s", output_path)
        except Exception as e:
            logger.error("Failed to save report: %s", str(e), exc_info=True)
            raise

class HTMLReporter(BaseReporter):
    """HTML report generator with interactive features."""
    
    async def _generate_report(
        self,
        findings: List[ReportFinding],
        metadata: ReportMetadata,
        summary: ReportSummary
    ) -> str:
        """Generate an HTML report."""
        template = self.template_env.get_template("report.html")
        
        return template.render(
            findings=findings,
            metadata=metadata,
            summary=summary,
            options=self.options,
            now=datetime.utcnow(),
            ReportSeverity=ReportSeverity,
            ReportConfidence=ReportConfidence
        )

class MarkdownReporter(BaseReporter):
    """Markdown report generator."""
    
    async def _generate_report(
        self,
        findings: List[ReportFinding],
        metadata: ReportMetadata,
        summary: ReportSummary
    ) -> str:
        """Generate a Markdown report."""
        lines = [
            f"# {metadata.title}",
            f"**Generated at:** {metadata.generated_at.isoformat()}",
            f"**Target:** {metadata.scan_target or 'N/A'}",
            f"**Scan ID:** {metadata.scan_id}",
            f"**Duration:** {metadata.scan_duration:.2f} seconds\n",
            "## Summary",
            f"- Total findings: {summary.total_findings}",
            "- Findings by severity:",
            *[f"  - {sev.value.capitalize()}: {count}" 
              for sev, count in summary.findings_by_severity.items() if count > 0],
            "\n## Findings\n"
        ]
        
        for finding in sorted(findings, key=lambda f: (
            -list(ReportSeverity).index(ReportSeverity(f.severity)),
            -list(ReportConfidence).index(ReportConfidence(f.confidence))
        )):
            lines.extend([
                f"### {finding.title}",
                f"**Severity:** {finding.severity.upper()}  ",
                f"**Confidence:** {finding.confidence.capitalize()}",
                f"**Location:** {finding.location or 'N/A'}",
                f"**CWE:** {finding.cwe or 'N/A'}",
                f"**CVE:** {finding.cve or 'N/A'}",
                f"**Risk Score:** {finding.risk_score or 'N/A'}",
                "",
                "#### Description",
                finding.description,
                ""
            ])
            
            if self.options.include_remediation and finding.remediation:
                lines.extend(["#### Remediation", finding.remediation, ""])
                
            if self.options.include_evidence and finding.evidence:
                lines.append("#### Evidence")
                for i, evidence in enumerate(finding.evidence, 1):
                    lines.extend([
                        f"**Evidence {i}**",
                        f"```\n{evidence.get('content', '')}\n```",
                        f"*Source: {evidence.get('source', 'N/A')}*\n"
                    ])
            
            if self.options.include_references and finding.references:
                lines.append("#### References")
                for ref in finding.references:
                    lines.append(f"- {ref}")
                
            lines.append("---\n")
        
        return "\n".join(lines)

class JSONReporter(BaseReporter):
    """JSON report generator."""
    
    async def _generate_report(
        self,
        findings: List[ReportFinding],
        metadata: ReportMetadata,
        summary: ReportSummary
    ) -> str:
        """Generate a JSON report."""
        report = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "metadata": {
                **asdict(metadata),
                "generated_at": metadata.generated_at.isoformat(),
                "scan_duration": float(metadata.scan_duration)  # Convert Decimal to float
            },
            "summary": summary.dict(),
            "findings": [
                {
                    **{k: v for k, v in asdict(f).items() 
                       if not k.startswith('_') and v is not None},
                    "timestamp": f.timestamp.isoformat() if hasattr(f, 'timestamp') else None,
                    "severity": f.severity.value,
                    "confidence": f.confidence.value
                }
                for f in findings
            ]
        }
        
        return json.dumps(report, indent=2, ensure_ascii=False)

class SARIFReporter(BaseReporter):
    """SARIF (Static Analysis Results Interchange Format) reporter."""
    
    async def _generate_report(
        self,
        findings: List[ReportFinding],
        metadata: ReportMetadata,
        summary: ReportSummary
    ) -> str:
        """Generate a SARIF report."""
        # SARIF version and schema
        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": metadata.generator,
                        "version": metadata.generator_version,
                        "informationUri": metadata.generator_uri,
                        "rules": []
                    }
                },
                "artifacts": [{
                    "location": {"uri": metadata.scan_target or ""}
                }],
                "results": []
            }]
        }
        
        # Add rules and results
        rule_indices = {}
        results = []
        
        for i, finding in enumerate(findings):
            # Create a rule for each unique finding type
            rule_id = f"{finding.id}"
            if rule_id not in rule_indices:
                rule = {
                    "id": rule_id,
                    "name": finding.title,
                    "shortDescription": {
                        "text": finding.title
                    },
                    "fullDescription": {
                        "text": finding.description
                    },
                    "defaultConfiguration": {
                        "level": self._get_sarif_level(finding.severity)
                    },
                    "helpUri": finding.references[0] if finding.references else "",
                    "properties": {
                        "tags": finding.tags,
                        "precision": finding.confidence.value
                    }
                }
                
                if finding.cwe:
                    rule["properties"]["cwe"] = f"CWE-{finding.cwe}"
                
                rule_indices[rule_id] = len(sarif["runs"][0]["tool"]["driver"]["rules"])
                sarif["runs"][0]["tool"]["driver"]["rules"].append(rule)
            
            # Create result
            result = {
                "ruleId": rule_id,
                "ruleIndex": rule_indices[rule_id],
                "level": self._get_sarif_level(finding.severity),
                "message": {
                    "text": finding.description
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.location or metadata.scan_target or ""
                        }
                    }
                }]
            }
            
            # Add evidence if available
            if finding.evidence:
                result["attachments"] = [{
                    "description": "Evidence",
                    "text": "\n".join([
                        f"{e.get('source', 'Evidence')}:\n{e.get('content', '')}" 
                        for e in finding.evidence
                    ])
                }]
            
            results.append(result)
        
        sarif["runs"][0]["results"] = results
        
        return json.dumps(sarif, indent=2, ensure_ascii=False)
    
    def _get_sarif_level(self, severity: ReportSeverity) -> str:
        """Convert our severity to SARIF level."""
        return {
            ReportSeverity.CRITICAL: "error",
            ReportSeverity.HIGH: "error",
            ReportSeverity.MEDIUM: "warning",
            ReportSeverity.LOW: "note",
            ReportSeverity.INFO: "note"
        }.get(severity, "none")

class TextReporter(BaseReporter):
    """Plain text report generator for console output."""
    
    async def _generate_report(
        self,
        findings: List[ReportFinding],
        metadata: ReportMetadata,
        summary: ReportSummary
    ) -> str:
        """Generate a plain text report."""
        lines = [
            f"{metadata.title}",
            "=" * len(metadata.title),
            f"Generated at: {metadata.generated_at.isoformat()}",
            f"Target: {metadata.scan_target or 'N/A'}",
            f"Scan ID: {metadata.scan_id}",
            f"Duration: {metadata.scan_duration:.2f} seconds",
            "",
            "Summary",
            "-------",
            f"Total findings: {summary.total_findings}",
            "Findings by severity:"
        ]
        
        for sev in ReportSeverity:
            count = summary.findings_by_severity.get(sev.value, 0)
            if count > 0:
                lines.append(f"  {sev.value.upper()}: {count}")
        
        lines.append("\nFindings\n--------")
        
        for i, finding in enumerate(sorted(findings, key=lambda f: (
            -list(ReportSeverity).index(ReportSeverity(f.severity)),
            -list(ReportConfidence).index(ReportConfidence(f.confidence))
        )), 1):
            lines.extend([
                "",
                f"{i}. {finding.title}",
                f"{'=' * (len(str(i)) + 2)} {len(finding.title) * '='}",
                f"Severity:    {finding.severity.upper()}",
                f"Confidence:  {finding.confidence.capitalize()}",
                f"Location:    {finding.location or 'N/A'}",
                f"CWE:         {finding.cwe or 'N/A'}",
                f"CVE:         {finding.cve or 'N/A'}",
                f"Risk Score:  {finding.risk_score or 'N/A'}",
                "",
                "Description:",
                finding.description,
            ])
            
            if self.options.include_remediation and finding.remediation:
                lines.extend(["", "Remediation:", finding.remediation])
                
            if self.options.include_evidence and finding.evidence:
                lines.append("\nEvidence:")
                for j, evidence in enumerate(finding.evidence, 1):
                    lines.extend([
                        f"  {j}. {evidence.get('source', 'Evidence')}:",
                        f"{'=' * (len(str(j)) + 2)} {len(evidence.get('source', 'Evidence')) * '='}",
                        evidence.get('content', '').strip(),
                        ""
                    ])
            
            if self.options.include_references and finding.references:
                lines.append("References:")
                for ref in finding.references:
                    lines.append(f"- {ref}")
        
        return "\n".join(lines)

class PDFReporter(HTMLReporter):
    """PDF report generator (uses WeasyPrint to convert HTML to PDF)."""
    
    async def _generate_report(
        self,
        findings: List[ReportFinding],
        metadata: ReportMetadata,
        summary: ReportSummary
    ) -> str:
        """Generate a PDF report."""
        try:
            from weasyprint import HTML
            from weasyprint.text.fonts import FontConfiguration
        except ImportError:
            logger.error(
                "WeasyPrint is required for PDF generation. "
                "Install with: pip install weasyprint"
            )
            raise ImportError("WeasyPrint is required for PDF generation")
        
        # Generate HTML first
        html = await super()._generate_report(findings, metadata, summary)
        
        # Convert HTML to PDF
        font_config = FontConfiguration()
        pdf_bytes = HTML(string=html).write_pdf(font_config=font_config)
        
        # Return as base64-encoded string
        import base64
        return base64.b64encode(pdf_bytes).decode('utf-8')
    
    async def save(self, report: str, output_path: Optional[Union[str, Path]] = None) -> None:
        """Save the PDF report to a file."""
        output_path = output_path or self.options.output_file
        if not output_path:
            return
            
        try:
            import base64
            pdf_bytes = base64.b64decode(report)
            
            if hasattr(output_path, 'write'):
                # It's a file-like object
                output_path.write(pdf_bytes)
                if hasattr(output_path, 'flush'):
                    output_path.flush()
            else:
                # It's a path
                output_path = Path(output_path)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_bytes(pdf_bytes)
                
            logger.info("PDF report saved to %s", output_path)
        except Exception as e:
            logger.error("Failed to save PDF report: %s", str(e), exc_info=True)
            raise

def get_reporter(
    format: Union[str, ReportFormat] = ReportFormat.HTML,
    **kwargs
) -> BaseReporter:
    """Get a reporter instance by format.
    
    Args:
        format: The report format (html, markdown, json, sarif, text, pdf)
        **kwargs: Additional options to pass to the reporter
        
    Returns:
        A reporter instance
        
    Raises:
        ValueError: If the format is not supported
    """
    format = ReportFormat(format.lower()) if isinstance(format, str) else format
    
    reporters = {
        ReportFormat.HTML: HTMLReporter,
        ReportFormat.MARKDOWN: MarkdownReporter,
        ReportFormat.JSON: JSONReporter,
        ReportFormat.SARIF: SARIFReporter,
        ReportFormat.TEXT: TextReporter,
        ReportFormat.PDF: PDFReporter,
    }
    
    if format not in reporters:
        raise ValueError(f"Unsupported report format: {format}")
    
    return reporters[format](ReportOptions(format=format, **kwargs))
