""
Test cases for HTML reporter.
"""

import asyncio
from pathlib import Path
from typing import Any, Dict

import pytest

from vulnbuster.interfaces.enhanced_reporter import (
    HTMLReporter, ReportFormat, ReportOptions, ReportSeverity, ReportConfidence
)
from .test_base import TestBaseReporter

class TestHTMLReporter(TestBaseReporter):
    """Test cases for HTML reporter."""
    
    reporter_class = HTMLReporter
    format = ReportFormat.HTML
    
    @pytest.fixture
    def reporter(self, report_options: Dict[str, Any]) -> HTMLReporter:
        ""Create an HTML reporter instance with default options.""
        return HTMLReporter(ReportOptions(
            format=ReportFormat.HTML,
            **report_options
        ))
    
    async def test_html_structure(
        self,
        reporter: HTMLReporter,
        sample_findings: list,
        sample_metadata: dict
    ) -> None:
        ""Test that the HTML report has the correct structure.""
        report = await reporter.generate(sample_findings, sample_metadata)
        
        # Check basic HTML structure
        assert "<!DOCTYPE html>" in report
        assert "<html" in report
        assert "<head>" in report
        assert "<title>" in report
        assert "<body>" in report
        
        # Check metadata is included
        assert sample_metadata.title in report
        assert sample_metadata.description in report
        
        # Check findings are included
        for finding in sample_findings:
            assert finding.title in report
            assert finding.severity.upper() in report
    
    async def test_custom_styles(
        self,
        reporter: HTMLReporter,
        sample_findings: list,
        sample_metadata: dict,
        custom_styles: Dict[str, str]
    ) -> None:
        ""Test that custom styles are applied to the HTML report.""
        reporter.options.custom_styles = custom_styles
        report = await reporter.generate(sample_findings, sample_metadata)
        
        # Check that custom colors are in the CSS
        for color in custom_styles.values():
            assert color in report
    
    async def test_custom_template(
        self,
        reporter: HTMLReporter,
        sample_findings: list,
        sample_metadata: dict,
        html_template_path: Path,
        temp_output_dir: Path
    ) -> None:
        ""Test that a custom template can be used for the HTML report.""
        # Set a custom template
        reporter.options.template = str(html_template_path)
        
        # Generate the report
        output_file = temp_output_dir / "custom_template_test.html"
        reporter.options.output_file = output_file
        
        report = await reporter.generate(sample_findings, sample_metadata)
        await reporter.save(report)
        
        # Check that the report was generated
        assert output_file.exists()
        
        # Check that the custom template was used
        content = output_file.read_text(encoding='utf-8')
        assert "<h1>" + sample_metadata.title + "</h1>" in content
        
        # Check that all findings are included
        for finding in sample_findings:
            assert finding.title in content
    
    async def test_severity_highlighting(
        self,
        reporter: HTMLReporter,
        sample_findings: list,
        sample_metadata: dict
    ) -> None:
        ""Test that different severity levels are highlighted differently.""
        report = await reporter.generate(sample_findings, sample_metadata)
        
        # Check that each severity level has its own CSS class
        for severity in ReportSeverity:
            if severity != ReportSeverity.UNKNOWN:
                assert f'severity-{severity.value.lower()}' in report.lower()
    
    async def test_evidence_rendering(
        self,
        reporter: HTMLReporter,
        sample_findings: list,
        sample_metadata: dict
    ) -> None:
        ""Test that evidence is properly rendered in the HTML report.""
        reporter.options.include_evidence = True
        report = await reporter.generate(sample_findings, sample_metadata)
        
        # Check that evidence sections are included
        assert "<h3>Evidence</h3>" in report or "<h4>Evidence</h4>" in report
        
        # Check that evidence content is included
        for finding in sample_findings:
            if finding.evidence:
                for evidence in finding.evidence:
                    assert evidence["source"] in report
                    assert evidence["content"] in report
    
    async def test_remediation_rendering(
        self,
        reporter: HTMLReporter,
        sample_findings: list,
        sample_metadata: dict
    ) -> None:
        ""Test that remediation information is properly rendered.""
        reporter.options.include_remediation = True
        report = await reporter.generate(sample_findings, sample_metadata)
        
        # Check that remediation sections are included
        assert "<h3>Remediation</h3>" in report or "<h4>Remediation</h4>" in report
        
        # Check that remediation content is included
        for finding in sample_findings:
            if finding.remediation:
                assert finding.remediation in report
    
    async def test_references_rendering(
        self,
        reporter: HTMLReporter,
        sample_findings: list,
        sample_metadata: dict
    ) -> None:
        ""Test that references are properly rendered as clickable links.""
        reporter.options.include_references = True
        report = await reporter.generate(sample_findings, sample_metadata)
        
        # Check that references sections are included
        assert "<h3>References</h3>" in report or "<h4>References</h4>" in report
        
        # Check that references are properly formatted as links
        for finding in sample_findings:
            if finding.references:
                for ref in finding.references:
                    assert f'<a href="{ref}"' in report or f'href="{ref}"' in report
    
    async def test_custom_metadata(
        self,
        reporter: HTMLReporter,
        sample_findings: list,
        sample_metadata: dict
    ) -> None:
        ""Test that custom metadata fields are included in the report.""
        # Add custom fields to metadata
        sample_metadata.custom_fields = {
            "environment": "production",
            "scanner_version": "1.2.3",
            "scan_type": "full"
        }
        
        report = await reporter.generate(sample_findings, sample_metadata)
        
        # Check that custom fields are included
        for key, value in sample_metadata.custom_fields.items():
            assert str(key) in report
            assert str(value) in report
    
    async def test_error_handling(
        self,
        reporter: HTMLReporter,
        sample_metadata: dict
    ) -> None:
        ""Test that the reporter handles errors gracefully.""
        # Test with invalid template path
        reporter.options.template = "/nonexistent/template.html"
        
        # Should raise an error or fall back to default template
        if hasattr(reporter, 'template_env'):
            # If using Jinja2, it will raise an error
            with pytest.raises(Exception):
                await reporter.generate([], sample_metadata)
        else:
            # Should fall back to default template
            report = await reporter.generate([], sample_metadata)
            assert "No findings" in report or "0 findings" in report
