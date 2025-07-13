""
Base test cases for reporter implementations.
"""

import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

import pytest

from vulnbuster.interfaces.enhanced_reporter import (
    BaseReporter, ReportFinding, ReportMetadata, ReportOptions, ReportFormat,
    ReportSeverity, ReportConfidence
)

class TestBaseReporter:
    """Base test class for reporter implementations."""
    
    # Override this in subclasses
    reporter_class: Type[BaseReporter]
    format: ReportFormat
    
    @pytest.fixture
    def reporter(self, report_options: Dict[str, Any]) -> BaseReporter:
        ""Create a reporter instance with default options.""
        return self.reporter_class(ReportOptions(
            format=self.format,
            **report_options
        ))
    
    async def test_generate_report(
        self,
        reporter: BaseReporter,
        sample_findings: List[ReportFinding],
        sample_metadata: ReportMetadata
    ) -> None:
        ""Test that a report can be generated.""
        report = await reporter.generate(sample_findings, sample_metadata)
        assert isinstance(report, str)
        assert len(report) > 0
        
        # Basic content validation
        assert sample_metadata.title in report
        assert str(len(sample_findings)) in report
        
        # Check that all finding titles are in the report
        for finding in sample_findings:
            assert finding.title in report
    
    async def test_save_report(
        self,
        reporter: BaseReporter,
        sample_findings: List[ReportFinding],
        sample_metadata: ReportMetadata,
        temp_output_dir: Path
    ) -> None:
        ""Test that a report can be saved to a file.""
        output_file = temp_output_dir / f"test_report.{self.format.value}"
        reporter.options.output_file = output_file
        
        report = await reporter.generate(sample_findings, sample_metadata)
        await reporter.save(report)
        
        assert output_file.exists()
        assert output_file.stat().st_size > 0
        
        # Verify the file contains the expected content
        content = output_file.read_text(encoding='utf-8')
        assert sample_metadata.title in content
        for finding in sample_findings:
            assert finding.title in content
    
    async def test_min_severity_filtering(
        self,
        reporter: BaseReporter,
        sample_findings: List[ReportFinding],
        sample_metadata: ReportMetadata
    ) -> None:
        ""Test that findings are filtered by minimum severity.""
        # Set minimum severity to HIGH
        reporter.options.min_severity = ReportSeverity.HIGH
        
        # Count expected findings
        expected_count = sum(
            1 for f in sample_findings 
            if ReportSeverity(f.severity) >= ReportSeverity.HIGH
        )
        
        report = await reporter.generate(sample_findings, sample_metadata)
        
        # Check that the report contains the expected number of findings
        assert str(expected_count) in report
        
        # Check that no low-severity findings are included
        low_severity = [f for f in sample_findings 
                       if ReportSeverity(f.severity) < ReportSeverity.HIGH]
        
        for finding in low_severity:
            assert finding.title not in report
    
    async def test_empty_findings(
        self,
        reporter: BaseReporter,
        sample_metadata: ReportMetadata
    ) -> None:
        ""Test report generation with no findings.""
        report = await reporter.generate([], sample_metadata)
        assert "No findings" in report or "0 findings" in report
    
    async def test_large_number_of_findings(
        self,
        reporter: BaseReporter,
        sample_metadata: ReportMetadata
    ) -> None:
        ""Test report generation with a large number of findings.""
        # Create 1000 sample findings
        findings = [
            ReportFinding(
                id=f"finding-{i}",
                title=f"Test Finding {i}",
                description=f"This is test finding {i}",
                severity=ReportSeverity.MEDIUM,
                confidence=ReportConfidence.FIRM,
                location=f"https://example.com/vuln/{i}"
            )
            for i in range(1000)
        ]
        
        report = await reporter.generate(findings, sample_metadata)
        assert "1000" in report  # Should mention the number of findings
        
        # Check that some sample findings are included
        for i in range(0, 1000, 100):
            assert f"Test Finding {i}" in report
