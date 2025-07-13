""
Test cases for JSON reporter.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import pytest
from pydantic import ValidationError

from vulnbuster.interfaces.enhanced_reporter import (
    JSONReporter, ReportFormat, ReportOptions, ReportSeverity, ReportConfidence,
    ReportFinding, ReportMetadata, ReportSummary, ReportSchema
)
from .test_base import TestBaseReporter

class TestJSONReporter(TestBaseReporter):
    """Test cases for JSON reporter."""
    
    reporter_class = JSONReporter
    format = ReportFormat.JSON
    
    @pytest.fixture
    def reporter(self, report_options: Dict[str, Any]) -> JSONReporter:
        ""Create a JSON reporter instance with default options.""
        return JSONReporter(ReportOptions(
            format=ReportFormat.JSON,
            **report_options
        ))
    
    async def test_json_structure(
        self,
        reporter: JSONReporter,
        sample_findings: List[ReportFinding],
        sample_metadata: ReportMetadata
    ) -> None:
        ""Test that the JSON report has the correct structure.""
        report = await reporter.generate(sample_findings, sample_metadata)
        data = json.loads(report)
        
        # Check top-level keys
        assert "metadata" in data
        assert "findings" in data
        assert "summary" in data
        
        # Check metadata
        assert data["metadata"]["title"] == sample_metadata.title
        assert data["metadata"]["description"] == sample_metadata.description
        
        # Check findings
        assert isinstance(data["findings"], list)
        assert len(data["findings"]) == len(sample_findings)
        
        # Check summary
        assert isinstance(data["summary"], dict)
        assert "total_findings" in data["summary"]
        assert data["summary"]["total_findings"] == len(sample_findings)
    
    async def test_finding_structure(
        self,
        reporter: JSONReporter,
        sample_findings: List[ReportFinding],
        sample_metadata: ReportMetadata
    ) -> None:
        ""Test that findings have the correct structure in the JSON report.""
        report = await reporter.generate(sample_findings, sample_metadata)
        data = json.loads(report)
        
        for i, finding in enumerate(sample_findings):
            json_finding = data["findings"][i]
            
            # Check basic fields
            assert json_finding["id"] == finding.id
            assert json_finding["title"] == finding.title
            assert json_finding["description"] == finding.description
            assert json_finding["severity"] == finding.severity.value
            assert json_finding["confidence"] == finding.confidence.value
            
            # Check optional fields
            if finding.location:
                assert json_finding["location"] == finding.location
            
            if finding.details:
                assert json_finding["details"] == finding.details
            
            if finding.evidence:
                assert isinstance(json_finding["evidence"], list)
                assert len(json_finding["evidence"]) == len(finding.evidence)
    
    async def test_metadata_structure(
        self,
        reporter: JSONReporter,
        sample_findings: List[ReportFinding],
        sample_metadata: ReportMetadata
    ) -> None:
        ""Test that metadata has the correct structure in the JSON report.""
        # Add custom fields to metadata
        sample_metadata.custom_fields = {
            "environment": "production",
            "scanner_version": "1.2.3"
        }
        
        report = await reporter.generate(sample_findings, sample_metadata)
        data = json.loads(report)
        
        # Check metadata fields
        metadata = data["metadata"]
        assert metadata["title"] == sample_metadata.title
        assert metadata["description"] == sample_metadata.description
        assert metadata["version"] == sample_metadata.version
        assert metadata["scan_target"] == sample_metadata.scan_target
        assert metadata["scan_duration"] == sample_metadata.scan_duration
        
        # Check custom fields
        assert "custom_fields" in metadata
        assert metadata["custom_fields"]["environment"] == "production"
        assert metadata["custom_fields"]["scanner_version"] == "1.2.3"
    
    async def test_summary_structure(
        self,
        reporter: JSONReporter,
        sample_findings: List[ReportFinding],
        sample_metadata: ReportMetadata
    ) -> None:
        ""Test that the summary has the correct structure in the JSON report."""
        report = await reporter.generate(sample_findings, sample_metadata)
        data = json.loads(report)
        
        summary = data["summary"]
        
        # Check basic summary fields
        assert "total_findings" in summary
        assert "severity_counts" in summary
        assert "confidence_counts" in summary
        
        # Check severity counts
        severity_counts = summary["severity_counts"]
        for severity in ReportSeverity:
            if severity != ReportSeverity.UNKNOWN:
                assert severity.value in severity_counts
        
        # Check confidence counts
        confidence_counts = summary["confidence_counts"]
        for confidence in ReportConfidence:
            if confidence != ReportConfidence.UNKNOWN:
                assert confidence.value in confidence_counts
    
    async def test_json_validation(
        self,
        reporter: JSONReporter,
        sample_findings: List[ReportFinding],
        sample_metadata: ReportMetadata
    ) -> None:
        ""Test that the generated JSON is valid according to the schema.""
        report = await reporter.generate(sample_findings, sample_metadata)
        data = json.loads(report)
        
        # Validate against the schema
        try:
            ReportSchema(**data)
        except ValidationError as e:
            pytest.fail(f"Generated JSON does not match schema: {e}")
    
    async def test_min_severity_filtering(
        self,
        reporter: JSONReporter,
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
        data = json.loads(report)
        
        # Check that the correct number of findings are included
        assert len(data["findings"]) == expected_count
        
        # Check that no low-severity findings are included
        for finding in data["findings"]:
            severity = ReportSeverity(finding["severity"])
            assert severity >= ReportSeverity.HIGH
    
    async def test_custom_serialization(
        self,
        reporter: JSONReporter,
        sample_metadata: ReportMetadata
    ) -> None:
        ""Test that custom objects are properly serialized to JSON.""
        # Create a finding with complex data types
        finding = ReportFinding(
            id="complex-data",
            title="Test with Complex Data",
            description="This finding tests complex data serialization",
            severity=ReportSeverity.MEDIUM,
            confidence=ReportConfidence.FIRM,
            location="https://example.com/complex",
            details={
                "nested": {"key": "value"},
                "list": [1, 2, 3],
                "boolean": True,
                "none": None
            },
            evidence=[
                {
                    "source": "test",
                    "content": {"key": "value"},
                    "timestamp": "2023-01-01T00:00:00Z"
                }
            ]
        )
        
        report = await reporter.generate([finding], sample_metadata)
        data = json.loads(report)
        
        # Check that complex data was properly serialized
        assert data["findings"][0]["details"]["nested"]["key"] == "value"
        assert data["findings"][0]["details"]["list"] == [1, 2, 3]
        assert data["findings"][0]["details"]["boolean"] is True
        assert data["findings"][0]["details"]["none"] is None
        
        # Check that evidence was properly serialized
        assert data["findings"][0]["evidence"][0]["source"] == "test"
        assert data["findings"][0]["evidence"][0]["content"]["key"] == "value"
    
    async def test_empty_findings(
        self,
        reporter: JSONReporter,
        sample_metadata: ReportMetadata
    ) -> None:
        ""Test report generation with no findings.""
        report = await reporter.generate([], sample_metadata)
        data = json.loads(report)
        
        assert data["findings"] == []
        assert data["summary"]["total_findings"] == 0
        
        # Check that all severity and confidence counts are zero
        for severity in data["summary"]["severity_counts"].values():
            assert severity == 0
            
        for confidence in data["summary"]["confidence_counts"].values():
            assert confidence == 0
    
    async def test_timestamps(
        self,
        reporter: JSONReporter,
        sample_findings: List[ReportFinding],
        sample_metadata: ReportMetadata
    ) -> None:
        ""Test that timestamps are properly formatted in the JSON report.""
        # Set a fixed timestamp for testing
        test_time = datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        sample_metadata.generated_at = test_time
        
        report = await reporter.generate(sample_findings, sample_metadata)
        data = json.loads(report)
        
        # Check that the timestamp is in ISO 8601 format
        assert data["metadata"]["generated_at"] == "2023-01-01T12:00:00+00:00"
        
        # Check finding timestamps if they exist
        for i, finding in enumerate(sample_findings):
            if hasattr(finding, "timestamp") and finding.timestamp:
                assert data["findings"][i]["timestamp"] == finding.timestamp.isoformat()
