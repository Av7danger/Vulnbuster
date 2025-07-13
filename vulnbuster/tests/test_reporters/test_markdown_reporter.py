""
Test cases for Markdown reporter.
"""

import re
from pathlib import Path
from typing import Any, Dict, List

import pytest

from vulnbuster.interfaces.enhanced_reporter import (
    MarkdownReporter, ReportFormat, ReportOptions, ReportSeverity, ReportConfidence,
    ReportFinding, ReportMetadata
)
from .test_base import TestBaseReporter

class TestMarkdownReporter(TestBaseReporter):
    """Test cases for Markdown reporter."""
    
    reporter_class = MarkdownReporter
    format = ReportFormat.MARKDOWN
    
    @pytest.fixture
    def reporter(self, report_options: Dict[str, Any]) -> MarkdownReporter:
        ""Create a Markdown reporter instance with default options.""
        return MarkdownReporter(ReportOptions(
            format=ReportFormat.MARKDOWN,
            **report_options
        ))
    
    async def test_markdown_structure(
        self,
        reporter: MarkdownReporter,
        sample_findings: List[ReportFinding],
        sample_metadata: ReportMetadata
    ) -> None:
        ""Test that the Markdown report has the correct structure.""
        report = await reporter.generate(sample_findings, sample_metadata)
        
        # Check basic Markdown structure
        lines = report.split('\n')
        
        # Should start with a level 1 heading with the report title
        assert lines[0].startswith('# ')
        assert sample_metadata.title in lines[0]
        
        # Should contain a table of contents
        assert "## Table of Contents" in report
        
        # Should have a findings section
        assert "## Findings" in report
        
        # Each finding should be a level 3 heading
        for finding in sample_findings:
            assert f"### {finding.title}" in report
    
    async def test_finding_metadata(
        self,
        reporter: MarkdownReporter,
        sample_findings: List[ReportFinding],
        sample_metadata: ReportMetadata
    ) -> None:
        ""Test that finding metadata is properly formatted in the Markdown report.""
        report = await reporter.generate(sample_findings, sample_metadata)
        
        for finding in sample_findings:
            # Check severity and confidence
            assert f"**Severity:** {finding.severity.upper()}" in report
            assert f"**Confidence:** {finding.confidence.upper()}" in report
            
            # Check description
            assert finding.description in report
            
            # Check location
            if finding.location:
                assert f"**Location:** `{finding.location}`" in report
    
    async def test_evidence_rendering(
        self,
        reporter: MarkdownReporter,
        sample_findings: List[ReportFinding],
        sample_metadata: ReportMetadata
    ) -> None:
        ""Test that evidence is properly rendered in the Markdown report.""
        reporter.options.include_evidence = True
        report = await reporter.generate(sample_findings, sample_metadata)
        
        for finding in sample_findings:
            if finding.evidence:
                for evidence in finding.evidence:
                    # Check evidence source is in a heading
                    assert f"#### {evidence['source']}" in report
                    # Check evidence content is in a code block
                    assert f"```\n{evidence['content']}\n```" in report
    
    async def test_remediation_rendering(
        self,
        reporter: MarkdownReporter,
        sample_findings: List[ReportFinding],
        sample_metadata: ReportMetadata
    ) -> None:
        ""Test that remediation information is properly rendered.""
        reporter.options.include_remediation = True
        report = await reporter.generate(sample_findings, sample_metadata)
        
        for finding in sample_findings:
            if finding.remediation:
                # Check remediation section exists
                assert "#### Remediation" in report
                # Check remediation content is included
                assert finding.remediation in report
    
    async def test_references_rendering(
        self,
        reporter: MarkdownReporter,
        sample_findings: List[ReportFinding],
        sample_metadata: ReportMetadata
    ) -> None:
        ""Test that references are properly rendered as links.""
        reporter.options.include_references = True
        report = await reporter.generate(sample_findings, sample_metadata)
        
        for finding in sample_findings:
            if finding.references:
                # Check references section exists
                assert "#### References" in report
                
                # Check each reference is a proper Markdown link
                for ref in finding.references:
                    # Should be in the format: - [URL](URL)
                    assert f"- [{ref}]({ref})" in report
    
    async def test_custom_template(
        self,
        reporter: MarkdownReporter,
        sample_findings: List[ReportFinding],
        sample_metadata: ReportMetadata,
        markdown_template_path: Path,
        temp_output_dir: Path
    ) -> None:
        ""Test that a custom template can be used for the Markdown report.""
        # Set a custom template
        reporter.options.template = str(markdown_template_path)
        
        # Generate the report
        output_file = temp_output_dir / "custom_template_test.md"
        reporter.options.output_file = output_file
        
        report = await reporter.generate(sample_findings, sample_metadata)
        await reporter.save(report)
        
        # Check that the report was generated
        assert output_file.exists()
        
        # Check that the custom template was used
        content = output_file.read_text(encoding='utf-8')
        assert "# " + sample_metadata.title in content
        
        # Check that all findings are included
        for finding in sample_findings:
            assert f"### {finding.title}" in content
    
    async def test_severity_emoji(
        self,
        reporter: MarkdownReporter,
        sample_findings: List[ReportFinding],
        sample_metadata: ReportMetadata
    ) -> None:
        ""Test that severity levels are indicated with appropriate emojis.""
        report = await reporter.generate(sample_findings, sample_metadata)
        
        # Check that each finding has an emoji based on its severity
        for finding in sample_findings:
            if finding.severity == ReportSeverity.CRITICAL:
                assert "🔴" in report
            elif finding.severity == ReportSeverity.HIGH:
                assert "🟠" in report
            elif finding.severity == ReportSeverity.MEDIUM:
                assert "🟡" in report
            elif finding.severity == ReportSeverity.LOW:
                assert "🔵" in report
            else:  # INFO or UNKNOWN
                assert "⚪" in report or "ℹ️" in report
    
    async def test_code_blocks(
        self,
        reporter: MarkdownReporter,
        sample_metadata: ReportMetadata
    ) -> None:
        ""Test that code blocks in descriptions and evidence are properly formatted.""
        # Create a finding with code in the description
        finding = ReportFinding(
            id="code-test",
            title="Code Block Test",
            description="""
            This is a test with a code block:
            
            ```python
            def test():
                print("Hello, world!")
            ```
            
            And some more text.
            """,
            severity=ReportSeverity.MEDIUM,
            confidence=ReportConfidence.FIRM,
            location="https://example.com/code-test"
        )
        
        report = await reporter.generate([finding], sample_metadata)
        
        # Check that the code block is properly formatted
        assert "```python\n            def test():\n                print(\"Hello, world!\")\n            ```" in report
    
    async def test_table_of_contents(
        self,
        reporter: MarkdownReporter,
        sample_findings: List[ReportFinding],
        sample_metadata: ReportMetadata
    ) -> None:
        ""Test that the table of contents is generated correctly.""
        report = await reporter.generate(sample_findings, sample_metadata)
        
        # Find the table of contents section
        toc_start = report.find("## Table of Contents")
        assert toc_start != -1, "Table of contents not found"
        
        # Get the table of contents
        toc_section = report[toc_start:report.find("##", toc_start + 1)]
        
        # Check that each finding is in the table of contents
        for finding in sample_findings:
            # The title should be a link in the format [Title](#title-id)
            # Convert title to a slug for the ID
            slug = finding.title.lower().replace(' ', '-')
            slug = re.sub(r'[^a-z0-9-]', '', slug)
            assert f"- [{finding.title}](#{slug})" in toc_section
