"""
Report Generator with AI-powered analysis
"""

import json
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path
from datetime import datetime
import jinja2

from ai.ai_bridge import ask_mixtral

class Reporter:
    def __init__(self, output_dir: str = "reports", mode: str = "web"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        if mode == "web":
            self.template_dir = Path("modes/web/templates")
        else:
            self.template_dir = Path("templates")
        self.findings = []
        self.scan_metadata = {}
        
    def add_finding(self, finding: Dict[str, Any]):
        """Add a vulnerability finding"""
        self.findings.append(finding)
        
    def set_metadata(self, metadata: Dict[str, Any]):
        """Set scan metadata"""
        self.scan_metadata = metadata
        
    async def generate_reports(self, formats: List[str] = None, use_ai: bool = False, template: str = None, client_name: str = None) -> Dict[str, str]:
        """Generate reports in specified formats with optional AI enhancement, template, and client branding"""
        if formats is None:
            formats = ['html', 'json', 'markdown']
        if 'all' in formats:
            formats = ['html', 'json', 'markdown']
        report_files = {}
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        ai_summary = None
        if use_ai:
            ai_summary = await self._generate_ai_summary()
        for format_type in formats:
            try:
                if format_type == 'html':
                    report_file = await self._generate_html_report(timestamp, ai_summary, template=template, client_name=client_name)
                    report_files['html'] = str(report_file)
                elif format_type == 'json':
                    report_file = await self._generate_json_report(timestamp, ai_summary)
                    report_files['json'] = str(report_file)
                elif format_type == 'markdown':
                    report_file = await self._generate_markdown_report(timestamp, ai_summary)
                    report_files['markdown'] = str(report_file)
            except Exception as e:
                logging.error(f"Failed to generate {format_type} report: {e}")
        return report_files
    
    async def _generate_ai_summary(self) -> Dict[str, Any]:
        """Generate AI-powered analysis and summary"""
        try:
            if not self.findings:
                return {'summary': 'No vulnerabilities found', 'risk_level': 'low'}
            
            # Prepare findings for AI analysis
            findings_summary = []
            for finding in self.findings:
                findings_summary.append({
                    'type': finding.get('type', 'unknown'),
                    'severity': finding.get('severity', 'unknown'),
                    'url': finding.get('url', 'unknown'),
                    'parameter': finding.get('parameter', 'unknown'),
                    'evidence': finding.get('evidence', '')[:200]  # Truncate for AI
                })
            
            prompt = f"""
You are an expert offensive security analyst. Analyze these vulnerability findings and provide a comprehensive summary:

FINDINGS: {json.dumps(findings_summary, indent=2)}

TARGET: {self.scan_metadata.get('target_url', 'unknown')}
SCAN DATE: {self.scan_metadata.get('scan_date', 'unknown')}

Provide analysis in JSON format:
{{
    "executive_summary": "Brief overview of findings",
    "risk_assessment": "high/medium/low",
    "critical_findings": ["list of critical issues"],
    "exploit_chains": ["possible attack chains"],
    "recommendations": ["specific remediation steps"],
    "business_impact": "potential business impact",
    "technical_details": "technical analysis summary"
}}
"""
            
            ai_response = ask_mixtral(prompt)
            
            # Parse AI response
            try:
                if '{' in ai_response and '}' in ai_response:
                    start = ai_response.find('{')
                    end = ai_response.rfind('}') + 1
                    json_str = ai_response[start:end]
                    ai_analysis = json.loads(json_str)
                else:
                    ai_analysis = {
                        'executive_summary': ai_response[:500],
                        'risk_assessment': 'medium',
                        'critical_findings': [],
                        'exploit_chains': [],
                        'recommendations': [],
                        'business_impact': 'Unknown',
                        'technical_details': ai_response
                    }
            except Exception as e:
                logging.warning(f"Failed to parse AI analysis: {e}")
                ai_analysis = {
                    'executive_summary': ai_response[:500],
                    'risk_assessment': 'medium',
                    'critical_findings': [],
                    'exploit_chains': [],
                    'recommendations': [],
                    'business_impact': 'Unknown',
                    'technical_details': ai_response
                }
            
            return ai_analysis
            
        except Exception as e:
            logging.error(f"Failed to generate AI summary: {e}")
            return {
                'executive_summary': 'AI analysis failed',
                'risk_assessment': 'unknown',
                'critical_findings': [],
                'exploit_chains': [],
                'recommendations': [],
                'business_impact': 'Unknown',
                'technical_details': 'AI analysis unavailable'
            }
    
    async def _generate_html_report(self, timestamp: str, ai_summary: Optional[Dict[str, Any]] = None, template: str = None, client_name: str = None) -> Path:
        """Generate HTML report using the specified Jinja2 template and client name"""
        report_file = self.output_dir / f"vulnbuster_report_{timestamp}.html"
        # Prepare data for template
        template_data = {
            'scan_metadata': self.scan_metadata,
            'findings': self.findings,
            'ai_summary': ai_summary,
            'generation_time': datetime.now().isoformat(),
            'total_findings': len(self.findings),
            'risk_distribution': self._get_risk_distribution(),
            'vulnerability_types': self._get_vulnerability_types(),
            'client_name': client_name or 'Client',
            'scan_results': {
                'metadata': self.scan_metadata,
                'security_issues': self.findings,
                'ai_summary': ai_summary['executive_summary'] if ai_summary and 'executive_summary' in ai_summary else '',
                'ai_exploit_chain': ai_summary['exploit_chains'] if ai_summary and 'exploit_chains' in ai_summary else '',
                'dynamic_analysis': self.scan_metadata.get('dynamic_analysis', {}),
            }
        }
        # Select template
        template_name = None
        if template == 'pentest' or template is None:
            template_name = 'report_pentest.html.j2'
        elif template == 'web':
            template_name = 'web_report.html.j2'
        else:
            template_name = template
        # Load and render template
        env = jinja2.Environment(loader=jinja2.FileSystemLoader(['templates', str(self.template_dir)]))
        jinja_template = env.get_template(template_name)
        html_content = jinja_template.render(**template_data)
        # Write report
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        logging.info(f"Generated HTML report: {report_file}")
        return report_file
    
    async def _generate_json_report(self, timestamp: str, ai_summary: Optional[Dict[str, Any]] = None) -> Path:
        """Generate JSON report"""
        report_file = self.output_dir / f"vulnbuster_report_{timestamp}.json"
        
        report_data = {
            'metadata': {
                'generator': 'VulnBuster',
                'version': '1.0',
                'generation_time': datetime.now().isoformat(),
                **self.scan_metadata
            },
            'summary': {
                'total_findings': len(self.findings),
                'risk_distribution': self._get_risk_distribution(),
                'vulnerability_types': self._get_vulnerability_types(),
                'ai_analysis': ai_summary
            },
            'findings': self.findings
        }
        
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2)
        
        logging.info(f"Generated JSON report: {report_file}")
        return report_file
    
    async def _generate_markdown_report(self, timestamp: str, ai_summary: Optional[Dict[str, Any]] = None) -> Path:
        """Generate Markdown report"""
        report_file = self.output_dir / f"vulnbuster_report_{timestamp}.md"
        
        # Generate AI-powered markdown content
        markdown_content = await self._generate_ai_markdown(ai_summary)
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(markdown_content)
        
        logging.info(f"Generated Markdown report: {report_file}")
        return report_file
    
    async def _generate_ai_markdown(self, ai_summary: Optional[Dict[str, Any]] = None) -> str:
        """Generate AI-powered markdown content"""
        try:
            if not ai_summary:
                ai_summary = await self._generate_ai_summary()
            
            prompt = f"""
You are an expert security analyst. Create a professional markdown report based on this vulnerability scan:

AI ANALYSIS: {json.dumps(ai_summary, indent=2)}
FINDINGS COUNT: {len(self.findings)}
TARGET: {self.scan_metadata.get('target_url', 'unknown')}

Create a comprehensive markdown report with:
1. Executive Summary
2. Risk Assessment
3. Critical Findings
4. Technical Details
5. Recommendations
6. Exploit Chains
7. Business Impact

Use proper markdown formatting with headers, lists, code blocks, and tables where appropriate.
"""
            
            ai_markdown = ask_mixtral(prompt)
            
            # Add metadata header
            header = f"""# VulnBuster Security Assessment Report

**Target:** {self.scan_metadata.get('target_url', 'Unknown')}
**Scan Date:** {self.scan_metadata.get('scan_date', 'Unknown')}
**Total Findings:** {len(self.findings)}
**Report Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

"""
            
            return header + ai_markdown
            
        except Exception as e:
            logging.error(f"Failed to generate AI markdown: {e}")
            return self._generate_fallback_markdown()
    
    def _generate_fallback_html(self, data: Dict[str, Any]) -> str:
        """Generate fallback HTML if template is missing"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>VulnBuster Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .finding {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
        .high {{ border-left: 5px solid #ff4444; }}
        .medium {{ border-left: 5px solid #ffaa00; }}
        .low {{ border-left: 5px solid #44aa44; }}
        .ai-summary {{ background: #e8f4f8; padding: 15px; border-radius: 5px; margin: 20px 0; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>VulnBuster Security Assessment Report</h1>
        <p><strong>Target:</strong> {data['scan_metadata'].get('target_url', 'Unknown')}</p>
        <p><strong>Scan Date:</strong> {data['scan_metadata'].get('scan_date', 'Unknown')}</p>
        <p><strong>Total Findings:</strong> {data['total_findings']}</p>
    </div>
"""
        
        if data.get('ai_summary'):
            html += f"""
    <div class="ai-summary">
        <h2>AI Analysis Summary</h2>
        <p><strong>Risk Level:</strong> {data['ai_summary'].get('risk_assessment', 'Unknown')}</p>
        <p><strong>Executive Summary:</strong> {data['ai_summary'].get('executive_summary', 'No summary available')}</p>
    </div>
"""
        
        html += "<h2>Vulnerability Findings</h2>"
        
        for finding in data['findings']:
            severity_class = finding.get('severity', 'low').lower()
            html += f"""
    <div class="finding {severity_class}">
        <h3>{finding.get('type', 'Unknown Vulnerability')}</h3>
        <p><strong>Severity:</strong> {finding.get('severity', 'Unknown')}</p>
        <p><strong>URL:</strong> {finding.get('url', 'Unknown')}</p>
        <p><strong>Parameter:</strong> {finding.get('parameter', 'Unknown')}</p>
        <p><strong>Evidence:</strong> {finding.get('evidence', 'No evidence provided')}</p>
    </div>
"""
        
        html += """
</body>
</html>
"""
        return html
    
    def _generate_fallback_markdown(self) -> str:
        """Generate fallback markdown if AI fails"""
        markdown = f"""# VulnBuster Security Assessment Report

## Executive Summary
This report contains the results of a comprehensive security assessment using VulnBuster.

## Scan Information
- **Target:** {self.scan_metadata.get('target_url', 'Unknown')}
- **Scan Date:** {self.scan_metadata.get('scan_date', 'Unknown')}
- **Total Findings:** {len(self.findings)}

## Findings Summary
"""
        
        for finding in self.findings:
            markdown += f"""
### {finding.get('type', 'Unknown Vulnerability')}
- **Severity:** {finding.get('severity', 'Unknown')}
- **URL:** {finding.get('url', 'Unknown')}
- **Parameter:** {finding.get('parameter', 'Unknown')}
- **Evidence:** {finding.get('evidence', 'No evidence provided')}

"""
        
        return markdown
    
    def _get_risk_distribution(self) -> Dict[str, int]:
        """Get distribution of findings by risk level"""
        distribution = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for finding in self.findings:
            severity = finding.get('severity', 'low').lower()
            if severity in distribution:
                distribution[severity] += 1
        
        return distribution
    
    def _get_vulnerability_types(self) -> Dict[str, int]:
        """Get distribution of findings by vulnerability type"""
        types = {}
        
        for finding in self.findings:
            vuln_type = finding.get('type', 'unknown')
            types[vuln_type] = types.get(vuln_type, 0) + 1
        
        return types
    
    async def generate_poc_report(self, finding: Dict[str, Any]) -> str:
        """Generate AI-powered proof of concept for a finding"""
        try:
            prompt = f"""
You are an expert penetration tester. Create a detailed proof of concept (PoC) for this vulnerability:

VULNERABILITY: {finding.get('type', 'unknown')}
URL: {finding.get('url', 'unknown')}
PARAMETER: {finding.get('parameter', 'unknown')}
PAYLOAD: {finding.get('payload', 'unknown')}
EVIDENCE: {finding.get('evidence', 'unknown')}

Create a comprehensive PoC including:
1. curl command to reproduce
2. Browser-based reproduction steps
3. Exploitation impact
4. Remediation steps

Format as markdown with code blocks.
"""
            
            poc_content = ask_mixtral(prompt)
            return poc_content
            
        except Exception as e:
            logging.error(f"Failed to generate PoC: {e}")
            return f"# PoC Generation Failed\n\nError: {e}"
    
    def get_report_statistics(self) -> Dict[str, Any]:
        """Get report statistics"""
        return {
            'total_findings': len(self.findings),
            'risk_distribution': self._get_risk_distribution(),
            'vulnerability_types': self._get_vulnerability_types(),
            'scan_metadata': self.scan_metadata
        } 