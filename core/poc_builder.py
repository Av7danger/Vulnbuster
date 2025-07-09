"""
AI-Prompted PoC Builder
Generates exploit scripts using Mixtral for confirmed vulnerabilities
"""

import asyncio
import logging
import json
from typing import Dict, Any, List, Optional
from pathlib import Path
from datetime import datetime

from ai.ai_bridge import ask_mixtral

class POCBuilder:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.poc_dir = Path("reports/pocs")
        self.poc_dir.mkdir(parents=True, exist_ok=True)
        self.generated_pocs = []
        
    async def generate_poc(self, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Generate PoC for a vulnerability finding"""
        vuln_type = finding.get('type', 'unknown')
        url = finding.get('url', '')
        parameter = finding.get('parameter', '')
        payload = finding.get('payload', '')
        
        logging.info(f"Generating PoC for {vuln_type} at {url}")
        
        try:
            # Generate AI-powered PoC
            poc_content = await self._generate_ai_poc(finding)
            
            if poc_content:
                # Save PoC to file
                poc_file = await self._save_poc(finding, poc_content)
                
                result = {
                    'type': 'poc_generated',
                    'vulnerability': vuln_type,
                    'url': url,
                    'parameter': parameter,
                    'poc_file': str(poc_file),
                    'timestamp': datetime.now().isoformat(),
                    'description': f"PoC generated for {vuln_type}"
                }
                
                self.generated_pocs.append(result)
                logging.info(f"PoC generated: {poc_file}")
                return result
                
        except Exception as e:
            logging.error(f"Failed to generate PoC: {e}")
        
        return None
    
    async def _generate_ai_poc(self, finding: Dict[str, Any]) -> Optional[str]:
        """Generate PoC using AI"""
        vuln_type = finding.get('type', 'unknown')
        url = finding.get('url', '')
        parameter = finding.get('parameter', '')
        payload = finding.get('payload', '')
        evidence = finding.get('evidence', '')
        
        # Build context-aware prompt
        prompt = self._build_poc_prompt(vuln_type, url, parameter, payload, evidence)
        
        try:
            ai_response = ask_mixtral(prompt)
            return ai_response
            
        except Exception as e:
            logging.error(f"AI PoC generation failed: {e}")
            return None
    
    def _build_poc_prompt(self, vuln_type: str, url: str, parameter: str, payload: str, evidence: str) -> str:
        """Build context-aware prompt for PoC generation"""
        
        if vuln_type.lower() == 'xss':
            return f"""
You are an expert penetration tester. Create a comprehensive proof-of-concept (PoC) for a reflected XSS vulnerability.

VULNERABILITY: Reflected XSS
URL: {url}
PARAMETER: {parameter}
PAYLOAD: {payload}
EVIDENCE: {evidence[:200]}

Create a detailed PoC including:
1. curl command to reproduce
2. Browser-based reproduction steps
3. JavaScript payload variations
4. Impact assessment
5. Remediation steps

Format as Markdown with code blocks and clear sections.
"""
        
        elif vuln_type.lower() == 'sqli':
            return f"""
You are an expert penetration tester. Create a comprehensive proof-of-concept (PoC) for a SQL injection vulnerability.

VULNERABILITY: SQL Injection
URL: {url}
PARAMETER: {parameter}
PAYLOAD: {payload}
EVIDENCE: {evidence[:200]}

Create a detailed PoC including:
1. curl command to reproduce
2. Database enumeration commands
3. Data extraction examples
4. Impact assessment
5. Remediation steps

Format as Markdown with code blocks and clear sections.
"""
        
        elif vuln_type.lower() == 'upload':
            return f"""
You are an expert penetration tester. Create a comprehensive proof-of-concept (PoC) for a file upload vulnerability.

VULNERABILITY: File Upload
URL: {url}
PARAMETER: {parameter}
PAYLOAD: {payload}
EVIDENCE: {evidence[:200]}

Create a detailed PoC including:
1. curl command to upload shell
2. File extension bypass techniques
3. Shell access verification
4. Impact assessment
5. Remediation steps

Format as Markdown with code blocks and clear sections.
"""
        
        elif vuln_type.lower() == 'cmdinj':
            return f"""
You are an expert penetration tester. Create a comprehensive proof-of-concept (PoC) for a command injection vulnerability.

VULNERABILITY: Command Injection
URL: {url}
PARAMETER: {parameter}
PAYLOAD: {payload}
EVIDENCE: {evidence[:200]}

Create a detailed PoC including:
1. curl command to reproduce
2. Command execution examples
3. Reverse shell payloads
4. Impact assessment
5. Remediation steps

Format as Markdown with code blocks and clear sections.
"""
        
        elif vuln_type.lower() == 'idor':
            return f"""
You are an expert penetration tester. Create a comprehensive proof-of-concept (PoC) for an IDOR vulnerability.

VULNERABILITY: IDOR
URL: {url}
PARAMETER: {parameter}
PAYLOAD: {payload}
EVIDENCE: {evidence[:200]}

Create a detailed PoC including:
1. curl command to reproduce
2. Parameter manipulation examples
3. Data enumeration techniques
4. Impact assessment
5. Remediation steps

Format as Markdown with code blocks and clear sections.
"""
        
        else:
            return f"""
You are an expert penetration tester. Create a comprehensive proof-of-concept (PoC) for a {vuln_type} vulnerability.

VULNERABILITY: {vuln_type}
URL: {url}
PARAMETER: {parameter}
PAYLOAD: {payload}
EVIDENCE: {evidence[:200]}

Create a detailed PoC including:
1. curl command to reproduce
2. Exploitation steps
3. Impact assessment
4. Remediation steps

Format as Markdown with code blocks and clear sections.
"""
    
    async def _save_poc(self, finding: Dict[str, Any], poc_content: str) -> Path:
        """Save PoC to file"""
        vuln_type = finding.get('type', 'unknown')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create filename
        filename = f"poc_{vuln_type}_{timestamp}.md"
        poc_file = self.poc_dir / filename
        
        # Add metadata header
        header = f"""# Proof of Concept: {vuln_type.upper()}

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Vulnerability:** {vuln_type}
**URL:** {finding.get('url', 'Unknown')}
**Parameter:** {finding.get('parameter', 'Unknown')}
**Severity:** {finding.get('severity', 'Unknown')}

---

"""
        
        # Write PoC content
        with open(poc_file, 'w', encoding='utf-8') as f:
            f.write(header + poc_content)
        
        return poc_file
    
    async def generate_batch_pocs(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate PoCs for multiple findings"""
        results = []
        
        for finding in findings:
            poc_result = await self.generate_poc(finding)
            if poc_result:
                results.append(poc_result)
        
        return results
    
    async def generate_summary_report(self, findings: List[Dict[str, Any]]) -> Optional[Path]:
        """Generate a summary report of all PoCs"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            summary_file = self.poc_dir / f"poc_summary_{timestamp}.md"
            
            # Build summary content
            summary_content = f"""# Vulnerability PoC Summary Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Total Vulnerabilities:** {len(findings)}

## Vulnerabilities Found

"""
            
            # Group by vulnerability type
            vuln_groups = {}
            for finding in findings:
                vuln_type = finding.get('type', 'unknown')
                if vuln_type not in vuln_groups:
                    vuln_groups[vuln_type] = []
                vuln_groups[vuln_type].append(finding)
            
            # Add each vulnerability type
            for vuln_type, vuln_findings in vuln_groups.items():
                summary_content += f"### {vuln_type.upper()} ({len(vuln_findings)})\n\n"
                
                for finding in vuln_findings:
                    summary_content += f"- **URL:** {finding.get('url', 'Unknown')}\n"
                    summary_content += f"  - **Parameter:** {finding.get('parameter', 'Unknown')}\n"
                    summary_content += f"  - **Severity:** {finding.get('severity', 'Unknown')}\n"
                    summary_content += f"  - **Evidence:** {finding.get('evidence', 'No evidence')[:100]}...\n\n"
            
            # Add PoC files generated
            summary_content += "## Generated PoC Files\n\n"
            for poc in self.generated_pocs:
                summary_content += f"- **{poc['vulnerability']}:** {poc['poc_file']}\n"
            
            # Write summary
            with open(summary_file, 'w', encoding='utf-8') as f:
                f.write(summary_content)
            
            logging.info(f"PoC summary report generated: {summary_file}")
            return summary_file
            
        except Exception as e:
            logging.error(f"Failed to generate PoC summary: {e}")
            return None
    
    def get_poc_statistics(self) -> Dict[str, Any]:
        """Get PoC generation statistics"""
        return {
            'total_pocs_generated': len(self.generated_pocs),
            'vulnerability_types': list(set(poc.get('vulnerability', '') for poc in self.generated_pocs)),
            'poc_files': [poc.get('poc_file', '') for poc in self.generated_pocs],
            'generation_timestamps': [poc.get('timestamp', '') for poc in self.generated_pocs]
        }
    
    def clear_pocs(self):
        """Clear generated PoCs"""
        self.generated_pocs.clear()
        logging.info("PoC cache cleared") 