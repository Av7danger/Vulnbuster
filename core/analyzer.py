import re
import logging
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

class Analyzer:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.false_positive_patterns = self.config.get('false_positive_patterns', [])
        self.risk_assessment_rules = self.config.get('risk_assessment_rules', {})
        self.confidence_threshold = self.config.get('confidence_threshold', 0.7)
        
    async def analyze_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze and filter findings"""
        analyzed_findings = []
        
        for finding in findings:
            # Analyze each finding
            analyzed_finding = await self.analyze_finding(finding)
            
            # Filter out false positives
            if not self.is_false_positive(analyzed_finding):
                analyzed_findings.append(analyzed_finding)
        
        # Sort by risk level
        analyzed_findings.sort(key=lambda x: self.get_risk_score(x), reverse=True)
        
        logging.info(f"Analyzed {len(findings)} findings, kept {len(analyzed_findings)} after filtering")
        return analyzed_findings
    
    async def analyze_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a single finding"""
        # Add analysis metadata
        finding['confidence'] = self.calculate_confidence(finding)
        finding['risk_score'] = self.get_risk_score(finding)
        finding['false_positive_probability'] = self.calculate_false_positive_probability(finding)
        finding['exploitability'] = self.assess_exploitability(finding)
        finding['impact'] = self.assess_impact(finding)
        
        # Add CWE mapping if not present
        if 'cwe' not in finding:
            finding['cwe'] = self.map_to_cwe(finding.get('type', ''))
        
        # Add remediation suggestions
        finding['remediation'] = self.get_remediation_suggestions(finding)
        
        return finding
    
    def is_false_positive(self, finding: Dict[str, Any]) -> bool:
        """Check if finding is likely a false positive"""
        # Check against known false positive patterns
        for pattern in self.false_positive_patterns:
            if self.matches_pattern(finding, pattern):
                return True
        
        # Check confidence threshold
        if finding.get('confidence', 0) < self.confidence_threshold:
            return True
        
        # Check false positive probability
        if finding.get('false_positive_probability', 0) > 0.8:
            return True
        
        return False
    
    def calculate_confidence(self, finding: Dict[str, Any]) -> float:
        """Calculate confidence score for finding"""
        confidence = 0.5  # Base confidence
        
        # Increase confidence based on indicators
        if finding.get('response_code') in [200, 500]:
            confidence += 0.2
        
        if finding.get('response_time') and finding['response_time'] > 1000:
            confidence += 0.1
        
        if finding.get('payload') and len(finding['payload']) > 10:
            confidence += 0.1
        
        if finding.get('parameter'):
            confidence += 0.1
        
        # Decrease confidence for certain conditions
        if finding.get('response_code') == 404:
            confidence -= 0.3
        
        if finding.get('response_size') and finding['response_size'] < 100:
            confidence -= 0.2
        
        return max(0.0, min(1.0, confidence))
    
    def get_risk_score(self, finding: Dict[str, Any]) -> int:
        """Calculate risk score (0-10)"""
        risk_score = 5  # Base score
        
        # Adjust based on vulnerability type
        vuln_type = finding.get('type', '').lower()
        if 'sql' in vuln_type:
            risk_score += 3
        elif 'xss' in vuln_type:
            risk_score += 2
        elif 'rce' in vuln_type or 'command' in vuln_type:
            risk_score += 4
        elif 'lfi' in vuln_type or 'rfi' in vuln_type:
            risk_score += 3
        
        # Adjust based on risk level
        risk_level = finding.get('risk', 'medium').lower()
        if risk_level == 'critical':
            risk_score += 3
        elif risk_level == 'high':
            risk_score += 2
        elif risk_level == 'low':
            risk_score -= 1
        
        # Adjust based on exploitability
        exploitability = finding.get('exploitability', 'medium')
        if exploitability == 'high':
            risk_score += 2
        elif exploitability == 'low':
            risk_score -= 1
        
        return max(0, min(10, risk_score))
    
    def calculate_false_positive_probability(self, finding: Dict[str, Any]) -> float:
        """Calculate probability that finding is a false positive"""
        probability = 0.3  # Base probability
        
        # Increase probability for certain conditions
        if finding.get('response_code') == 404:
            probability += 0.4
        
        if finding.get('response_size') and finding['response_size'] < 50:
            probability += 0.3
        
        if not finding.get('payload'):
            probability += 0.2
        
        # Decrease probability for strong indicators
        if finding.get('response_code') == 500:
            probability -= 0.2
        
        if finding.get('response_time') and finding['response_time'] > 2000:
            probability -= 0.1
        
        return max(0.0, min(1.0, probability))
    
    def assess_exploitability(self, finding: Dict[str, Any]) -> str:
        """Assess exploitability level"""
        vuln_type = finding.get('type', '').lower()
        
        if 'sql' in vuln_type and finding.get('response_code') == 500:
            return 'high'
        elif 'xss' in vuln_type and finding.get('reflected'):
            return 'high'
        elif 'rce' in vuln_type or 'command' in vuln_type:
            return 'high'
        elif 'lfi' in vuln_type and finding.get('response_code') == 200:
            return 'medium'
        else:
            return 'low'
    
    def assess_impact(self, finding: Dict[str, Any]) -> str:
        """Assess potential impact"""
        vuln_type = finding.get('type', '').lower()
        
        if 'sql' in vuln_type or 'rce' in vuln_type or 'command' in vuln_type:
            return 'high'
        elif 'xss' in vuln_type:
            return 'medium'
        elif 'lfi' in vuln_type or 'rfi' in vuln_type:
            return 'medium'
        else:
            return 'low'
    
    def map_to_cwe(self, vuln_type: str) -> str:
        """Map vulnerability type to CWE"""
        cwe_mapping = {
            'sql_injection': 'CWE-89',
            'xss': 'CWE-79',
            'lfi': 'CWE-22',
            'rfi': 'CWE-98',
            'rce': 'CWE-78',
            'idor': 'CWE-639',
            'csrf': 'CWE-352',
            'open_redirect': 'CWE-601',
            'ssrf': 'CWE-918',
            'xxe': 'CWE-611',
            'ssti': 'CWE-94',
            'upload': 'CWE-434'
        }
        
        for key, cwe in cwe_mapping.items():
            if key in vuln_type.lower():
                return cwe
        
        return 'CWE-200'  # Default to Information Exposure
    
    def get_remediation_suggestions(self, finding: Dict[str, Any]) -> List[str]:
        """Get remediation suggestions for finding"""
        suggestions = []
        vuln_type = finding.get('type', '').lower()
        
        if 'sql' in vuln_type:
            suggestions.extend([
                "Use parameterized queries or prepared statements",
                "Implement input validation and sanitization",
                "Use ORM frameworks with built-in protection",
                "Apply principle of least privilege to database users"
            ])
        elif 'xss' in vuln_type:
            suggestions.extend([
                "Implement proper output encoding",
                "Use Content Security Policy (CSP)",
                "Validate and sanitize all user inputs",
                "Use modern frameworks with XSS protection"
            ])
        elif 'lfi' in vuln_type or 'rfi' in vuln_type:
            suggestions.extend([
                "Validate file paths and restrict access",
                "Use whitelist approach for allowed files",
                "Implement proper access controls",
                "Use virtual file systems when possible"
            ])
        elif 'csrf' in vuln_type:
            suggestions.extend([
                "Implement CSRF tokens",
                "Use SameSite cookie attribute",
                "Validate Origin and Referer headers",
                "Implement double-submit cookie pattern"
            ])
        else:
            suggestions.append("Review and implement appropriate security controls")
        
        return suggestions
    
    def matches_pattern(self, finding: Dict[str, Any], pattern: Dict[str, Any]) -> bool:
        """Check if finding matches a pattern"""
        for key, value in pattern.items():
            if key not in finding:
                return False
            
            if isinstance(value, str):
                if value not in str(finding[key]):
                    return False
            elif isinstance(value, re.Pattern):
                if not value.search(str(finding[key])):
                    return False
            else:
                if finding[key] != value:
                    return False
        
        return True
    
    def get_analysis_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get summary of analysis results"""
        if not findings:
            return {
                'total_findings': 0,
                'risk_distribution': {},
                'confidence_distribution': {},
                'false_positive_rate': 0.0
            }
        
        risk_distribution = {}
        confidence_distribution = {'high': 0, 'medium': 0, 'low': 0}
        false_positive_count = 0
        
        for finding in findings:
            # Risk distribution
            risk = finding.get('risk', 'unknown')
            risk_distribution[risk] = risk_distribution.get(risk, 0) + 1
            
            # Confidence distribution
            confidence = finding.get('confidence', 0)
            if confidence >= 0.8:
                confidence_distribution['high'] += 1
            elif confidence >= 0.5:
                confidence_distribution['medium'] += 1
            else:
                confidence_distribution['low'] += 1
            
            # False positive count
            if finding.get('false_positive_probability', 0) > 0.5:
                false_positive_count += 1
        
        return {
            'total_findings': len(findings),
            'risk_distribution': risk_distribution,
            'confidence_distribution': confidence_distribution,
            'false_positive_rate': false_positive_count / len(findings) if findings else 0.0
        } 