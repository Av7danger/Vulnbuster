"""
Mobile Security Analysis Demo

This script demonstrates how to use the mobile security analysis tools
for analyzing Android and iOS applications.
"""
import asyncio
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Add the project root to the Python path
import sys
sys.path.append(str(Path(__file__).parent.parent))

from modes.mobile.platform_checks import (
    AndroidSecurityChecks,
    IOSSecurityChecks,
    CheckType
)
from modes.mobile.bugbounty_agent import BugBountyAgent
from modes.mobile.models import Finding, Severity, Platform, BountyTarget, BountyTargetType
from modes.mobile.train_ai_model import MobileSecurityModelTrainer


class MobileSecurityDemo:
    """Demonstrates mobile security analysis capabilities."""
    
    def __init__(self, output_dir: str = "output/mobile_analysis"):
        """Initialize the demo."""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize platform checkers
        self.android_checks = AndroidSecurityChecks()
        self.ios_checks = IOSSecurityChecks()
        
        # Initialize AI model (if available)
        self.ai_model = None
        self._load_ai_model()
    
    def _load_ai_model(self, model_path: Optional[str] = None):
        """Load a pre-trained AI model for security analysis."""
        try:
            if model_path is None:
                # Try to find the latest model
                model_dir = Path("models/mobile_security")
                if model_dir.exists():
                    model_paths = list(model_dir.glob("mobile_security_model_*"))
                    if model_paths:
                        model_path = str(sorted(model_paths, reverse=True)[0])
            
            if model_path and Path(model_path).exists():
                self.ai_model = MobileSecurityModelTrainer.load(model_path)
                logger.info(f"Loaded AI model from {model_path}")
            else:
                logger.warning("No AI model found. Some features may be limited.")
        except Exception as e:
            logger.error(f"Error loading AI model: {str(e)}", exc_info=True)
    
    async def analyze_android_app(self, apk_path: str) -> List[Finding]:
        """Analyze an Android application.
        
        Args:
            apk_path: Path to the APK file
            
        Returns:
            List of security findings
        """
        logger.info(f"Analyzing Android app: {apk_path}")
        
        # Create a target for the BugBountyAgent
        target = BountyTarget(
            identifier=Path(apk_path).stem,
            target_type=BountyTargetType.ANDROID_APP,
            platform=Platform.ANDROID,
            path=apk_path
        )
        
        # Initialize the agent
        agent = BugBountyAgent(
            target=target,
            output_dir=self.output_dir / "android",
            config={
                'frida': {'enabled': False},  # Disable Frida for demo
                'dynamic_analysis': {'enabled': False}  # Disable dynamic analysis for demo
            }
        )
        
        # Run the analysis
        findings = await agent.run_scan()
        
        # Run additional platform checks
        platform_findings = await self._run_platform_checks(agent, Platform.ANDROID)
        findings.extend(platform_findings)
        
        # Analyze with AI model if available
        if self.ai_model:
            ai_analysis = await self._analyze_with_ai(findings)
            findings.extend(ai_analysis)
        
        return findings
    
    async def analyze_ios_app(self, ipa_path: str) -> List[Finding]:
        """Analyze an iOS application.
        
        Args:
            ipa_path: Path to the IPA file
            
        Returns:
            List of security findings
        """
        logger.info(f"Analyzing iOS app: {ipa_path}")
        
        # Create a target for the BugBountyAgent
        target = BountyTarget(
            identifier=Path(ipa_path).stem,
            target_type=BountyTargetType.IOS_APP,
            platform=Platform.IOS,
            path=ipa_path
        )
        
        # Initialize the agent
        agent = BugBountyAgent(
            target=target,
            output_dir=self.output_dir / "ios",
            config={
                'frida': {'enabled': False},  # Disable Frida for demo
                'dynamic_analysis': {'enabled': False}  # Disable dynamic analysis for demo
            }
        )
        
        # Run the analysis
        findings = await agent.run_scan()
        
        # Run additional platform checks
        platform_findings = await self._run_platform_checks(agent, Platform.IOS)
        findings.extend(platform_findings)
        
        # Analyze with AI model if available
        if self.ai_model:
            ai_analysis = await self._analyze_with_ai(findings)
            findings.extend(ai_analysis)
        
        return findings
    
    async def _run_platform_checks(self, agent, platform: Platform) -> List[Finding]:
        """Run platform-specific security checks."""
        findings = []
        
        try:
            # Get the appropriate checker
            checker = self.android_checks if platform == Platform.ANDROID else self.ios_checks
            
            # Prepare context for the checks
            context = await agent._get_dynamic_analysis_data()
            
            # Run all checks
            for check_id in checker.checks:
                try:
                    check_findings = checker.run_check(check_id, context)
                    findings.extend(check_findings)
                except Exception as e:
                    logger.error(f"Error running check {check_id}: {str(e)}", exc_info=True)
            
            logger.info(f"Ran {len(checker.checks)} {platform.value} security checks")
            
        except Exception as e:
            logger.error(f"Error running platform checks: {str(e)}", exc_info=True)
            findings.append(
                Finding(
                    title="Platform Check Error",
                    description=f"Error running platform checks: {str(e)}",
                    severity=Severity.MEDIUM,
                    category="Analysis Error"
                )
            )
        
        return findings
    
    async def _analyze_with_ai(self, findings: List[Finding]) -> List[Finding]:
        """Analyze findings with the AI model."""
        if not self.ai_model:
            return []
        
        try:
            # Convert findings to the format expected by the AI model
            findings_data = []
            for finding in findings:
                findings_data.append({
                    'description': finding.description,
                    'context': finding.context or {},
                    'severity': finding.severity.value.lower(),
                    'raw_data': finding.raw_data or {}
                })
            
            # Get AI predictions
            ai_results = self.ai_model.predict(findings_data)
            
            # Process AI results
            ai_findings = []
            for i, result in enumerate(ai_results):
                if 'predicted_labels' in result and result['predicted_labels']:
                    original = findings[i]
                    
                    # Create a new finding for each predicted label
                    for pred in result['predicted_labels']:
                        ai_findings.append(
                            Finding(
                                title=f"AI Analysis: {pred['label'].replace('_', ' ').title()}",
                                description=(
                                    f"The AI model identified a potential {pred['label']} issue "
                                    f"with {pred['confidence']:.1%} confidence.\n\n"
                                    f"Original finding: {original.title}"
                                ),
                                severity=original.severity,
                                category=f"AI/{pred['label'].upper()}",
                                confidence=pred['confidence'],
                                context={
                                    'original_finding': original.to_dict(),
                                    'ai_analysis': {
                                        'label': pred['label'],
                                        'confidence': pred['confidence']
                                    }
                                }
                            )
                        )
            
            logger.info(f"AI analysis identified {len(ai_findings)} potential issues")
            return ai_findings
            
        except Exception as e:
            logger.error(f"Error in AI analysis: {str(e)}", exc_info=True)
            return [
                Finding(
                    title="AI Analysis Error",
                    description=f"Error during AI analysis: {str(e)}",
                    severity=Severity.MEDIUM,
                    category="Analysis Error"
                )
            ]
    
    def save_findings(self, findings: List[Finding], output_file: str) -> str:
        """Save findings to a JSON file."""
        output_path = self.output_dir / output_file
        
        # Convert findings to dictionaries
        findings_dicts = [f.to_dict() for f in findings]
        
        # Save to file
        with open(output_path, 'w') as f:
            json.dump(findings_dicts, f, indent=2)
        
        logger.info(f"Saved {len(findings)} findings to {output_path}")
        return str(output_path)


async def main():
    """Run the mobile security analysis demo."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Mobile Security Analysis Demo')
    parser.add_argument('--android', type=str, help='Path to Android APK file')
    parser.add_argument('--ios', type=str, help='Path to iOS IPA file')
    parser.add_argument('--output', type=str, default='findings.json',
                       help='Output file name for findings')
    
    args = parser.parse_args()
    
    if not args.android and not args.ios:
        print("Error: You must specify either --android or --ios")
        return 1
    
    # Initialize the demo
    demo = MobileSecurityDemo()
    
    # Run the appropriate analysis
    if args.android:
        findings = await demo.analyze_android_app(args.android)
    else:
        findings = await demo.analyze_ios_app(args.ios)
    
    # Save the findings
    output_file = demo.save_findings(findings, args.output)
    
    # Print a summary
    print("\nAnalysis Complete!")
    print(f"Found {len(findings)} security issues")
    print(f"Results saved to: {output_file}")
    
    # Print a summary by severity
    severity_counts = {}
    for finding in findings:
        sev = finding.severity.value
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    print("\nFindings by severity:")
    for sev in sorted(severity_counts.keys(), reverse=True):
        print(f"  {sev}: {severity_counts[sev]}")
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(asyncio.run(main()))
