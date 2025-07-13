"""
Tests for mobile platform security checks.
"""
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from modes.mobile.platform_checks import (
    AndroidSecurityChecks,
    IOSSecurityChecks,
    PlatformCheck,
    CheckType
)
from modes.models import Finding, Severity, Platform

# Test data
SAMPLE_MANIFEST = {
    'application': {
        'android:debuggable': 'true',
        'android:allowBackup': 'true',
        'android:fullBackupContent': None,
        'activity': [
            {
                'android:name': '.MainActivity',
                'android:exported': 'true'
            }
        ]
    }
}

SAMPLE_INFO_PLIST = {
    'NSAppTransportSecurity': {
        'NSAllowsArbitraryLoads': True
    },
    'CFBundleURLTypes': [
        {
            'CFBundleURLSchemes': ['myapp', 'http']
        }
    ]
}

@pytest.fixture
def android_checks():
    return AndroidSecurityChecks()

@pytest.fixture
def ios_checks():
    return IOSSecurityChecks()

class TestAndroidSecurityChecks:
    """Tests for Android security checks."""
    
    def test_check_debuggable(self, android_checks):
        """Test detection of debuggable flag."""
        context = {'manifest': SAMPLE_MANIFEST}
        findings = android_checks.run_check('debuggable', context)
        assert len(findings) == 1
        assert findings[0].title == 'Debug Mode Enabled'
        assert findings[0].severity == Severity.HIGH
    
    def test_check_backup(self, android_checks):
        """Test detection of insecure backup configuration."""
        context = {'manifest': SAMPLE_MANIFEST}
        findings = android_checks.run_check('backup', context)
        assert len(findings) == 1
        assert findings[0].title == 'Backup Config'
        assert findings[0].severity == Severity.MEDIUM
    
    def test_check_exported_components(self, android_checks):
        """Test detection of exported components without permissions."""
        context = {'manifest': SAMPLE_MANIFEST}
        findings = android_checks.run_check('exported', context)
        assert len(findings) == 1
        assert 'Exported' in findings[0].title
        assert findings[0].severity == Severity.HIGH
    
    def test_check_webview_ssl(self, android_checks):
        """Test detection of WebView SSL issues."""
        context = {
            'webview': {
                'ignores_ssl_errors': True
            }
        }
        findings = android_checks.run_check('webview_ssl', context)
        assert len(findings) > 0
        assert 'SSL' in findings[0].title
    
    def test_check_secrets(self, android_checks, tmp_path):
        """Test detection of hardcoded secrets."""
        # Create a temporary file with a secret
        test_file = tmp_path / "test.java"
        test_file.write_text("String apiKey = \"1234-5678-9012\";")
        
        context = {
            'source_files': [test_file]
        }
        findings = android_checks.run_check('secrets', context)
        assert len(findings) > 0
        assert 'Secret' in findings[0].title

class TestIOSSecurityChecks:
    """Tests for iOS security checks."""
    
    def test_check_plist_security(self, ios_checks):
        """Test detection of insecure plist settings."""
        context = {'info_plist': SAMPLE_INFO_PLIST}
        findings = ios_checks.run_check('plist', context)
        assert len(findings) > 0
        assert any('ATS' in f.title for f in findings)
        assert any('URL Scheme' in f.title for f in findings)
    
    def test_check_keychain(self, ios_checks):
        """Test detection of insecure keychain usage."""
        context = {
            'keychain': {
                'items': [
                    {
                        'account': 'test',
                        'accessibility': 'kSecAttrAccessibleAlways'
                    }
                ]
            }
        }
        findings = ios_checks.run_check('keychain', context)
        assert len(findings) > 0
        assert 'Keychain' in findings[0].title
    
    def test_check_webview(self, ios_checks):
        """Test detection of WebView security issues."""
        context = {
            'webview': {
                'javascript_enabled': True
            }
        }
        findings = ios_checks.run_check('webview', context)
        assert len(findings) > 0
        assert 'WebView' in findings[0].title
    
    def test_check_jailbreak(self, ios_checks):
        """Test detection of jailbreak detection."""
        context = {
            'jailbreak': {
                'detection_implemented': False
            }
        }
        findings = ios_checks.run_check('jailbreak', context)
        assert len(findings) > 0
        assert 'Jailbreak' in findings[0].title

@pytest.mark.asyncio
async def test_platform_check_integration():
    """Test integration of platform checks with BugBountyAgent."""
    # Mock the BugBountyAgent and its dependencies
    with patch('modes.mobile.bugbounty_agent.AdvancedMobileAnalyzer') as mock_analyzer, \
         patch('modes.mobile.bugbounty_agent.DynamicAnalyzer') as mock_dynamic_analyzer:
        
        # Setup mock analyzer
        mock_analyzer.return_value.analyze.return_value = []
        
        # Setup mock dynamic analyzer
        mock_dynamic_analyzer.return_value.get_webview_data.return_value = {}
        mock_dynamic_analyzer.return_value.get_storage_operations.return_value = []
        
        # Import here to avoid circular imports
        from modes.mobile.bugbounty_agent import BugBountyAgent, BountyTarget, BountyTargetType
        
        # Create a test target
        target = BountyTarget(
            identifier="com.example.test",
            target_type=BountyTargetType.ANDROID_APP,
            platform=Platform.ANDROID
        )
        
        # Initialize the agent
        agent = BugBountyAgent(
            target=target,
            output_dir=Path("/tmp"),
            config={
                'frida': {
                    'enabled': False
                }
            }
        )
        
        # Mock the platform check methods
        with patch.object(agent, '_get_manifest_data', return_value=SAMPLE_MANIFEST), \
             patch.object(agent, '_get_webview_data', return_value={"ignores_ssl_errors": True}), \
             patch.object(agent, '_get_source_files', return_value=[]):
            
            # Run the assessment
            await agent._android_assessment()
            
            # Verify findings were added
            assert len(agent.findings) > 0
            assert any(f.title == 'Debug Mode Enabled' for f in agent.findings)
            assert any('WebView' in f.title for f in agent.findings)
