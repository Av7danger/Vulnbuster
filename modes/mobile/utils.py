""
Utility functions for mobile security scanning.
"""
import hashlib
import logging
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

import requests
from androguard.core.bytecodes.apk import APK

logger = logging.getLogger(__name__)

def extract_apk_info(apk_path: Union[str, Path]) -> Dict[str, any]:
    """Extract basic information from an APK file.
    
    Args:
        apk_path: Path to the APK file
        
    Returns:
        Dictionary containing APK information
    """
    try:
        apk = APK(apk_path)
        return {
            'package_name': apk.get_package(),
            'version_name': apk.get_androidversion_name(),
            'version_code': apk.get_androidversion_code(),
            'min_sdk': apk.get_min_sdk_version(),
            'target_sdk': apk.get_target_sdk_version(),
            'permissions': apk.get_permissions(),
            'activities': apk.get_activities(),
            'services': apk.get_services(),
            'receivers': apk.get_receivers(),
            'providers': apk.get_providers(),
            'is_debuggable': apk.get_debuggable(),
            'is_backup_allowed': apk.get_application_attr_value('allowBackup'),
        }
    except Exception as e:
        logger.error(f"Error extracting APK info: {str(e)}")
        raise

def extract_ipa_info(ipa_path: Union[str, Path]) -> Dict[str, any]:
    """Extract basic information from an IPA file.
    
    Args:
        ipa_path: Path to the IPA file
        
    Returns:
        Dictionary containing IPA information
    """
    try:
        # This is a placeholder - actual implementation would require IPA parsing
        # with tools like ipatool, libimobiledevice, or similar
        return {
            'bundle_id': 'com.example.app',  # Extracted from Info.plist
            'version': '1.0',  # Extracted from Info.plist
            'build': '1',  # Extracted from Info.plist
            'minimum_os_version': '12.0',  # Extracted from Info.plist
            'permissions': [],  # Would extract from Info.plist
        }
    except Exception as e:
        logger.error(f"Error extracting IPA info: {str(e)}")
        raise

def calculate_hashes(file_path: Union[str, Path]) -> Dict[str, str]:
    """Calculate various hashes for a file.
    
    Args:
        file_path: Path to the file
        
    Returns:
        Dictionary containing different hash values
    """
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    hashes = {}
    hash_algorithms = {
        'md5': hashlib.md5(),
        'sha1': hashlib.sha1(),
        'sha256': hashlib.sha256(),
        'sha512': hashlib.sha512()
    }
    
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            for hash_obj in hash_algorithms.values():
                hash_obj.update(chunk)
    
    for name, hash_obj in hash_algorithms.items():
        hashes[name] = hash_obj.hexdigest()
    
    return hashes

def extract_strings(file_path: Union[str, Path], min_length: int = 4) -> List[str]:
    """Extract strings from a binary file.
    
    Args:
        file_path: Path to the binary file
        min_length: Minimum length of strings to extract
        
    Returns:
        List of extracted strings
    """
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    strings = []
    string_pattern = re.compile(b'[\x20-\x7E]{' + str(min_length).encode() + b',}')
    
    with open(file_path, 'rb') as f:
        data = f.read()
        for match in string_pattern.finditer(data):
            try:
                strings.append(match.group(0).decode('utf-8', errors='ignore'))
            except UnicodeDecodeError:
                continue
    
    return strings

def run_command(cmd: List[str], cwd: Optional[Union[str, Path]] = None) -> Tuple[int, str, str]:
    """Run a shell command and return the results.
    
    Args:
        cmd: Command to run as a list of strings
        cwd: Working directory for the command
        
    Returns:
        Tuple of (return_code, stdout, stderr)
    """
    try:
        result = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            check=False
        )
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        logger.error(f"Error running command {' '.join(cmd)}: {str(e)}")
        return -1, "", str(e)

def download_file(url: str, output_path: Union[str, Path], timeout: int = 30) -> bool:
    """Download a file from a URL.
    
    Args:
        url: URL to download from
        output_path: Path to save the downloaded file
        timeout: Request timeout in seconds
        
    Returns:
        True if download was successful, False otherwise
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    try:
        with requests.get(url, stream=True, timeout=timeout) as r:
            r.raise_for_status()
            with open(output_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
        return True
    except Exception as e:
        logger.error(f"Error downloading {url}: {str(e)}")
        return False

def create_temp_dir(prefix: str = "vulnbuster_") -> Path:
    """Create a temporary directory.
    
    Args:
        prefix: Prefix for the temporary directory name
        
    Returns:
        Path to the created temporary directory
    """
    temp_dir = Path(tempfile.mkdtemp(prefix=prefix))
    return temp_dir

def cleanup_temp_dir(temp_dir: Union[str, Path]) -> bool:
    """Clean up a temporary directory.
    
    Args:
        temp_dir: Path to the temporary directory
        
    Returns:
        True if cleanup was successful, False otherwise
    """
    temp_dir = Path(temp_dir)
    try:
        if temp_dir.exists() and temp_dir.is_dir():
            shutil.rmtree(temp_dir)
        return True
    except Exception as e:
        logger.error(f"Error cleaning up temporary directory {temp_dir}: {str(e)}")
        return False

def is_valid_apk(file_path: Union[str, Path]) -> bool:
    """Check if a file is a valid APK.
    
    Args:
        file_path: Path to the file to check
        
    Returns:
        True if the file is a valid APK, False otherwise
    """
    try:
        file_path = Path(file_path)
        if not file_path.exists() or not file_path.is_file():
            return False
            
        # Check file signature (APK files start with PK/ZIP magic number)
        with open(file_path, 'rb') as f:
            magic = f.read(4)
            return magic == b'PK\x03\x04' or magic == b'PK\x05\x06' or magic == b'PK\x07\x08'
    except Exception:
        return False

def is_valid_ipa(file_path: Union[str, Path]) -> bool:
    """Check if a file is a valid IPA.
    
    Args:
        file_path: Path to the file to check
        
    Returns:
        True if the file is a valid IPA, False otherwise
    """
    try:
        file_path = Path(file_path)
        if not file_path.exists() or not file_path.is_file():
            return False
            
        # Check file extension and zip structure
        if file_path.suffix.lower() != '.ipa':
            return False
            
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            # Check for Payload directory and .app bundle
            return any(name.startswith('Payload/') and name.endswith('.app/') for name in zip_ref.namelist())
    except (zipfile.BadZipFile, IOError):
        return False
    except Exception:
        return False

def find_files(directory: Union[str, Path], pattern: str) -> List[Path]:
    """Find files in a directory matching a pattern.
    
    Args:
        directory: Directory to search in
        pattern: Glob pattern to match files against
        
    Returns:
        List of matching file paths
    """
    directory = Path(directory)
    if not directory.exists() or not directory.is_dir():
        return []
    
    return list(directory.rglob(pattern))

def extract_zip(zip_path: Union[str, Path], output_dir: Union[str, Path]) -> bool:
    """Extract a ZIP file to a directory.
    
    Args:
        zip_path: Path to the ZIP file
        output_dir: Directory to extract to
        
    Returns:
        True if extraction was successful, False otherwise
    """
    try:
        zip_path = Path(zip_path)
        output_dir = Path(output_dir)
        
        if not zip_path.exists() or not zip_path.is_file():
            return False
            
        output_dir.mkdir(parents=True, exist_ok=True)
        
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(output_dir)
            
        return True
    except Exception as e:
        logger.error(f"Error extracting {zip_path}: {str(e)}")
        return False
