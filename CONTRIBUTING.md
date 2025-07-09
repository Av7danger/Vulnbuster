# Contributing to VulnBuster

Thank you for your interest in contributing to VulnBuster! This document provides guidelines and information for contributors.

## Table of Contents
1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Development Setup](#development-setup)
4. [Contributing Guidelines](#contributing-guidelines)
5. [Code Style](#code-style)
6. [Testing](#testing)
7. [Documentation](#documentation)
8. [Security](#security)
9. [Pull Request Process](#pull-request-process)

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Getting Started

### Prerequisites
- Python 3.11 or higher
- Git
- Basic knowledge of offensive security concepts
- Familiarity with Python async programming

### Fork and Clone
```bash
# Fork the repository on GitHub
# Then clone your fork
git clone https://github.com/your-username/Vulnbuster.git
cd Vulnbuster

# Add the original repository as upstream
git remote add upstream https://github.com/Av7danger/Vulnbuster.git
```

## Development Setup

### Virtual Environment
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install development dependencies
pip install -r requirements-dev.txt
pip install -e .
```

### Pre-commit Hooks
```bash
# Install pre-commit hooks
pre-commit install

# Run pre-commit on all files
pre-commit run --all-files
```

## Contributing Guidelines

### Types of Contributions

#### 🐛 Bug Reports
- Use the bug report template
- Provide detailed reproduction steps
- Include error messages and stack traces
- Specify your environment (OS, Python version, etc.)

#### ✨ Feature Requests
- Use the feature request template
- Describe the use case and benefits
- Consider implementation complexity
- Check if the feature aligns with project goals

#### 🔧 Code Contributions
- Fork the repository
- Create a feature branch: `git checkout -b feature/amazing-feature`
- Make your changes
- Add tests for new functionality
- Update documentation
- Submit a pull request

#### 📚 Documentation
- Fix typos and grammar
- Improve clarity and structure
- Add missing examples
- Update API documentation

#### 🧪 Testing
- Add unit tests for new features
- Improve test coverage
- Fix failing tests
- Add integration tests

### Issue Labels
- `bug`: Something isn't working
- `enhancement`: New feature or request
- `documentation`: Improvements or additions to documentation
- `good first issue`: Good for newcomers
- `help wanted`: Extra attention is needed
- `security`: Security-related issues
- `ai`: AI-related features or improvements
- `web`: Web application scanning
- `mobile`: Mobile application scanning
- `cloud`: Cloud infrastructure scanning
- `iot`: IoT device scanning
- `binary`: Binary exploitation
- `ctf`: CTF-specific features

## Code Style

### Python Style Guide
We follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) with some modifications:

- Line length: 88 characters (Black default)
- Use type hints for all function parameters and return values
- Use async/await for I/O operations
- Use f-strings for string formatting
- Use descriptive variable and function names

### Code Formatting
```bash
# Format code with Black
black .

# Sort imports with isort
isort .

# Check code style with flake8
flake8 .

# Type checking with mypy
mypy .
```

### File Structure
```
vulnbuster/
├── core/           # Core framework components
├── ai/             # AI and machine learning
├── modes/          # Scanning modes (web, mobile, cloud, etc.)
├── modules/        # Shared vulnerability modules
├── post_exploitation/  # Post-exploitation tools
├── binex/          # Binary exploitation
├── network/        # Network reconnaissance
├── recon/          # Reconnaissance tools
├── bypass/         # WAF and protection bypass
├── dynamic/        # Dynamic analysis
├── oob/            # Out-of-band detection
├── ctf_modules/    # CTF-specific modules
├── payloads/       # Payload collections
├── templates/      # Report templates
├── config/         # Configuration files
├── prompts/        # AI prompt templates
├── kb/             # Knowledge base
├── scripts/        # Utility scripts
├── plugins/        # Plugin system
├── wordlists/      # Wordlist collections
├── reports/        # Generated reports
├── docs/           # Documentation
├── tests/          # Test suite
├── examples/       # Usage examples
├── docker/         # Docker configuration
├── .github/        # GitHub configuration
├── memory/         # AI memory storage
├── audit/          # Audit logs
└── kb/             # Knowledge base storage
```

## Testing

### Running Tests
```bash
# Run all tests
pytest

# Run tests with coverage
pytest --cov=vulnbuster --cov-report=html

# Run specific test file
pytest tests/test_core.py

# Run tests with verbose output
pytest -v

# Run tests in parallel
pytest -n auto
```

### Writing Tests
- Use descriptive test names
- Test both success and failure cases
- Mock external dependencies
- Use fixtures for common setup
- Test edge cases and error conditions

### Test Structure
```python
import pytest
from vulnbuster.core.scanner import Scanner

class TestScanner:
    @pytest.fixture
    def scanner(self):
        return Scanner(config={})
    
    async def test_scanner_initialization(self, scanner):
        assert scanner is not None
    
    async def test_scanner_invalid_target(self, scanner):
        with pytest.raises(ValueError):
            await scanner.scan("invalid-url")
```

## Documentation

### Docstring Format
Use Google-style docstrings:

```python
async def scan_target(target: str, modules: List[str]) -> List[Dict[str, Any]]:
    """Scan a target for vulnerabilities.
    
    Args:
        target: The target URL or IP address to scan
        modules: List of vulnerability modules to use
        
    Returns:
        List of vulnerability findings
        
    Raises:
        ValueError: If target is invalid
        ConnectionError: If target is unreachable
        
    Example:
        >>> results = await scan_target("https://example.com", ["xss", "sqli"])
        >>> print(len(results))
        5
    """
    pass
```

### README Updates
- Update README.md for new features
- Add usage examples
- Update installation instructions
- Document new CLI options

### API Documentation
- Document all public functions and classes
- Include type hints
- Provide usage examples
- Update API reference in docs/

## Security

### Responsible Disclosure
- Report security vulnerabilities privately
- Do not disclose vulnerabilities publicly
- Work with maintainers to fix issues
- Follow responsible disclosure timeline

### Security Guidelines
- Never commit API keys or secrets
- Use environment variables for sensitive data
- Validate all user inputs
- Follow secure coding practices
- Use parameterized queries
- Implement proper error handling

### Testing Security Features
- Test with safe, controlled environments
- Use dedicated test targets
- Avoid testing against production systems
- Follow ethical hacking guidelines

## Pull Request Process

### Before Submitting
1. Ensure your code follows the style guide
2. Add tests for new functionality
3. Update documentation
4. Run the full test suite
5. Check that all CI checks pass

### Pull Request Template
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Test addition
- [ ] Other (please describe)

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests added/updated
- [ ] No breaking changes

## Related Issues
Closes #(issue number)
```

### Review Process
1. Automated checks must pass
2. At least one maintainer must approve
3. All conversations must be resolved
4. Documentation must be updated
5. Tests must be comprehensive

### After Merge
- Delete feature branch
- Update release notes if needed
- Tag release if appropriate
- Update documentation

## Getting Help

### Communication Channels
- GitHub Issues: For bug reports and feature requests
- GitHub Discussions: For questions and general discussion
- Security: Email security@vulnbuster.com for security issues

### Resources
- [Python Documentation](https://docs.python.org/)
- [AsyncIO Documentation](https://docs.python.org/3/library/asyncio.html)
- [Pytest Documentation](https://docs.pytest.org/)
- [Black Documentation](https://black.readthedocs.io/)

## Recognition

Contributors will be recognized in:
- README.md contributors section
- Release notes
- Project documentation
- GitHub contributors page

Thank you for contributing to VulnBuster! 🚀 