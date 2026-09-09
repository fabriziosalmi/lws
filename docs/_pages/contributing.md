---
layout: default
title: Contributing
---

# Contributing to LWS

Thank you for your interest in contributing to LWS! This guide will help you get started.

## Ways to Contribute

- Report bugs
- Suggest new features
- Improve documentation
- Submit code patches
- Write tests
- Translate documentation

## Getting Started

### 1. Fork and Clone

```bash
# Fork the repository on GitHub
# Then clone your fork
git clone https://github.com/YOUR_USERNAME/lws.git
cd lws
```

### 2. Set Up Development Environment

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install pytest pytest-cov black flake8
```

### 3. Create a Branch

```bash
git checkout -b feature/my-new-feature
# or
git checkout -b fix/bug-description
```

## Development Workflow

### Code Style

LWS follows PEP 8 style guidelines:

```bash
# Format code with black
black lws.py lws_core/ api.py

# Check with flake8
flake8 lws.py lws_core/ api.py
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=lws_core --cov-report=html

# Run specific test
pytest tests/test_config.py
```

### Adding New Features

1. **Create an Issue** first to discuss the feature
2. **Write tests** for the new functionality
3. **Implement** the feature
4. **Update documentation**
5. **Submit a pull request**

## Project Structure

```
lws/
├── lws.py                  # CLI entry point
├── api.py                  # REST API
├── lws_core/              # Core modules
│   ├── config.py          # Configuration
│   ├── ssh.py             # SSH utilities
│   ├── proxmox.py         # Proxmox commands
│   └── utils.py           # Utilities
├── lws_commands/          # Command groups (future)
├── tests/                 # Test suite
└── docs/                  # Documentation
```

## Coding Guidelines

### Python Best Practices

```python
# Use type hints
def create_container(instance_id: str, size: str) -> dict:
    """Create a new container."""
    pass

# Write docstrings
def run_command(cmd: list) -> subprocess.CompletedProcess:
    """
    Execute a command with proper error handling.

    Parameters:
    - cmd: Command as list of strings

    Returns:
    - CompletedProcess with stdout and stderr
    """
    pass

# Handle errors gracefully
try:
    result = run_command(cmd)
except subprocess.CalledProcessError as e:
    logging.error(f"Command failed: {e}")
    raise
```

### CLI Commands

When adding new CLI commands:

```python
@lxc.command('new-command')
@click.option('--option', help="Description")
@click.argument('arg')
def new_command(option, arg):
    """🎯 Short description of command."""
    # Implementation
    pass
```

### API Endpoints

When adding new API endpoints:

```python
@app.route('/api/v1/new/endpoint', methods=['POST'])
@require_api_key
def new_endpoint():
    """Handle new endpoint requests."""
    data = request.get_json()

    # Validate input
    if not data or 'required_field' not in data:
        return jsonify({"error": "Missing required field"}), 400

    # Execute command
    stdout, stderr, rc = run_lws_command(['command'], data)

    # Return response
    return format_response(stdout, stderr, rc)
```

## Testing Guidelines

### Writing Tests

```python
import pytest
from lws_core.config import load_config, validate_config

def test_load_config_success():
    """Test successful configuration loading."""
    config = load_config()
    assert config is not None
    assert 'regions' in config

def test_validate_config_missing_regions():
    """Test validation fails with missing regions."""
    invalid_config = {'instance_sizes': {}}

    with pytest.raises(ValueError, match="Missing required configuration key: regions"):
        validate_config(invalid_config)
```

### Test Coverage

Aim for:
- **80%+ coverage** for core modules
- **100% coverage** for critical paths (authentication, validation)
- Test both success and failure cases

## Documentation

### Code Documentation

```python
def important_function(param1: str, param2: int) -> bool:
    """
    Brief description of what the function does.

    This function performs XYZ operation by doing ABC.
    It's particularly useful for cases where...

    Parameters:
    - param1: Description of param1
    - param2: Description of param2

    Returns:
    - bool: True if successful, False otherwise

    Raises:
    - ValueError: If param1 is empty
    - RuntimeError: If operation fails

    Example:
    >>> important_function("test", 42)
    True
    """
    pass
```

### Markdown Documentation

Update relevant docs in `docs/pages/` when adding features:
- getting-started.md
- cli-reference.md
- api-reference.md
- architecture.md

## Commit Messages

Follow conventional commits:

```bash
# Format
<type>(<scope>): <subject>

<body>

<footer>

# Examples
feat(lxc): add snapshot rollback command

Add ability to rollback to a specific snapshot with the
new 'lxc snapshot-rollback' command.

Closes #123

fix(api): handle missing API key gracefully

Previously, missing API key would cause 500 error.
Now returns proper 401 Unauthorized.

docs(readme): update installation instructions

Add note about Python 3.6+ requirement.

test(config): add validation tests

Improve test coverage for configuration validation.
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `test`: Tests
- `refactor`: Code refactoring
- `style`: Formatting
- `chore`: Maintenance

## Pull Request Process

### 1. Prepare Your PR

```bash
# Update your branch
git fetch upstream
git rebase upstream/main

# Run tests
pytest

# Format code
black .
flake8 .
```

### 2. Create Pull Request

- Clear title describing the change
- Reference related issues (`Fixes #123`)
- Describe what changed and why
- Include screenshots for UI changes
- List breaking changes (if any)

### 3. PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Tests pass locally
- [ ] Added new tests
- [ ] Updated documentation

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No breaking changes (or listed above)
```

## Review Process

1. **Automated checks** must pass (tests, linting)
2. **Code review** by maintainer(s)
3. **Address feedback** if requested
4. **Squash commits** if needed
5. **Merge** when approved

## Community Guidelines

### Be Respectful

- Use welcoming and inclusive language
- Respect differing viewpoints
- Accept constructive criticism gracefully
- Focus on what's best for the community

### Get Help

- [Discussions](https://github.com/fabriziosalmi/lws/discussions) - Ask questions
- [Issues](https://github.com/fabriziosalmi/lws/issues) - Report bugs
- Email maintainers for sensitive matters

## Recognition

Contributors are recognized in:
- README.md contributors section
- Release notes
- Git history

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to LWS!

[← Configuration](configuration.html) | [Back to Home →](../index.html)
