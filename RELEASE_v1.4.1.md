# Release v1.4.1 - Testing & Modularization

## Overview
This release focuses on improving code quality, testing infrastructure, and project organization. It introduces the `lws_core/` package: a small, 96%-covered module of config/SSH/Proxmox/utility helpers extracted as a first step toward modularizing the codebase.

**Scope note (added after the fact, see [architecture docs](docs/_pages/architecture.md)):** the coverage and "modularized" claims below describe `lws_core/` only (~500 lines) as of this release. `lws.py` (the CLI, ~3,500 lines) has no automated tests. `api.py` (the REST API, ~1,200 lines) gained a targeted test suite for its validation and routing logic in a later release (22 tests, not comprehensive coverage of its ~60 endpoints) - see `tests/TEST_SUMMARY.md` for the current state.

## New Features

### Comprehensive Test Suite
- **98 unit tests** with 100% pass rate
- **96% code coverage** across the core modules
- Pytest-based testing framework with:
  - `pytest-cov` for coverage reporting
  - `pytest-mock` for mocking capabilities
  - Organized test fixtures and markers
  - HTML coverage reports

### Test Coverage by Module
- `lws_core/__init__.py` - 100%
- `lws_core/proxmox.py` - 100%
- `lws_core/ssh.py` - 98%
- `lws_core/config.py` - 97%
- `lws_core/utils.py` - 93%
- `lws_core/logging_setup.py` - 87%

### Documentation Site
- Added project documentation site in `docs/` directory
- Comprehensive API reference
- Architecture documentation
- CLI reference guide
- Getting started guide
- Configuration documentation

## Improvements

### Code Modularization
- **First step toward a modularized codebase**: config/SSH/Proxmox/utility
  helpers extracted into `lws_core/`, with clear separation of concerns:
  - `lws_core/config.py` - Configuration management
  - `lws_core/ssh.py` - SSH operations
  - `lws_core/utils.py` - Utility functions
  - `lws_core/proxmox.py` - Proxmox API interactions
  - `lws_core/logging_setup.py` - Logging configuration
- `lws_commands/` was scaffolded as a placeholder for splitting the ~61
  CLI commands out of `lws.py` into per-group files, but that split was
  never done - the directory is still an empty stub.

### Enhanced `.gitignore`
- Added comprehensive Python development patterns
- Test coverage and cache exclusions
- IDE and OS-specific file exclusions
- Virtual environment patterns
- Temporary file patterns

### Testing Infrastructure
- `pytest.ini` configuration with coverage settings
- `tests/conftest.py` with shared fixtures
- Organized test files by module:
  - `test_config.py` (29 tests)
  - `test_ssh.py` (15 tests)
  - `test_utils.py` (32 tests)
  - `test_proxmox.py` (22 tests)

## Dependencies

### New Testing Dependencies
```
pytest>=7.4.0,<8.0.0
pytest-cov>=4.1.0,<5.0.0
pytest-mock>=3.11.0,<4.0.0
```

## Test Categories

### Configuration Tests
- YAML parsing and validation
- Region and availability zone validation
- Instance size configuration
- Sensitive data masking
- Error handling

### SSH Tests
- Command execution with retry logic
- Connection timeout handling
- Password sanitization in logs
- sshpass dependency checking

### Utility Tests
- Service status checking
- VMID generation
- Container operations (stop, start, resize, snapshot)
- Command processing

### Proxmox Tests
- Local and remote command execution
- Error propagation
- Parameter validation

## Running Tests

```bash
# Run all tests
pytest tests/

# Run with coverage report
pytest tests/ --cov=lws_core --cov-report=html

# Run specific test file
pytest tests/test_config.py -v

# Run by marker
pytest -m ssh  # SSH tests only
pytest -m unit # Unit tests only
```

## Code Quality Metrics (for `lws_core/` only, as of this release - see scope note above)

- **Total Tests**: 98
- **Pass Rate**: 100%
- **Code Coverage**: 96%
- **Modules**: `lws_core/` only; `lws.py` has no tests; `api.py` later gained a targeted (not comprehensive) suite, see `tests/TEST_SUMMARY.md`
- **Documentation**: present, not verified against the code at the time of this release

## What's Tested (in `lws_core/`, not in `lws.py`'s command implementations)

- Configuration loading and validation
- SSH command execution with retries
- Proxmox API interactions
- Utility functions (VMID generation, container operations)
- Error handling and edge cases
- Password/secret sanitization
- Container lifecycle management (the `lws_core.utils.process_instance_command` helper; whether `lws.py`'s commands actually call it unshadowed was not verified at the time of this release)
- Snapshot operations

## Breaking Changes

None.

## Bug Fixes

- Improved error handling in SSH operations
- Enhanced configuration validation
- Better logging for debugging

## Documentation

- Added `tests/TEST_SUMMARY.md`
- Documentation site in `docs/` directory
- Inline code documentation
- API reference documentation
- Architecture diagrams and guides

## Acknowledgments

This release added `lws_core/` and its test suite.

---

## Installation

```bash
git clone https://github.com/fabriziosalmi/lws.git
cd lws
pip install -r requirements.txt
```

## Quick Start

```bash
# Run tests
pytest tests/

# View coverage
pytest tests/ --cov=lws_core --cov-report=html
open htmlcov/index.html
```

For full documentation, visit the [documentation site](docs/index.html).
