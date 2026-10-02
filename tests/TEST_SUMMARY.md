# Test Suite Summary

## Overview
Pytest test suite for the `lws_core/` package (config, SSH, Proxmox and
utility helpers used by the LWS CLI), plus a small, targeted `test_api.py`
for `api.py`'s request-validation logic. **Scope**: `lws_core/` is
comprehensively covered (96%); `lws.py` (the CLI, ~3,700 lines) has no
automated tests at all, and `api.py` (the REST API, ~1,200 lines) has
tests only for its input-validation and routing logic (22 tests), not its
~60 other endpoints - see [architecture docs](../docs/_pages/architecture.md).

## Test Results
- **Total Tests**: 125 (103 for `lws_core/`, 22 for `api.py`)
- **Passed**: 125 (100%)
- **Failed**: 0
- **Coverage**: 96% of `lws_core/`; not measured for `api.py`/`lws.py`
  (`pytest.ini` only instruments `lws_core/` - see `--cov=lws_core` below)

## Test Structure

### Configuration Files
- `pytest.ini` - Pytest configuration with coverage settings
- `tests/conftest.py` - Shared fixtures and test configuration
- `requirements.txt` - Updated with testing dependencies (pytest, pytest-cov, pytest-mock)

### Test Files Created

#### 1. `tests/test_config.py` (29 tests)
Tests for `lws_core/config.py`:
- Configuration loading from YAML files
- Configuration validation
- Error handling for missing/invalid configurations
- Sensitive information masking
- Module-level configuration loading

**Coverage**: 97%

#### 2. `tests/test_ssh.py` (14 tests)
Tests for `lws_core/ssh.py`:
- SSH command execution with password authentication (passed via the
  `SSHPASS` env var, never argv)
- Retry logic for failed connections
- Timeout handling
- Password sanitization in logs
- Error handling for missing sshpass

**Coverage**: 98%

#### 3. `tests/test_utils.py` (33 tests)
Tests for `lws_core/utils.py`:
- Service status checking
- Command aliases
- Instance command processing (a failure now exits the process with a
  non-zero code instead of returning normally)
- Resize command building
- VMID generation
- Container lock checking

**Coverage**: 93%

#### 4. `tests/test_proxmox.py` (22 tests)
Tests for `lws_core/proxmox.py`:
- Local command execution
- Remote command execution via SSH
- Error handling for command execution
- Validation of command parameters

**Coverage**: 100%

#### 5. `tests/test_python_support.py` (5 tests)
Guards against the README/CI/Dockerfile Python-version floor drifting out
of sync with `pyproject.toml` (and with the interpreter actually running
the tests).

#### 6. `tests/test_api.py` (22 tests)
Tests for `api.py` - not comprehensive (the ~60 endpoints have no tests of
their own), but covers the request-handling logic directly:
- `validate_instance_id` / `validate_instance_ids_list`
- `run_lws_command`'s `consumed_keys` (a value sent positionally in
  `cmd_parts` must not also be re-sent as a `--flag` option)
- the global `before_request` guard rejecting non-numeric `<instance_id>`
  path segments
- the `app_remove` route (previously crashed every request with a
  `TypeError` - its view function took a positional arg the route never
  supplied)
- API key authentication

## Key Features

### Test Fixtures
- `sample_config` - Valid configuration for testing
- `config_file` - Temporary config.yaml file
- `mock_subprocess_result` - Mock subprocess results
- `mock_ssh_host_details` - SSH connection details
- `mock_pct_list_output` - Sample Proxmox container list output
- `mock_pct_config_output` - Sample container configuration
- `mock_sshpass_installed/not_installed` - Mock sshpass availability

### Test Markers
- `@pytest.mark.unit` - Unit tests
- `@pytest.mark.integration` - Integration tests
- `@pytest.mark.ssh` - SSH-related tests
- `@pytest.mark.proxmox` - Proxmox-related tests

## Running Tests

### Run all tests:
```bash
pytest tests/
```

### Run with coverage:
```bash
pytest tests/ --cov=lws_core --cov-report=html
```

### Run specific test file:
```bash
pytest tests/test_config.py -v
```

### Run tests by marker:
```bash
pytest -m ssh  # Run only SSH tests
pytest -m unit  # Run only unit tests
```

## Coverage Details

| Module | Coverage |
|--------|----------|
| lws_core/__init__.py | 100% |
| lws_core/config.py | 97% |
| lws_core/proxmox.py | 100% |
| lws_core/ssh.py | 98% |
| lws_core/utils.py | 93% |
| lws_core/logging_setup.py | 87% |
| **Overall** | **96%** |

## Test Categories

### Configuration Tests
- Valid/invalid YAML parsing
- Missing required fields
- Region and availability zone validation
- Instance size validation
- Sensitive data masking

### SSH Tests
- Successful/failed command execution
- Connection retry logic
- Timeout handling
- Password sanitization
- Error handling

### Utility Tests
- Service status checks
- VMID generation
- Container operations (stop, start, resize, etc.)
- Snapshot management
- Error handling for invalid regions/zones

### Proxmox Tests
- Local vs remote command execution
- Command validation
- Error propagation
- Host details handling

## Next Steps

1. **Continuous Integration**: Set up CI/CD pipeline to run tests automatically
2. **Integration Tests**: Add integration tests for end-to-end workflows
3. **Performance Tests**: Add tests for performance-critical functions
4. **Additional Coverage**: Increase coverage for logging_setup.py and utils.py
5. **Mutation Testing**: Consider adding mutation testing for test quality validation

## Dependencies

```
pytest>=7.4.0,<8.0.0
pytest-cov>=4.1.0,<5.0.0
pytest-mock>=3.11.0,<4.0.0
```

## Notes

- All tests use mocking to avoid external dependencies
- Tests are isolated and can run in any order
- Coverage reports are generated in `htmlcov/` directory
- Tests validate both success and failure scenarios
- Password/secret masking is verified in security-sensitive tests
