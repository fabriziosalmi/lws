---
layout: default
title: Architecture
---

# LWS Architecture

LWS is built with a modular architecture that separates concerns and makes the codebase maintainable and testable.

## High-Level Overview

```
┌─────────────────────────────────────────────────────────┐
│                      User Interface                      │
├───────────────┬─────────────────────┬───────────────────┤
│   CLI (lws)   │   REST API (api.py) │   Web UI (ui.html)│
├───────────────┴─────────────────────┴───────────────────┤
│                    LWS Core Modules                      │
├──────────────────────────────────────────────────────────┤
│  config  │  ssh  │  proxmox  │  logging  │  utils      │
├──────────────────────────────────────────────────────────┤
│                  Command Executors                       │
├──────────────────────────────────────────────────────────┤
│    Proxmox VE Hosts (Multiple Regions & AZs)            │
└──────────────────────────────────────────────────────────┘
```

## Project Structure

```
lws/
├── lws.py                      # Main CLI entry point (~3700 lines, 61 commands)
├── api.py                      # REST API server (Flask), drives lws.py via subprocess
├── ui.html                     # Web UI interface
├── config.yaml.example         # Committed config template — cp to config.yaml and edit
├── config.yaml                 # Your local config (gitignored, not in the repository)
│
├── lws_core/                   # Core functionality modules
│   ├── __init__.py            # Module initialization
│   ├── config.py              # Configuration management
│   ├── logging_setup.py       # Logging configuration
│   ├── ssh.py                 # SSH execution utilities
│   ├── proxmox.py             # Proxmox command wrappers
│   └── utils.py               # Shared utility functions
│
├── lws_commands/               # Reserved for a future command-module split — see
│   └── __init__.py            # "Future Enhancements" below. Currently just a stub;
│                               # all 61 commands still live directly in lws.py.
│
├── tests/                     # Unit and integration tests (lws_core only, see below)
│   ├── conftest.py
│   ├── test_config.py
│   ├── test_proxmox.py
│   ├── test_ssh.py
│   ├── test_utils.py
│   └── test_python_support.py
│
└── docs/                      # Documentation (GitHub Pages)
    ├── index.html
    ├── _config.yml
    └── _pages/
```

The test suite above covers `lws_core/` only (96% coverage of those five files); `lws.py` and `api.py`, which hold the actual command and endpoint logic, currently have no automated tests.

## Core Modules

### 1. Configuration Module (`lws_core/config.py`)

Handles loading and validating configuration from `config.yaml`.

**Key Functions:**
- `load_config()` - Loads YAML configuration
- `validate_config()` - Validates configuration structure
- `mask_sensitive_info()` - Masks passwords/keys for display

**Configuration Structure:**
```yaml
regions:
  <region-name>:
    availability_zones:
      <az-name>:
        host: <proxmox-host>
        user: <ssh-user>
        ssh_password: <password>

instance_sizes:
  <size-name>:
    memory: <MB>
    cpulimit: <cores>
    storage: <storage>:<size>
```

### 2. SSH Module (`lws_core/ssh.py`)

Manages SSH connections to Proxmox hosts with retry logic and timeout handling.

**Features:**
- A fresh SSH connection per command (via `sshpass` + the system `ssh` binary — no connection reuse/pooling)
- Automatic retry on failure (up to 2 retries)
- 60-second command timeout
- Password sanitization in logs

**Key Functions:**
- `run_ssh_command(host, user, password, command)` - Execute SSH command

### 3. Proxmox Module (`lws_core/proxmox.py`)

Wrappers for executing Proxmox commands locally or remotely.

**Key Functions:**
- `execute_command()` - Execute command locally or via SSH
- `run_proxmox_command()` - Run Proxmox-specific commands

### 4. Utilities Module (`lws_core/utils.py`)

Common utility functions used across the application.

**Key Functions:**
- `get_next_vmid()` - Generate next available container ID
- `is_container_locked()` - Check if container is locked
- `process_instance_command()` - Generic instance command processor
- `build_resize_command()` - Build resize command arguments

### 5. Logging Module (`lws_core/logging_setup.py`)

Configures logging with both standard and JSON formats.

**Features:**
- Console logging
- File logging (`lws.log`)
- JSON logging (`lws.json.log`)
- Configurable log levels

## Command Groups

LWS organizes commands into logical groups:

### Configuration (`conf`)
- `show` - Display current configuration
- `validate` - Validate configuration
- `backup` - Backup configuration to file

### Proxmox Hosts (`px`)
- `list` - List all Proxmox hosts
- `status` - Check host resource usage
- `reboot` - Reboot a Proxmox host
- `upload` - Upload LXC template
- `clusters` - List clusters
- Security group management
- Template management

### LXC Containers (`lxc`)
- `run` - Create and start containers
- `show` - List/describe containers
- `stop` / `start` / `reboot` - Container lifecycle
- `terminate` - Destroy containers
- `scale` - Resize container resources
- `snapshot-add` / `snapshot-rm` - Snapshot management
- `exec` - Execute commands in container
- `clone` - Clone containers
- `migrate` - Migrate between hosts
- Backup & restore operations
- Resource monitoring

### Docker/Apps (`app`)
- `setup` - Install Docker in container
- `run` - Run Docker containers
- `deploy` - Manage Docker Compose apps
- `logs` - View Docker logs
- `list` - List Docker containers
- `remove` - Uninstall Docker

### Security (`sec`)
- `scan` - Security audit containers
- `discovery` - Network discovery

## Data Flow

### CLI Command Execution

```
1. User runs command
   ↓
2. Click parses arguments
   ↓
3. Load configuration (lws_core.config)
   ↓
4. Determine execution mode (local vs remote)
   ↓
5. Execute via SSH or locally (lws_core.ssh/proxmox)
   ↓
6. Parse and display results
```

### API Request Flow

```
1. HTTP request to API
   ↓
2. Flask routes request
   ↓
3. Validate API key (if required)
   ↓
4. Parse request parameters
   ↓
5. Build lws.py subprocess command
   ↓
6. Execute command
   ↓
7. Format and return JSON response
```

## Design Principles

### 1. Modularity
- Core functionality separated into focused modules
- Easy to test individual components
- Clear separation of concerns

### 2. Configuration Over Code
- All infrastructure details in `config.yaml`
- No hardcoded credentials or hosts
- Easy to manage multiple environments

### 3. Error Handling
- Comprehensive error messages
- Retry logic for transient failures
- Graceful degradation

### 4. Security
- Credential masking in logs
- API key authentication
- SSH password never exposed in logs

### 5. Extensibility
- Easy to add new commands
- Plugin-friendly architecture
- Clear interfaces between modules

## Performance Considerations

### SSH Connection Optimization
- Connection timeout: 15 seconds
- Command timeout: 60 seconds
- Maximum 2 retries on failure
- ServerAliveInterval: 5 seconds

### Parallel Execution
- Multiple containers can be managed in parallel
- Progress bars for batch operations
- ThreadPoolExecutor for concurrent operations

### Resource Monitoring
- Configurable check intervals
- Threshold-based scaling recommendations
- Efficient resource usage tracking

## Future Enhancements

Planned architectural improvements:

1. **Command Module Extraction**
   - Move command groups to `lws_commands/`
   - Reduce `lws.py` to thin entry point

2. **Database Support**
   - Track container state
   - Historical metrics
   - Audit logging

3. **Caching Layer**
   - Cache Proxmox API responses
   - Reduce SSH overhead
   - Faster status checks

4. **Plugin System**
   - Custom command plugins
   - Third-party integrations
   - Event hooks

5. **Web Dashboard**
   - Real-time monitoring
   - Visual resource management
   - Interactive container controls

---

[← Getting Started](getting-started.html) | [Next: CLI Reference →](cli-reference.html)
