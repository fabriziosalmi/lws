---
layout: default
title: Configuration
---

# Configuration Guide

Complete guide to configuring LWS for your infrastructure.

## Configuration File Location

LWS uses `config.yaml` in the project root directory.

```bash
lws/
├── config.yaml         # Your configuration
├── config.yaml.example # Example template
└── lws.py
```

## Complete Configuration Example

```yaml
# Basic Settings
use_local_only: false
start_vmid: 10000
default_storage: local-lvm
default_network: vmbr0

# Minimum Resource Requirements
minimum_resources:
  cores: 1
  memory_mb: 512

# API Configuration
api_key: "your-secure-random-api-key"
api:
  host: "0.0.0.0"
  port: 8080
  debug: false
  log_level: "INFO"
  allowed_origins:
    - "http://localhost:8080"
    - "null"  # For file:// access

# Regions and Availability Zones
regions:
  eu-south-1:
    availability_zones:
      az1:
        host: proxmox1.example.com
        user: root
        ssh_password: SecurePassword123
      az2:
        host: 192.168.1.101
        user: root
        ssh_password: AnotherPassword

  us-east-1:
    availability_zones:
      az1:
        host: proxmox-us.example.com
        user: root
        ssh_password: UsPassword

# Instance Size Definitions
instance_sizes:
  # Basic Sizes
  micro:
    memory: 512
    cpulimit: 1
    storage: local-lvm:4

  small:
    memory: 1024
    cpulimit: 1
    storage: local-lvm:8

  medium:
    memory: 2048
    cpulimit: 2
    storage: local-lvm:16

  large:
    memory: 4096
    cpulimit: 4
    storage: local-lvm:32

  # AWS-like Sizes
  t2-micro:
    memory: 1024
    cpulimit: 1
    storage: local-lvm:8

  t2-small:
    memory: 2048
    cpulimit: 1
    storage: local-lvm:20

  m5-large:
    memory: 8192
    cpulimit: 2
    storage: local-lvm:50

  # Application-Specific
  lws-web:
    memory: 2048
    cpulimit: 2
    storage: local-lvm:20

  lws-database:
    memory: 8192
    cpulimit: 4
    storage: local-lvm:100

# Auto-Scaling Configuration
scaling:
  host_cpu:
    max_threshold: 80
    min_threshold: 30
    step: 1
    scale_up_multiplier: 1.5
    scale_down_multiplier: 0.5

  lxc_cpu:
    max_threshold: 80
    min_threshold: 30
    step: 1
    scale_up_multiplier: 1.5
    scale_down_multiplier: 0.5

  host_memory:
    max_threshold: 70
    min_threshold: 40
    step_mb: 256
    scale_up_multiplier: 1.25
    scale_down_multiplier: 0.75

  lxc_memory:
    max_threshold: 70
    min_threshold: 40
    step_mb: 256
    scale_up_multiplier: 1.25
    scale_down_multiplier: 0.75

  limits:
    min_memory_mb: 512
    max_memory_mb: 32768
    min_cpu_cores: 1
    max_cpu_cores: 16
    min_storage_gb: 10
    max_storage_gb: 1024

  general:
    scaling_interval: 5
    notify_user: true
    dry_run: false
    scaling_log_level: DEBUG

# Security Configuration
security:
  discovery:
    proxmox_timeout: 2
    lxc_timeout: 2
    discovery_methods: ['ping']
    max_parallel_workers: 10
```

## Configuration Sections

### Basic Settings

```yaml
use_local_only: false      # Execute commands locally (true) or via SSH (false)
start_vmid: 10000          # Starting VMID for new containers
default_storage: local-lvm # Default storage backend
default_network: vmbr0     # Default network bridge
```

### API Configuration

```yaml
api_key: "your-key-here"   # API authentication key
api:
  host: "0.0.0.0"          # Listen on all interfaces
  port: 8080               # API port
  debug: false             # Enable debug mode (development only!)
  log_level: "INFO"        # Logging level
  allowed_origins:         # CORS allowed origins
    - "http://localhost:8080"
```

**Security Note:** Never commit your actual API key to version control!

### Regions and Availability Zones

Define your Proxmox infrastructure:

```yaml
regions:
  <region-name>:
    availability_zones:
      <az-name>:
        host: <proxmox-host>    # Hostname or IP
        user: <ssh-user>        # SSH username
        ssh_password: <password> # SSH password
```

**Best Practices:**
- Use descriptive region names (e.g., `eu-south-1`, `us-east-1`)
- Group geographically close hosts
- Use different AZs for redundancy

### Instance Sizes

Define container resource templates:

```yaml
instance_sizes:
  <size-name>:
    memory: <MB>           # RAM in megabytes
    cpulimit: <cores>      # CPU cores
    storage: <backend>:<size> # Storage (e.g., local-lvm:20)
```

**Naming Conventions:**
- Use consistent naming (small, medium, large)
- Or AWS-style (t2-micro, m5-large)
- Or app-specific (lws-web, lws-database)

### Auto-Scaling

Configure automatic resource scaling:

```yaml
scaling:
  lxc_cpu:
    max_threshold: 80      # Scale down if below this %
    min_threshold: 30      # Scale up if above this %
    step: 1                # Cores to add/remove
    scale_up_multiplier: 1.5
    scale_down_multiplier: 0.5

  limits:
    min_memory_mb: 512     # Minimum allowed RAM
    max_memory_mb: 32768   # Maximum allowed RAM
```

## Environment-Specific Configurations

### Development
```yaml
api:
  debug: true
  log_level: "DEBUG"

scaling:
  general:
    dry_run: true  # Simulate scaling without applying
```

### Production
```yaml
api:
  debug: false
  log_level: "WARNING"
  allowed_origins:
    - "https://yourdomain.com"

scaling:
  general:
    dry_run: false
    notify_user: true
```

## Security Best Practices

### 1. API Key Security

Generate a strong API key:

```bash
# On Linux/Mac
openssl rand -hex 32

# Or use Python
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### 2. SSH Password Management

**Option 1: Environment Variables**
```yaml
regions:
  eu-south-1:
    availability_zones:
      az1:
        host: proxmox1.example.com
        user: root
        ssh_password: ${PROXMOX_PASSWORD}
```

**Option 2: SSH Keys** (Recommended)
Consider modifying LWS to use SSH keys instead of passwords.

### 3. File Permissions

```bash
chmod 600 config.yaml
```

### 4. Secrets Management

For production, use a secrets management system:
- HashiCorp Vault
- AWS Secrets Manager
- Azure Key Vault

## Storage Backends

Common Proxmox storage backends:

```yaml
# Local LVM
storage: local-lvm:20

# Local Directory
storage: local:20

# NFS
storage: nfs-storage:50

# Ceph
storage: ceph-storage:100
```

## Network Configuration

Configure network bridges:

```yaml
default_network: vmbr0  # Default bridge
```

Or set it per container at creation time:

```bash
lws lxc run --net0 "name=eth0,bridge=vmbr1,ip=192.168.1.100/24,gw=192.168.1.1"
```

## Validation

Validate your configuration:

```bash
# Via CLI
lws conf validate

# Via API
curl -X POST \
  -H "X-API-Key: your-key" \
  http://localhost:8080/api/v1/conf/validate
```

## Configuration Backup

Regular backups:

```bash
# With timestamp
lws conf backup /backup/lws-config.yaml --timestamp

# Compressed
lws conf backup /backup/lws-config.yaml.gz --timestamp --compress
```

## Troubleshooting

### Configuration Not Found

```bash
# Check file exists
ls -la config.yaml

# Check current directory
pwd

# Run from project root
cd /path/to/lws
python3 lws.py conf show
```

### Invalid YAML Syntax

```bash
# Validate YAML
python3 -c "import yaml; yaml.safe_load(open('config.yaml'))"

# Common issues:
# - Incorrect indentation (use spaces, not tabs)
# - Missing quotes around special characters
# - Unclosed brackets/braces
```

### Connection Issues

```bash
# Test SSH manually
ssh root@proxmox-host

# Check sshpass
which sshpass

# Verify credentials in config
lws conf show  # Passwords will be masked
```

## Migration Guide

### From Version 1.0 to 1.1

Version 1.1 introduced modular architecture:

1. No configuration changes required
2. All existing `config.yaml` files compatible
3. New API configuration options available

---

[← API Reference](api-reference.html) | [Next: Contributing →](contributing.html)
