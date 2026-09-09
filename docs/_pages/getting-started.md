---
layout: default
title: Getting Started
---

# Getting Started with LWS

Welcome to LWS (Linux Web Services)! This guide will help you get up and running quickly.

## Prerequisites

Before installing LWS, ensure you have:

- **Python 3.10+** installed
- **Proxmox VE 6.x or higher** running
- **SSH access** to your Proxmox hosts
- **sshpass** installed (`apt install sshpass` on Debian/Ubuntu)

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/fabriziosalmi/lws.git
cd lws
```

### 2. Create a Virtual Environment (Recommended)

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure LWS

Create your configuration file:

```bash
cp config.yaml.example config.yaml
```

Edit `config.yaml` with your Proxmox details:

```yaml
regions:
  eu-south-1:
    availability_zones:
      az1:
        host: proxmox1.example.com
        user: root
        ssh_password: your_password

instance_sizes:
  small:
    memory: 1024
    cpulimit: 1
    storage: local-lvm:8
  medium:
    memory: 2048
    cpulimit: 2
    storage: local-lvm:16

default_storage: local-lvm
default_network: vmbr0
```

### 5. Verify Installation

```bash
python3 lws.py --version
python3 lws.py --help
```

## Your First Container

Let's create your first LXC container!

### 1. List Available Proxmox Hosts

```bash
python3 lws.py px list
```

This will show you all configured Proxmox hosts and their availability.

### 2. Run a Container

```bash
python3 lws.py lxc run \
  --image-id local:vztmpl/ubuntu-22.04-standard_22.04-1_amd64.tar.gz \
  --size medium \
  --hostname my-container \
  --count 1
```

### 3. Check Container Status

```bash
python3 lws.py lxc show
```

### 4. Execute Commands in Container

```bash
python3 lws.py lxc exec <container-id> "apt update && apt upgrade -y"
```

## Using the API Server

LWS includes a REST API server for programmatic access.

### 1. Start the API Server

```bash
python3 api.py
```

The API will be available at `http://localhost:8080`.

### 2. Access the Web UI

Open your browser and navigate to:
- Web UI: `http://localhost:8080/`
- API Docs: `http://localhost:8080/api/v1/docs`

### 3. Make API Calls

```bash
# Get health status
curl http://localhost:8080/api/v1/health

# List containers (requires API key)
curl -H "X-API-Key: your-api-key" \
  http://localhost:8080/api/v1/lxc/instances
```

## Next Steps

Now that you have LWS installed and running:

- Read the [CLI Reference](cli-reference.html) for all available commands
- Learn about the [Architecture](architecture.html)
- Explore the [API Reference](api-reference.html)
- Check out [Advanced Configuration](configuration.html)

## Troubleshooting

### SSH Connection Issues

If you're having trouble connecting to Proxmox hosts:

1. Verify SSH access manually:
   ```bash
   ssh root@your-proxmox-host
   ```

2. Check `sshpass` is installed:
   ```bash
   which sshpass
   ```

3. Verify your credentials in `config.yaml`

### Permission Errors

Ensure your Proxmox user has the necessary permissions:

```bash
# On Proxmox host
pveum user list
pveum acl list
```

### Container Creation Fails

1. Check available templates:
   ```bash
   python3 lws.py px templates
   ```

2. Verify storage availability:
   ```bash
   python3 lws.py px status
   ```

## Getting Help

- [Documentation](../index.html)
- [Report Issues](https://github.com/fabriziosalmi/lws/issues)
- [Discussions](https://github.com/fabriziosalmi/lws/discussions)

---

[← Back to Home](../index.html) | [Next: Architecture →](architecture.html)
