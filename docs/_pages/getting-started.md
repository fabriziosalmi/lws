---
title: Getting Started
seo_title: "Getting Started: install LWS and create an LXC container"
description: "Install LWS from a checkout, point config.yaml at your Proxmox VE hosts, create a first LXC container and start the REST API with its web UI."
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

Edit `config.yaml` with your Proxmox details. The part to change first is
the list of hosts; the example file already defines the instance sizes:

```yaml
use_local_only: false
default_storage: local-lvm
default_network: vmbr0

regions:
  eu-south-1:
    availability_zones:
      az1:
        host: proxmox1.example.com
        user: root
        ssh_password: "your-password"
```

Keep the file private: `chmod 600 config.yaml`. LWS reads `config.yaml` from
the directory you run it in. [Configuration](configuration.html) describes
every key.

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

`--image-id` is a container template stored on the Proxmox host, written as `storage:vztmpl/<file>`. `python3 lws.py px templates` lists the files in `/var/lib/vz/template/cache`, which is the `local` storage. `--size` is one of the names under `instance_sizes` in `config.yaml`; the example file defines `micro`, `small`, `mid`, `large` and others.

```bash
python3 lws.py lxc run \
  --image-id local:vztmpl/ubuntu-22.04-standard_22.04-1_amd64.tar.zst \
  --size small \
  --hostname my-container \
  --count 1
```

### 3. Check Container Status

```bash
python3 lws.py lxc show
```

### 4. Execute Commands in Container

```bash
python3 lws.py lxc exec <container-id> "apt-get update"
python3 lws.py lxc exec <container-id> "apt-get -y upgrade"
```

Run one command per call: shell operators such as `&&` or `|` in the command
are read by the Proxmox host's shell and run on the host, not in the
container.

## Using the API Server

LWS includes a REST API server for programmatic access.

### 1. Start the API Server

The API refuses to start without a key. Generate one and write it into
`config.yaml`, then start the server from the directory that holds
`config.yaml`:

```bash
KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
sed -i "s|^api_key:.*|api_key: \"$KEY\"|" config.yaml   # on macOS: sed -i ''
python3 api.py
```

The API listens on `http://127.0.0.1:8080`. It runs commands as root on every
configured host, so keep it on the local machine or a private network.

### 2. Access the Web UI

Open your browser and navigate to:
- Web UI: `http://localhost:8080/`
- API Docs: `http://localhost:8080/api/v1/docs`

### 3. Make API Calls

```bash
# Get health status
curl http://localhost:8080/api/v1/health

# List containers (requires the API key)
curl -H "X-API-Key: $KEY" \
  http://localhost:8080/api/v1/lxc/instances
```

## Next Steps

Now that you have LWS installed and running:

- Read the [CLI Reference](cli-reference.html) for all available commands
- Add more hosts: [Several Proxmox hosts](multiple-hosts.html)
- Pick or define container sizes: [Instance sizes](instance-sizes.html)
- Explore the [API Reference](api-reference.html)
- If something fails: [Troubleshooting](troubleshooting.html)

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

LWS logs in with the `user` of each host in `config.yaml` and runs `pct` and
other administration commands directly, without `sudo`. Use `root`, or a user
that can run those commands. Proxmox users and API permissions (`pveum`) do
not apply: LWS does not use the Proxmox API.

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

- [Documentation home](../)
- [Report Issues](https://github.com/fabriziosalmi/lws/issues)
