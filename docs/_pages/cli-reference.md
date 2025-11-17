---
layout: default
title: CLI Reference
---

# CLI Command Reference

Complete reference for all LWS command-line commands.

## Global Options

```bash
lws [OPTIONS] COMMAND [ARGS]...
```

**Options:**
- `--version` - Show version and exit
- `-h, --help` - Show help message

## Configuration Commands (`conf`)

### `conf show`

Display current configuration with sensitive information masked.

```bash
lws conf show
```

### `conf validate`

Validate the configuration file structure.

```bash
lws conf validate
```

### `conf backup`

Backup configuration to a file.

```bash
lws conf backup <destination> [OPTIONS]

Options:
  --timestamp     Append timestamp to filename
  --compress      Compress backup with gzip
```

**Example:**
```bash
lws conf backup /backup/lws-config.yaml --timestamp --compress
```

## Proxmox Commands (`px`)

### `px list`

List all configured Proxmox hosts with availability status.

```bash
lws px list [OPTIONS]

Options:
  --region TEXT   Filter by region
```

**Example:**
```bash
lws px list --region eu-south-1
```

### `px status`

Monitor resource usage of a Proxmox host.

```bash
lws px status [OPTIONS]

Options:
  --region TEXT   Region (default: eu-south-1)
  --az TEXT       Availability zone (default: az1)
```

### `px reboot`

Reboot a Proxmox host.

```bash
lws px reboot [OPTIONS]

Options:
  --region TEXT   Region (default: eu-south-1)
  --az TEXT       Availability zone (default: az1)
  --confirm       Required confirmation flag
```

**Example:**
```bash
lws px reboot --region eu-south-1 --az az1 --confirm
```

### `px templates`

List available LXC templates on a Proxmox host.

```bash
lws px templates [OPTIONS]

Options:
  --region TEXT   Region (default: eu-south-1)
  --az TEXT       Availability zone (default: az1)
```

### `px upload`

Upload an LXC template to Proxmox.

```bash
lws px upload <local_path> [remote_name] [OPTIONS]

Options:
  --region TEXT        Region (default: eu-south-1)
  --az TEXT            Availability zone (default: az1)
  --storage-path TEXT  Remote storage path
```

**Example:**
```bash
lws px upload ./ubuntu-22.04.tar.gz ubuntu-22.04 \
  --region eu-south-1 --az az1
```

### `px clusters`

List all clusters in the Proxmox environment.

```bash
lws px clusters [OPTIONS]

Options:
  --region TEXT   Region
  --az TEXT       Availability zone
```

## LXC Container Commands (`lxc`)

### `lxc run`

Create and start LXC containers.

```bash
lws lxc run [OPTIONS]

Options:
  --image-id TEXT      Container image template (required)
  --count INTEGER      Number of instances (default: 1)
  --size TEXT          Instance size (default: small)
  --hostname TEXT      Hostname for container
  --region TEXT        Region (default: eu-south-1)
  --az TEXT            Availability zone (default: az1)
  --password TEXT      Root password
  --ip TEXT            Fixed IP address
  --netmask TEXT       Network mask (default: 24)
  --gateway TEXT       Network gateway
  --dns TEXT           DNS servers (comma-separated)
  --dhcp               Enable DHCP
```

**Example:**
```bash
lws lxc run \
  --image-id local:vztmpl/ubuntu-22.04-standard_22.04-1_amd64.tar.gz \
  --size medium \
  --count 3 \
  --hostname web-server \
  --password SecurePass123
```

### `lxc show`

List all containers or show details of specific containers.

```bash
lws lxc show [instance_ids...] [OPTIONS]

Options:
  --region TEXT   Region (default: eu-south-1)
  --az TEXT       Availability zone (default: az1)
```

**Examples:**
```bash
# List all containers
lws lxc show

# Show specific containers
lws lxc show 100 101 102
```

### `lxc start` / `stop` / `reboot`

Control container lifecycle.

```bash
lws lxc {start|stop|reboot} <instance_ids...> [OPTIONS]

Options:
  --region TEXT   Region (default: eu-south-1)
  --az TEXT       Availability zone (default: az1)
```

**Examples:**
```bash
lws lxc start 100 101
lws lxc stop 100
lws lxc reboot 100 101 102
```

### `lxc terminate`

Destroy containers permanently.

```bash
lws lxc terminate <instance_ids...> [OPTIONS]

Options:
  --region TEXT   Region (default: eu-south-1)
  --az TEXT       Availability zone (default: az1)
```

**Example:**
```bash
lws lxc terminate 100 101
```

### `lxc scale`

Resize container resources.

```bash
lws lxc scale <instance_ids...> [OPTIONS]

Options:
  --memory INTEGER        New memory in MB
  --cpulimit INTEGER      New CPU limit
  --cpucores INTEGER      New CPU cores
  --storage-size TEXT     New storage size (e.g., 32G)
  --region TEXT           Region
  --az TEXT               Availability zone
```

**Example:**
```bash
lws lxc scale 100 --memory 4096 --cpulimit 4 --storage-size 64G
```

### `lxc exec`

Execute commands inside containers.

```bash
lws lxc exec <instance_id> <command> [OPTIONS]

Options:
  --region TEXT   Region
  --az TEXT       Availability zone
```

**Example:**
```bash
lws lxc exec 100 "apt update && apt upgrade -y"
```

### `lxc snapshot-add` / `snapshot-rm`

Manage container snapshots.

```bash
# Create snapshot
lws lxc snapshot-add <instance_id> <snapshot_name> [OPTIONS]

# Delete snapshot
lws lxc snapshot-rm <instance_id> <snapshot_name> [OPTIONS]

Options:
  --region TEXT   Region
  --az TEXT       Availability zone
```

**Examples:**
```bash
lws lxc snapshot-add 100 before-update
lws lxc snapshot-rm 100 before-update
```

### `lxc snapshots`

List all snapshots for a container.

```bash
lws lxc snapshots <instance_id> [OPTIONS]

Options:
  --region TEXT   Region
  --az TEXT       Availability zone
```

### `lxc clone`

Clone a container.

```bash
lws lxc clone <source_id> <target_id> [OPTIONS]

Options:
  --full          Full clone (vs linked)
  --region TEXT   Region
  --az TEXT       Availability zone
```

**Example:**
```bash
lws lxc clone 100 200 --full
```

### `lxc migrate`

Migrate container between hosts.

```bash
lws lxc migrate <instance_id> [OPTIONS]

Options:
  --target-host TEXT  Target Proxmox host (required)
  --region TEXT       Region
  --az TEXT           Availability zone
```

### `lxc backup-create` / `backup-restore`

Backup and restore containers.

```bash
# Create backup
lws lxc backup-create <instance_id> [OPTIONS]

# Restore from backup
lws lxc backup-restore <instance_id> [OPTIONS]

Options:
  --backup-file TEXT  Backup file path
  --download          Download backup locally
  --region TEXT       Region
  --az TEXT           Availability zone
```

### `lxc resources`

Monitor real-time resource usage.

```bash
lws lxc resources <instance_id> [OPTIONS]

Options:
  --interval INTEGER  Check interval in seconds
  --count INTEGER     Number of checks
  --region TEXT       Region
  --az TEXT           Availability zone
```

**Example:**
```bash
lws lxc resources 100 --interval 5 --count 10
```

### `lxc health-check`

Perform health check on a container.

```bash
lws lxc health-check <instance_id> [OPTIONS]

Options:
  --fix           Attempt to fix issues automatically
  --region TEXT   Region
  --az TEXT       Availability zone
```

### `lxc report`

Generate comprehensive container report.

```bash
lws lxc report <instance_id> [OPTIONS]

Options:
  --output TEXT   Output format (json|text)
  --file TEXT     Save to file
  --region TEXT   Region
  --az TEXT       Availability zone
```

## Docker/App Commands (`app`)

### `app setup`

Install Docker and Docker Compose in a container.

```bash
lws app setup <instance_id> [OPTIONS]

Options:
  --package-name TEXT  Package to install (default: docker)
  --region TEXT        Region
  --az TEXT            Availability zone
```

### `app run`

Execute docker run inside a container.

```bash
lws app run <instance_id> <docker_command> [OPTIONS]

Options:
  --region TEXT   Region
  --az TEXT       Availability zone
```

**Example:**
```bash
lws app run 100 "-d -p 80:80 nginx"
```

### `app deploy`

Manage Docker Compose applications.

```bash
lws app deploy <action> <instance_id> [OPTIONS]

Actions: install, uninstall, start, stop, restart, status

Options:
  --compose-file TEXT  Docker Compose file path (required)
  --auto-start         Start after install
  --region TEXT        Region
  --az TEXT            Availability zone
```

**Example:**
```bash
lws app deploy install 100 \
  --compose-file docker-compose.yml \
  --auto-start
```

### `app logs`

Fetch Docker logs from a container.

```bash
lws app logs <instance_id> <container_name> [OPTIONS]

Options:
  --follow        Follow log output
  --lines INTEGER Number of lines
  --region TEXT   Region
  --az TEXT       Availability zone
```

### `app list`

List Docker containers in an LXC container.

```bash
lws app list <instance_id> [OPTIONS]

Options:
  --region TEXT   Region
  --az TEXT       Availability zone
```

### `app remove`

Uninstall Docker from containers.

```bash
lws app remove <instance_ids...> [OPTIONS]

Options:
  --purge         Remove all Docker data
  --region TEXT   Region
  --az TEXT       Availability zone
```

## Security Commands (`sec`)

### `sec scan`

Perform security scan on a container.

```bash
lws sec scan <instance_id> [OPTIONS]

Options:
  --scan-type TEXT  Scan type (full|quick)
  --region TEXT     Region
  --az TEXT         Availability zone
```

### `sec discovery`

Discover reachable hosts in the network.

```bash
lws sec discovery [lxc_id] [OPTIONS]

Options:
  --region TEXT   Region
  --az TEXT       Availability zone
```

## Common Patterns

### Managing Multiple Containers

```bash
# Start multiple containers
lws lxc start 100 101 102 103

# Stop all containers in a region
lws lxc stop $(lws lxc show | grep 'running' | awk '{print $1}')

# Scale multiple containers
for id in 100 101 102; do
  lws lxc scale $id --memory 4096 --cpulimit 4
done
```

### Backup Strategy

```bash
# Create snapshots before updates
lws lxc snapshot-add 100 before-$(date +%Y%m%d)

# Create full backup
lws lxc backup-create 100 --download

# Schedule regular backups (crontab)
0 2 * * * /path/to/lws lxc backup-create 100
```

### Resource Monitoring

```bash
# Check all containers
lws lxc show

# Monitor specific container
lws lxc resources 100 --interval 5 --count 60

# Generate performance report
lws lxc report 100 --output json --file report-$(date +%Y%m%d).json
```

---

[← Architecture](architecture.html) | [Next: API Reference →](api-reference.html)
