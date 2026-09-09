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

### `px update`

Run `apt-get update` on the machine running `lws` — **not** on any configured Proxmox host, and it takes no `--region`/`--az` (there's nothing to target). Despite the name and the `px` group, this always runs locally.

```bash
lws px update
```

### `px cluster-start` / `cluster-stop` / `cluster-restart`

Start, stop, or restart the `pve-cluster` and `corosync` services on a Proxmox host.

```bash
lws px cluster-start [OPTIONS]
lws px cluster-stop [OPTIONS]
lws px cluster-restart [OPTIONS]

Options:
  --region TEXT   Region (default: eu-south-1)
  --az TEXT       Availability zone (default: az1)
```

### `px backup-lxc`

Back up a single LXC container via `vzdump`, run on the Proxmox host (not to be confused with `lxc backup-create`, which backs up through `pct`).

```bash
lws px backup-lxc <vmid> --storage <storage-target> [OPTIONS]

Options:
  --storage TEXT  The storage target where the backup will be stored (required)
  --mode TEXT     Backup mode: snapshot, suspend, or stop (default: snapshot)
  --region TEXT   Region
  --az TEXT       Availability zone
```

### `px backup`

Back up Proxmox host configuration (`/etc/pve`) to a local `.tar.gz`.

```bash
lws px backup <backup_dir> [OPTIONS]

Options:
  --region TEXT   Region
  --az TEXT       Availability zone
```

### `px image-add` / `image-rm`

Create a template image from an existing container, or delete one from the Proxmox template cache.

```bash
lws px image-add <instance_id> <template_name> [OPTIONS]
lws px image-rm <template_name> [OPTIONS]

Options:
  --region TEXT   Region
  --az TEXT       Availability zone
```

`image-add` stops the source container before templating it.

### `px security-groups`

List all security groups and their rules defined in the cluster firewall (`/etc/pve/firewall/cluster.fw`).

```bash
lws px security-groups [OPTIONS]

Options:
  --region TEXT   Region
  --az TEXT       Availability zone
```

### `px security-group-add` / `security-group-rm`

Create or delete a security group in the cluster firewall.

```bash
lws px security-group-add <group_name> [OPTIONS]

Options:
  --description TEXT  Description of the security group
  --region TEXT        Region
  --az TEXT            Availability zone

lws px security-group-rm <group_name> [OPTIONS]

Options:
  --region TEXT   Region
  --az TEXT       Availability zone
```

### `px security-group-rule-add` / `security-group-rule-rm`

Add or remove a firewall rule within an existing security group.

```bash
lws px security-group-rule-add <group_name> --direction <IN|OUT> [OPTIONS]
lws px security-group-rule-rm <group_name> --direction <IN|OUT> [OPTIONS]

Options:
  --direction TEXT       IN or OUT (required)
  --action TEXT          ACCEPT, DROP, or REJECT (default: ACCEPT)
  --protocol TEXT        e.g. tcp, udp, icmp (default: tcp)
  --source-ip TEXT        Source IP or CIDR
  --source-port TEXT      Source port or range (e.g. 22, 80:443)
  --destination-ip TEXT   Destination IP or CIDR
  --destination-port TEXT Destination port or range
  --region TEXT           Region
  --az TEXT               Availability zone
```

**Example:**
```bash
lws px security-group-rule-add web --direction IN --protocol tcp \
  --destination-port 443
```

### `px security-group-attach` / `security-group-detach`

Attach or detach a security group from a specific container's firewall config (`/etc/pve/firewall/<vmid>.fw`).

```bash
lws px security-group-attach <group_name> <vmid> [OPTIONS]
lws px security-group-detach <group_name> <vmid> [OPTIONS]

Options:
  --region TEXT   Region
  --az TEXT       Availability zone
```

### `px exec`

Execute an arbitrary command on a Proxmox host over SSH. Unlike `lxc exec`, the command is joined into a single string and handed to the remote shell — there is no confirmation flag.

```bash
lws px exec <command>... [OPTIONS]

Options:
  --region TEXT   Region
  --az TEXT       Availability zone
```

**Example:**
```bash
lws px exec df -h /var/lib/vz
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

### `lxc show-info`

Retrieve IP address(es), in-container hostname, DNS servers, and the container's Proxmox-side hostname.

```bash
lws lxc show-info <instance_id> [OPTIONS]

Options:
  --region TEXT   Region
  --az TEXT       Availability zone
```

### `lxc show-public-ip`

Retrieve the public IP address(es) of a container.

```bash
lws lxc show-public-ip <instance_id> [OPTIONS]

Options:
  --region TEXT   Region
  --az TEXT       Availability zone
```

### `lxc show-storage`

Show storage usage inside a container (`df -h`).

```bash
lws lxc show-storage <instance_id> [OPTIONS]

Options:
  --region TEXT   Region
  --az TEXT       Availability zone
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

### `lxc scale-check`

Read a container's and its host's current resource usage against the thresholds in `config.yaml`'s `scaling` block and suggest whether to scale. Read-only — it only recommends, it never changes anything.

```bash
lws lxc scale-check <instance_id> [OPTIONS]

Options:
  --region TEXT   Region
  --az TEXT       Availability zone
```

### `lxc volume-attach` / `volume-detach`

Attach or detach a storage volume (`pct set --mp0=...`).

```bash
lws lxc volume-attach <instance_id> <volume_name> <volume_size> --mount-point <path> [OPTIONS]

Options:
  --mount-point TEXT  Mount point inside the container, e.g. /mnt/data (required)
  --region TEXT       Region
  --az TEXT           Availability zone

lws lxc volume-detach <instance_id> <volume_name> [OPTIONS]

Options:
  --region TEXT   Region
  --az TEXT       Availability zone
```

`volume-detach` always removes the container's `mp0` mount point — the `volume_name` argument is accepted but not used to pick which mount to remove.

### `lxc service`

Run a `systemctl` action against a service inside one or more containers.

```bash
lws lxc service <action> <service_name> <instance_ids...> [OPTIONS]

Arguments:
  action        One of: status, start, stop, restart, reload, enable
  service_name  The systemd unit name
  instance_ids  One or more instance IDs

Options:
  --region TEXT   Region
  --az TEXT       Availability zone
```

**Example:**
```bash
lws lxc service restart nginx 100 101
```

### `lxc exec`

Execute a command inside one or more containers.

```bash
lws lxc exec <instance_id>... <command> [OPTIONS]

Arguments:
  instance_id...  One or more instance IDs (space-separated, at least one required)
  command         The command to run, as a single argument — quote it if it has spaces

Options:
  --region TEXT   Region
  --az TEXT       Availability zone
```

**Examples:**
```bash
lws lxc exec 100 "apt update && apt upgrade -y"

# Same command across multiple containers
lws lxc exec 100 101 102 "systemctl restart nginx"
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

Backup and restore containers. The two commands take different options — `--backup-file` only applies to restore, not create.

```bash
# Create backup
lws lxc backup-create <instance_id> [OPTIONS]

Options:
  --destination TEXT    Destination directory for the backup (default: /var/lib/vz/dump)
  --download            Download the backup file to the local system
  --compress-level INT  Compression level, 1-9 (default: 6)
  --region TEXT         Region
  --az TEXT             Availability zone

# Restore from backup
lws lxc backup-restore <instance_id> --backup-file <path> [OPTIONS]

Options:
  --backup-file TEXT  Path to the backup file to restore (required)
  --force             Force restore without confirmation
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

### `lxc status`

A one-shot snapshot (load average, memory, disk, swap) for one or more containers — unlike `lxc resources`, this doesn't poll on an interval, and it takes multiple instance IDs.

```bash
lws lxc status <instance_ids...> [OPTIONS]

Options:
  --region TEXT   Region
  --az TEXT       Availability zone
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

### `lxc net`

Check whether a TCP or UDP port is open on a container, first from inside it, then (if that fails) from the Proxmox host to the container's IP.

```bash
lws lxc net <instance_id> <tcp|udp> <port> [OPTIONS]

Options:
  --timeout INTEGER  Timeout in seconds for the check (default: 5)
  --region TEXT       Region
  --az TEXT           Availability zone
```

**Example:**
```bash
lws lxc net 100 tcp 443
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
lws app setup <instance_id> [package_name] [OPTIONS]

Arguments:
  package_name         Package to install, positional, not a flag (default: docker)

Options:
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
  --compose_file TEXT  Docker Compose file path (required — note the underscore, not a hyphen)
  --auto_start         Start after install (also an underscore)
  --region TEXT        Region
  --az TEXT            Availability zone
```

**Example:**
```bash
lws app deploy install 100 \
  --compose_file docker-compose.yml \
  --auto_start
```

### `app update`

Upload a new Compose file to a container and re-deploy. Unlike `app deploy`, `compose_file` here is a positional argument, not an option.

```bash
lws app update <instance_id> <compose_file> [OPTIONS]

Options:
  --region TEXT   Region
  --az TEXT       Availability zone
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
