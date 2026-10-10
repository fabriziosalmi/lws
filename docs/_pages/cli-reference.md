---
title: CLI Reference
seo_title: "CLI reference: every lws command for Proxmox and LXC"
description: "Every LWS command with its options and an example: Proxmox hosts (px), LXC containers (lxc), Docker apps (app), configuration (conf) and security (sec)."
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

Every command below that takes `--region`/`--az` also accepts `--location`/`--node` as aliases for the same two options - this is not repeated per command in this reference.

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

Upgrade the packages of the configured Proxmox hosts with `apt-get update` and `apt-get dist-upgrade`, the upgrade Proxmox VE requires (plain `upgrade` skips new dependencies such as a new kernel). Existing configuration files are kept. The command lists the hosts and asks before it starts; a new kernel takes effect after a reboot.

```bash
lws px update [OPTIONS]

Options:
  --region TEXT   Only hosts in this region (default: every configured host)
  --az TEXT       Only this availability zone (requires --region)
  --yes           Do not ask for confirmation
```

**Example:**
```bash
lws px update --region eu-south-1 --az az2
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

Back up a single LXC container with `vzdump --storage <storage> --mode <mode>`, run on the Proxmox host. The archive stays on that storage; compression follows the host's `/etc/vzdump.conf`, and retention follows the storage's own backup retention settings (or `/etc/vzdump.conf`). `lxc backup-create` does the same with more options.

```bash
lws px backup-lxc <vmid> --storage <storage-target> [OPTIONS]

Options:
  --storage TEXT  The storage target where the backup will be stored (required)
  --mode TEXT     Backup mode: snapshot, suspend, or stop (default: snapshot)
  --region TEXT   Region
  --az TEXT       Availability zone
```

### `px backup`

Back up the Proxmox host configuration (`/etc/pve`) as `<backup_dir>/proxmox-backup.tar.gz`. The directory is created if needed, and the archive is written on the Proxmox host, not on the machine running LWS (unless `use_local_only` is set). The fixed file name means each run replaces the previous one.

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

List the security groups of the cluster firewall and their rules, numbered by position, as the Proxmox API reports them.

```bash
lws px security-groups [OPTIONS]

Options:
  --region TEXT   Region
  --az TEXT       Availability zone
```

The security group commands go through `pvesh`, the command-line client of the Proxmox VE API on the host. The API validates every rule and writes the firewall files in `/etc/pve/firewall/` itself.

### `px security-group-add` / `security-group-rm`

Create or delete a security group in the cluster firewall.

```bash
lws px security-group-add <group_name> [OPTIONS]

Options:
  --description TEXT  Comment shown with the group
  --region TEXT        Region
  --az TEXT            Availability zone

lws px security-group-rm <group_name> [OPTIONS]

Options:
  --force         Also delete the group's rules (without it, a group with rules is kept)
  --region TEXT   Region
  --az TEXT       Availability zone
```

### `px security-group-rule-add` / `security-group-rule-rm`

Add or remove a firewall rule in an existing security group.

```bash
lws px security-group-rule-add <group_name> --direction <IN|OUT> [OPTIONS]
lws px security-group-rule-rm <group_name> --direction <IN|OUT> [OPTIONS]

Options:
  --direction [IN|OUT]              Direction of the rule (required)
  --action [ACCEPT|DROP|REJECT]     Action (default: ACCEPT)
  --protocol TEXT                   e.g. tcp, udp, icmp (default: tcp)
  --source-ip TEXT                  Source IP or CIDR
  --source-port TEXT                Source port or range (e.g. 22, 80:443)
  --destination-ip TEXT             Destination IP or CIDR
  --destination-port TEXT           Destination port or range
  --region TEXT                     Region
  --az TEXT                         Availability zone
```

**Example:**
```bash
lws px security-group-rule-add web --direction IN --protocol tcp --destination-port 443
lws px security-group-rule-rm web --direction IN --protocol tcp --destination-port 443
```

`rule-rm` removes the rules that match all the given values exactly, including the defaults (`ACCEPT`, `tcp`); a value you leave out must be absent from the rule. It fails if no rule matches.

### `px security-group-attach` / `security-group-detach`

Attach a security group to a container, or detach it. The group becomes a rule in the container's firewall (`GROUP <name>`, enabled).

```bash
lws px security-group-attach <group_name> <vmid> [OPTIONS]
lws px security-group-detach <group_name> <vmid> [OPTIONS]

Options:
  --enable-firewall  (attach) Also enable the container's firewall and set
                     firewall=1 on its network interfaces
  --region TEXT      Region
  --az TEXT          Availability zone
```

Proxmox applies the rules only when the firewall is on at three levels: the datacenter, the container, and the container's network interface. `--enable-firewall` handles the last two. `attach` reports when the datacenter firewall is off; LWS does not enable it, because doing so without rules that allow SSH (22) and the web interface (8006) can lock you out of the hosts.

### `px exec`

Execute an arbitrary command on a Proxmox host over SSH. The arguments are joined into a single string and handed to the host's shell, so shell syntax works here. There is no confirmation prompt.

```bash
lws px exec <command>... [OPTIONS]

Options:
  --region TEXT   Region
  --az TEXT       Availability zone
```

**Example:**
```bash
lws px exec -- df -h /var/lib/vz
```

Put `--` before the command when any of its words start with `-`. Without it, LWS reads them as its own options: `lws px exec df -h` prints the LWS help page instead of running `df -h`.

## LXC Container Commands (`lxc`)

### `lxc run`

Create and start LXC containers.

```bash
lws lxc run [OPTIONS]

Options:
  --image-id TEXT        Container image template (required)
  --count INTEGER        Number of instances (default: 1)
  --size TEXT            Instance size, one of the keys under instance_sizes
                         in config.yaml (default: small)
  --hostname TEXT        Hostname for container; the container ID is appended
  --net0 TEXT            Network config string, Proxmox pct syntax
                         (default: name=eth0,bridge=<default_network>)
  --storage-size TEXT    Root disk size in GiB, replacing the size's own
                         (e.g. 16), on default_storage
  --features TEXT        LXC features, e.g. nesting=1 (needed for Docker)
  --unprivileged         Create an unprivileged container
  --onboot TEXT          Start the container on boot
                         (default: default_onboot in config.yaml, or True)
  --lock TEXT            Set a Proxmox lock on the container (default: none)
  --region TEXT          Region (default: eu-south-1)
  --az TEXT              Availability zone (default: az1)
  --max-retries INTEGER  Retries waiting for the container to start
                         (default: 5)
  --retry-delay INTEGER  Seconds between start retries (default: 5)
  --password TEXT        Root password, set with chpasswd once the
                         container runs (not passed to pct create)
  --ip TEXT              Fixed IP address
  --netmask TEXT         Network mask (default: 24)
  --gateway TEXT         Network gateway
  --dns TEXT             DNS servers (comma-separated)
  --dhcp                 Enable DHCP
```

**Examples:**
```bash
lws lxc run \
  --image-id local:vztmpl/ubuntu-22.04-standard_22.04-1_amd64.tar.zst \
  --size small \
  --count 3 \
  --hostname web-server \
  --password SecurePass123

# An unprivileged container ready for Docker
lws lxc run --size lws-web --unprivileged --features nesting=1,keyctl=1 --dhcp \
  --image-id local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst
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

Change the CPU, memory, disk and network limits of containers. CPU, memory and network changes use `pct set` and apply to a running container; the disk is grown with `pct resize`.

```bash
lws lxc scale <instance_ids...> [OPTIONS]

Options:
  --memory INTEGER        Memory in MB
  --cpulimit FLOAT        CPU time limit, in CPUs (0 removes the limit)
  --cpucores INTEGER      Number of CPU cores the container sees
  --storage-size TEXT     New root disk size, e.g. 32G, or +8G to add 8 GiB
                          (a plain number is GiB). Disks can only grow.
  --net-limit FLOAT       Rate limit of net0 in MB/s (0 removes the limit)
  --region TEXT           Region
  --az TEXT               Availability zone
```

**Example:**
```bash
lws lxc scale 100 --memory 4096 --cpucores 2 --storage-size 64G
```

Proxmox has no disk bandwidth limits for containers; the former `--disk-read-limit` and `--disk-write-limit` options are refused with an explanation.

### `lxc scale-check`

Compare a container's allocated cores, memory and root disk (from `pct config`) with the host's total cores and memory (`lscpu`, `free -m`), using the thresholds in `config.yaml`'s `scaling` block, and suggest new values. It reads allocations, not live usage (see `lxc resources` for that). Read-only: it never changes anything.

A container without a `cores` setting is counted by its `cpulimit`, or as using every host core when it has neither. Threshold values above 1 are read as percentages (80 means 0.80). A smaller disk is never suggested, since Proxmox cannot shrink one. The last line of the output is the `lxc scale` command that applies the suggestions, with `--cpulimit` for a container limited by `cpulimit` and `--cpucores` otherwise. See [Configuration](configuration.html#scaling-thresholds).

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
  --mount-point TEXT  Mount point inside the container, e.g. /mnt/data.
                      Not a true Click-required option (Click default is
                      None) - the command checks for it itself and prints
                      an error if it's missing, rather than failing at
                      argument-parsing time.
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
lws lxc exec 100 "apt-get update"

# Same command across multiple containers
lws lxc exec 100 101 102 "systemctl restart nginx"

# Several commands, or a pipeline: give them to a shell in the container
lws lxc exec 100 "sh -c 'apt-get update && apt-get -y upgrade'"
```

The command is split like a shell would split it (quotes group words) and run directly, without a shell, in every mode. Shell syntax such as `&&`, `|` or `>` therefore reaches the program as plain words; use `sh -c '...'` as above when you need it.

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
  --region TEXT           Region
  --az TEXT               Availability zone
  --use-local-only TEXT   Takes a string value, not a bare flag, despite
                          the name (e.g. --use-local-only true). Passed
                          straight through as a Python truthiness check,
                          so --use-local-only false is also truthy (any
                          non-empty string is) - omit the option entirely
                          to get the default (SSH/remote) behavior.
```

### `lxc clone`

Clone a container, on the same node or on another node of the cluster.

```bash
lws lxc clone <source_id> <target_id> [OPTIONS]

Options:
  --region TEXT              Region
  --az TEXT                  Availability zone
  --target-host TEXT         Cluster node to create the clone on
  --description TEXT         Description for the new container
  --hostname TEXT            Hostname for the new container
  --storage TEXT             Target storage for the clone
  --full                     Full clone (only matters when cloning a template)
  --pool TEXT                Add the new container to the specified pool
  --bwlimit TEXT             I/O bandwidth limit in KiB/s, digits only
  --start / --no-start       Start the cloned container after creation
                             (default: --start)
```

**Example:**
```bash
lws lxc clone 100 200 --hostname web-copy
```

To clone a running container, the command takes a temporary snapshot of the source (`lws-clone-<timestamp>`), clones from it with `pct clone --snapname`, and deletes the snapshot afterwards. In Proxmox, a clone of a regular container is always a full copy; linked clones exist only for templates. A clone created on another node is started there through the cluster API.

### `lxc migrate`

Move a container to another node of the same Proxmox cluster with `pct migrate`, run on the source node.

```bash
lws lxc migrate <instance_id> --target-host <node> [OPTIONS]

Options:
  --target-host TEXT     Proxmox node name to move to (required)
  --restart              Migrate a running container: stop it, move it and
                         start it on the target
  --target-storage TEXT  Storage on the target node for the disks
  --region TEXT          Region
  --az TEXT              Availability zone
```

**Example:**
```bash
lws lxc migrate 105 --target-host pve2 --restart
```

`--target-host` is the node name as the cluster knows it (`lws px clusters` lists them), not an availability zone from `config.yaml`. Without `--restart`, Proxmox refuses to move a running container.

### `lxc backup-create` / `backup-restore`

Create a vzdump backup of a container, or restore one.

```bash
# Create a backup
lws lxc backup-create <instance_id> [OPTIONS]

Options:
  --destination TEXT                  Directory on the host for the archive
                                      (default: /var/lib/vz/dump)
  --storage TEXT                      A Proxmox backup storage to use instead
                                      of --destination
  --mode [snapshot|suspend|stop]      vzdump mode (default: snapshot)
  --compress [zstd|gzip|lzo|none]     Compression (default: zstd)
  --download                          Copy the archive into the current
                                      directory afterwards
  --region TEXT                       Region
  --az TEXT                           Availability zone

# Restore a backup
lws lxc backup-restore <instance_id> --backup-file <archive> [OPTIONS]

Options:
  --backup-file TEXT       vzdump archive: a path on the host, a volume ID
                           (local:backup/...), or a local file to upload (required)
  --storage TEXT           Storage for the restored disks (default: default_storage)
  --start / --no-start     Start the container afterwards (default: --start)
  --force                  Do not ask for confirmation
  --region TEXT            Region
  --az TEXT                Availability zone
```

**Examples:**
```bash
lws lxc backup-create 100
lws lxc backup-create 100 --storage backups --mode stop --compress gzip

lws lxc backup-restore 100 --backup-file /var/lib/vz/dump/vzdump-lxc-100-2026_10_10-02_00_00.tar.zst
lws lxc backup-restore 205 --backup-file local:backup/vzdump-lxc-100-2026_10_10-02_00_00.tar.zst
```

`backup-create` prints the archive file vzdump wrote. `snapshot` mode keeps the container running and works on storage that supports snapshots (LVM-thin, ZFS, Ceph); elsewhere vzdump falls back to `suspend`. `stop` mode works everywhere and stops the container during the backup.

`backup-restore` restores with `pct restore`. If the container ID is free, the backup becomes a new container. If it exists, the command asks before replacing it: the container is stopped, and its current disks are destroyed and replaced by the backup. The backup file is never deleted; only a temporary copy uploaded from your machine is removed afterwards. The disks go to `--storage`, or to `default_storage` from `config.yaml`; without either, the command stops, because `pct restore` would use the storage named `local`, which cannot hold container disks on a default installation.

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

Check CPU, memory and disk use inside a container against an 80% limit, and DNS resolution. When CPU or memory is high, it lists the busiest processes.

```bash
lws lxc health-check <instance_id> [OPTIONS]

Options:
  --fix           When the disk is over 80% full, delete files older than
                  7 days in /tmp and /var/tmp; when DNS fails, restart networking
  --region TEXT   Region
  --az TEXT       Availability zone
```

### `lxc net`

Check whether a port is open on a container with `nc -z`, first from inside it, then (if that fails) from the Proxmox host to the container's IP. For UDP (`nc -zu`), a port is reported closed only when an ICMP "port unreachable" comes back, so an "open" UDP result is a best guess.

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

The `app` commands install Docker in a Debian or Ubuntu container and run Docker containers or Compose applications in it.

### `app setup`

Install Docker and Docker Compose in a container from its apt repositories: `docker.io`, plus `docker-compose-v2` (Ubuntu) or `docker-compose` (Debian). The container must be running.

```bash
lws app setup <instance_id> [OPTIONS]

Options:
  --enable-nesting     Set the LXC features Docker needs (nesting=1, and
                       keyctl=1 for unprivileged containers), then restart
                       the container
  --region TEXT        Region
  --az TEXT            Availability zone
```

Without `--enable-nesting`, the command warns when the features are missing. A second, optional positional argument (`package_name`) is accepted for compatibility and ignored.

### `app run`

Execute docker run inside a container.

```bash
lws app run [OPTIONS] <instance_id> -- <docker run arguments>...

Options:
  --region TEXT   Region
  --az TEXT       Availability zone
```

**Example:**
```bash
lws app run 100 -- -d -p 80:80 nginx
```

The arguments after `--` are passed to `docker run` one by one, so this runs `docker run -d -p 80:80 nginx` in container 100. The `--` is required whenever the first Docker argument starts with `-`. Docker must already be installed (`app setup`).

### `app deploy`

Manage a Docker Compose application.

```bash
lws app deploy <action> <instance_id> --compose-file <file> [OPTIONS]

Actions: install, uninstall, start, stop, restart, status

Options:
  --compose-file TEXT  Local path or URL of the Compose file (required)
  --auto-start         With install: start the app at boot
  --region TEXT        Region
  --az TEXT            Availability zone
```

**Example:**
```bash
lws app deploy install 100 --compose-file ./docker-compose.yml --auto-start
lws app deploy status 100 --compose-file ./docker-compose.yml
```

The first service name in the Compose file is the application name. `install` copies the file to `/opt/lws/apps/<app>/docker-compose.yml` in the container and runs `docker compose -p <app> up -d` there; the other actions use the same project, so they find the containers again. `--auto-start` installs a systemd unit, `lws-<app>.service`, in the container; `uninstall` removes it.

### `app update`

Copy a new version of the Compose file into the container, pull its images and recreate the services that changed (`pull`, then `up -d`). Unlike `app deploy`, `compose_file` here is a positional argument, not an option.

```bash
lws app update <instance_id> <compose_file> [OPTIONS]

Options:
  --region TEXT   Region
  --az TEXT       Availability zone
```

### `app logs`

Show the logs of a Docker container inside an LXC container.

```bash
lws app logs <instance_id> <container_name> [OPTIONS]

Options:
  --tail TEXT     Number of lines to show from the end (default: all)
  --region TEXT   Region
  --az TEXT       Availability zone
```

The logs are printed once; LWS cannot stream them. To follow them, run `pct exec <instance_id> -- docker logs -f <container>` on the host.

### `app list`

List the running Docker containers in an LXC container.

```bash
lws app list <instance_id> [OPTIONS]

Options:
  --region TEXT   Region
  --az TEXT       Availability zone
```

### `app remove`

Uninstall Docker from containers. Only the Docker packages that are installed are removed.

```bash
lws app remove <instance_ids...> [OPTIONS]

Options:
  --purge         First remove all Docker images, containers, volumes and networks
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
# Create a snapshot before an update
lws lxc snapshot-add 100 before-$(date +%Y%m%d)

# Create a full backup and copy it here
lws lxc backup-create 100 --download

# Schedule a nightly backup (crontab; run from the folder with config.yaml)
0 2 * * * cd /opt/lws && python3 lws.py lxc backup-create 100 --storage backups
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
