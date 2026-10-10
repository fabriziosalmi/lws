---
title: API Reference
seo_title: "REST API reference: Proxmox and LXC endpoints"
description: "Endpoints of the LWS REST API: API key authentication, Proxmox host operations, LXC lifecycle, snapshots, volumes, migration, Docker apps and errors."
---

# API Reference

LWS provides a comprehensive REST API for programmatic access to all functionality.

## Base URL

```
http://localhost:8080/api/v1
```

## Authentication

Most endpoints require API key authentication via the `X-API-Key` header.

```bash
curl -H "X-API-Key: your-api-key" \
  http://localhost:8080/api/v1/lxc/instances
```

Generate a key and write it into `config.yaml` in one step, so no example
value ever ends up in the file:

```bash
KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
sed -i "s|^api_key:.*|api_key: \"$KEY\"|" config.yaml   # on macOS: sed -i ''
echo "$KEY"   # give this to API clients
```

The server refuses to start when `api_key` is empty or one of the example
values that ship in the repository. Do not use a value copied from any
documentation page: anything published is known to everyone.

## Response Format

### Success Response (HTTP 200)
```json
{
  "output": "command output here"
}
```
If the underlying command's stdout starts with `{` or `[` (e.g. commands run with a JSON output option), the API returns that parsed JSON directly instead of wrapping it in `"output"`.

### Error Responses

There is no single error shape. It depends on where the request failed:

**The underlying `lws.py` command ran and exited non-zero (HTTP 500):**
```json
{
  "error": "Command execution failed",
  "details": "stderr from the command",
  "output": "stdout from the command, if any",
  "return_code": 1
}
```

**Request validation failed in the route handler itself - missing/invalid body fields (HTTP 400), most endpoints below:**
```json
{
  "error": "Missing 'field_name' in request body"
}
```
No `details` or `return_code` - just `error`.

**Missing/invalid API key (HTTP 401), a non-numeric `instance_id` path segment (HTTP 400, see note below), or any other Flask `HTTPException`:**
```json
{
  "code": 401,
  "name": "Unauthorized",
  "description": "Unauthorized: Invalid or missing API key."
}
```
A different shape again - `code`/`name`/`description`, not `error`.

**Route not found (HTTP 404) or an unhandled exception (HTTP 500):**
```json
{
  "error": "Not Found",
  "message": "The requested URL was not found on the server."
}
```
`error`/`message`, not `error`/`details`.

> **Note:** a global `before_request` hook rejects any request whose `<instance_id>` URL path segment isn't purely numeric, with HTTP 400 in the `code`/`name`/`description` shape above, before the route handler runs at all. This affects every endpoint below with `{instance_id}` in its path. The same validation (`validate_instance_ids_list`) also applies to the `instance_ids` JSON body field on the bulk endpoints (`/lxc/instances/start`, `/stop`, `/status`, `/scale`, `/terminate`, `/reboot`, `/lxc/instances/app/remove`): every element must be numeric, or the whole request is rejected with 400 in the `error`-only shape above.

> **Note:** `run_lws_command` builds the underlying CLI call from two sources: a handler-built positional `cmd_parts` list, and whatever is left in the request body/query string after the handler pops out the keys it already placed positionally (via `consumed_keys`). Earlier versions didn't pop those keys, so several endpoints below sent the same value twice — once positionally, once as a nonexistent `--key value` flag — and failed with a Click "no such option" error. That's fixed; it's noted on the endpoints below only where it's useful to know a field is positional rather than an option.

## API Endpoints

### Health & Status

#### GET `/health`

Check API health status (no authentication required).

```bash
curl http://localhost:8080/api/v1/health
```

**Response:**
```json
{
  "status": "ok"
}
```

### Configuration Endpoints

#### GET `/conf`

Show current configuration (masked).

```bash
curl -H "X-API-Key: your-key" \
  http://localhost:8080/api/v1/conf
```

#### POST `/conf/validate`

Validate configuration.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  http://localhost:8080/api/v1/conf/validate
```

#### POST `/conf/backup`

Back up the current configuration to a file. Unlike most POST handlers, this one builds `--timestamp`/`--compress` flags manually instead of forwarding the whole body.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{
    "destination_path": "/backup/lws-config.yaml",
    "timestamp": true,
    "compress": true
  }' \
  http://localhost:8080/api/v1/conf/backup
```

### Proxmox Host Endpoints

#### GET `/px/hosts`

List all Proxmox hosts.

```bash
curl -H "X-API-Key: your-key" \
  http://localhost:8080/api/v1/px/hosts
```

**Query Parameters:**
- `region` - Filter by region

#### GET `/px/status`

Get Proxmox host resource usage.

```bash
curl -H "X-API-Key: your-key" \
  "http://localhost:8080/api/v1/px/status?region=eu-south-1&az=az1"
```

#### POST `/px/reboot`

Reboot a Proxmox host.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"region": "eu-south-1", "az": "az1", "confirm": true}' \
  http://localhost:8080/api/v1/px/reboot
```

#### GET `/px/templates`

List available templates.

```bash
curl -H "X-API-Key: your-key" \
  "http://localhost:8080/api/v1/px/templates?region=eu-south-1&az=az1"
```

#### GET `/px/clusters`

List all clusters in the Proxmox environment.

```bash
curl -H "X-API-Key: your-key" \
  "http://localhost:8080/api/v1/px/clusters?region=eu-south-1&az=az1"
```

#### POST `/px/update`

Run `apt-get update` and `apt-get dist-upgrade` on Proxmox hosts. Without a body, every configured host is updated; `region`, and `region` with `az`, limit it. The request is the confirmation: the API always passes `--yes`.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"region": "eu-south-1", "az": "az1"}' \
  http://localhost:8080/api/v1/px/update
```

Upgrading a host can take many minutes. The request waits for it, up to `api.command_timeout` seconds.

#### POST `/px/cluster/start` / `/px/cluster/stop` / `/px/cluster/restart`

Start, stop, or restart cluster services (`pve-cluster`, `corosync`) on a Proxmox host.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"region": "eu-south-1", "az": "az1"}' \
  http://localhost:8080/api/v1/px/cluster/start
```

#### POST `/px/backup-lxc`

Back up a single LXC container via `vzdump` on the Proxmox host. `vmid` and `storage` are both required (400 if either is missing); `vmid` is positional in `px backup-lxc`, `storage`/`mode` are forwarded as options.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"vmid": "100", "storage": "local-lvm", "mode": "snapshot"}' \
  http://localhost:8080/api/v1/px/backup-lxc
```

#### POST `/px/backup`

Back up Proxmox host configuration (`/etc/pve`) to a local `.tar.gz`. `backup_dir` is positional.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"backup_dir": "/backups/px", "region": "eu-south-1", "az": "az1"}' \
  http://localhost:8080/api/v1/px/backup
```

#### POST `/px/image`

Create a template image from an LXC container. `instance_id` and `template_name` are both positional.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"instance_id": "100", "template_name": "my-template"}' \
  http://localhost:8080/api/v1/px/image
```

#### DELETE `/px/image/{template_name}`

Delete a template image from the Proxmox template cache. `template_name` comes from the URL.

```bash
curl -X DELETE -H "X-API-Key: your-key" \
  "http://localhost:8080/api/v1/px/image/my-template?region=eu-south-1&az=az1"
```

#### GET `/px/security-groups`

List the security groups of the cluster firewall, with their rules, through the Proxmox API (`pvesh`).

```bash
curl -H "X-API-Key: your-key" \
  "http://localhost:8080/api/v1/px/security-groups?region=eu-south-1&az=az1"
```

#### POST `/px/security-groups`

Create a security group. `group_name` is positional.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"group_name": "web", "description": "Web tier"}' \
  http://localhost:8080/api/v1/px/security-groups
```

#### DELETE `/px/security-groups/{group_name}`

Delete a security group. `group_name` comes from the URL. A group that still has rules is not deleted unless the query string has `force=true`, which deletes its rules first.

```bash
curl -X DELETE -H "X-API-Key: your-key" \
  "http://localhost:8080/api/v1/px/security-groups/web?region=eu-south-1&az=az1&force=true"
```

#### POST `/px/security-groups/{group_name}/rules` / DELETE `.../rules`

Add or remove a firewall rule within an existing security group. `group_name` comes from the URL; the rule fields (`direction`, `action`, `protocol`, `source_ip`, `source_port`, `destination_ip`, `destination_port`) are all real options on `px security-group-rule-add`/`rule-rm`. `protocol`, the IP/CIDR fields, and the port fields are validated server-side (allow-listed characters, or parsed as an IP/CIDR) before being used. `DELETE` removes the rules whose fields match the request exactly; fields left out must be unset in the rule too.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"direction": "IN", "protocol": "tcp", "destination_port": "443"}' \
  http://localhost:8080/api/v1/px/security-groups/web/rules
```

#### POST `/px/security-groups/attach` / `/px/security-groups/detach`

Attach or detach a security group from a container's firewall config. `group_name` and `vmid` are both positional; both are validated server-side (`group_name` against an allow-listed charset, `vmid` as numeric).

The rules of an attached group apply only while the container's firewall is on. `"enable_firewall": true` on `attach` turns it on, and sets `firewall=1` on the container's network interfaces; without it, the response warns when the firewall is off.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"group_name": "web", "vmid": "100", "enable_firewall": true}' \
  http://localhost:8080/api/v1/px/security-groups/attach
```

#### POST `/px/upload`

Upload an LXC template to a Proxmox host. `local_path` and `remote_template_name` are both positional.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"local_path": "./ubuntu-22.04.tar.gz", "remote_template_name": "ubuntu-22.04"}' \
  http://localhost:8080/api/v1/px/upload
```

#### POST `/px/exec`

Execute a command on a Proxmox host over SSH. `command` is a string or a list of strings; `region` and `az` are optional. Other body fields are ignored.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"command": "df -h /var/lib/vz"}' \
  http://localhost:8080/api/v1/px/exec
```

The API refuses command arguments that contain any of `` ; & | ` $ ( ) { } ``. This check is a guard against mistakes, not a sandbox: the command runs on the host's shell, as root, and any command can be sent through this endpoint. For pipes and command lists, use the CLI or a script on the host.

### LXC Container Endpoints

#### POST `/lxc/instances`

Create and start LXC containers.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{
    "image_id": "local:vztmpl/ubuntu-22.04-standard_22.04-1_amd64.tar.zst",
    "size": "small",
    "count": 1,
    "hostname": "web-server",
    "region": "eu-south-1",
    "az": "az1"
  }' \
  http://localhost:8080/api/v1/lxc/instances
```

**Request Body:**
```json
{
  "image_id": "string (required)",
  "size": "string (default: small)",
  "count": "integer (default: 1)",
  "hostname": "string",
  "password": "string",
  "ip": "string",
  "netmask": "string (default: 24)",
  "gateway": "string",
  "dns": "string",
  "dhcp": "boolean",
  "storage_size": "string, root disk in GiB (uses default_storage)",
  "features": "string, e.g. nesting=1,keyctl=1",
  "unprivileged": "boolean",
  "region": "string",
  "az": "string"
}
```

`size` must be one of the `instance_sizes` in `config.yaml`.

#### GET `/lxc/instances`

List all LXC containers.

```bash
curl -H "X-API-Key: your-key" \
  "http://localhost:8080/api/v1/lxc/instances?region=eu-south-1&az=az1"
```

#### GET `/lxc/instances/{instance_id}`

Get details of a specific container.

```bash
curl -H "X-API-Key: your-key" \
  http://localhost:8080/api/v1/lxc/instances/100
```

#### POST `/lxc/instances/start`

Start containers. `instance_ids` is a list of positional arguments; every element must be numeric (Proxmox container IDs always are) or the request is rejected with 400.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{
    "instance_ids": ["100", "101", "102"],
    "region": "eu-south-1",
    "az": "az1"
  }' \
  http://localhost:8080/api/v1/lxc/instances/start
```

#### POST `/lxc/instances/stop`

Stop containers. Same `instance_ids` handling as `/lxc/instances/start` above.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{
    "instance_ids": ["100", "101"],
    "region": "eu-south-1",
    "az": "az1"
  }' \
  http://localhost:8080/api/v1/lxc/instances/stop
```

#### POST `/lxc/instances/terminate`

Terminate (destroy) containers. Same `instance_ids` handling as `/lxc/instances/start` above.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{
    "instance_ids": ["100"],
    "region": "eu-south-1",
    "az": "az1"
  }' \
  http://localhost:8080/api/v1/lxc/instances/terminate
```

#### POST `/lxc/instances/reboot`

Reboot running containers. Same `instance_ids` handling as `/lxc/instances/start` above.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"instance_ids": ["100", "101"], "region": "eu-south-1", "az": "az1"}' \
  http://localhost:8080/api/v1/lxc/instances/reboot
```

#### POST `/lxc/instances/status`

A one-shot resource snapshot (load average, memory, disk, swap) for one or more containers. Same `instance_ids` handling as `/lxc/instances/start` above.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"instance_ids": ["100", "101"], "region": "eu-south-1", "az": "az1"}' \
  http://localhost:8080/api/v1/lxc/instances/status
```

#### POST `/lxc/instances/scale`

Scale container resources. Same `instance_ids` handling as `/lxc/instances/start` above. The fields are `memory` (MB), `cpulimit`, `cpucores`, `storage_size` and `net_limit` (MB/s), as in `lxc scale`. `storage_size` grows the root disk with `pct resize` (`"64G"`, or `"+8G"` to add 8 GiB); disks cannot shrink. `disk_read_limit` and `disk_write_limit` are refused: Proxmox has no disk bandwidth limits for containers.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{
    "instance_ids": ["100"],
    "memory": 4096,
    "cpulimit": 4,
    "storage_size": "64G",
    "region": "eu-south-1",
    "az": "az1"
  }' \
  http://localhost:8080/api/v1/lxc/instances/scale
```

#### POST `/lxc/instances/clone`

Clone an LXC container. `source_instance_id` and `target_instance_id` are both positional in `lxc clone`.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"source_instance_id": "100", "target_instance_id": "200", "full": true}' \
  http://localhost:8080/api/v1/lxc/instances/clone
```

#### POST `/lxc/instances/{instance_id}/exec`

Execute a command in a container. `command` is a string, split into words like a shell would split it, or a list of strings; it runs in the container without a shell.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{
    "command": "apt-get -y upgrade",
    "region": "eu-south-1",
    "az": "az1"
  }' \
  http://localhost:8080/api/v1/lxc/instances/100/exec
```

As with `/px/exec`, command arguments that contain any of `` ; & | ` $ ( ) { } `` are refused. Send one request per command, or run a script that is already in the container.

#### POST `/lxc/instances/{instance_id}/snapshots`

Create a snapshot. `snapshot_name` is a positional argument in `lxc snapshot-add`.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{
    "snapshot_name": "before-update",
    "region": "eu-south-1",
    "az": "az1"
  }' \
  http://localhost:8080/api/v1/lxc/instances/100/snapshots
```

#### DELETE `/lxc/instances/{instance_id}/snapshots/{snapshot_name}`

Delete a snapshot.

```bash
curl -X DELETE \
  -H "X-API-Key: your-key" \
  "http://localhost:8080/api/v1/lxc/instances/100/snapshots/before-update?region=eu-south-1&az=az1"
```

#### GET `/lxc/instances/{instance_id}/snapshots`

List all snapshots of a container.

```bash
curl -H "X-API-Key: your-key" \
  "http://localhost:8080/api/v1/lxc/instances/100/snapshots?region=eu-south-1&az=az1"
```

#### POST `/lxc/instances/{instance_id}/volumes/attach`

Attach a storage volume. All three fields are required (400 if any is missing). `volume_name` and `volume_size` are both positional in `lxc volume-attach`; `mount_point` is a real option, enforced by a manual check in that command rather than by Click.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"volume_name": "local-lvm", "volume_size": "16G", "mount_point": "/mnt/data"}' \
  http://localhost:8080/api/v1/lxc/instances/100/volumes/attach
```

#### POST `/lxc/instances/{instance_id}/volumes/detach`

Detach a storage volume — this always removes the container's `mp0` mount, regardless of `volume_name`. `volume_name` is positional in `lxc volume-detach`.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"volume_name": "local-lvm"}' \
  http://localhost:8080/api/v1/lxc/instances/100/volumes/detach
```

#### POST `/lxc/instances/{instance_id}/service`

Run a `systemctl` action against a service inside a container. `action` and `service_name` are both positional in `lxc service`.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"action": "restart", "service_name": "nginx"}' \
  http://localhost:8080/api/v1/lxc/instances/100/service
```

#### POST `/lxc/instances/{instance_id}/migrate`

Migrate a container to another node of the same Proxmox cluster. `target_host` is the node name as the cluster knows it, not a zone from `config.yaml`. `"restart": true` moves a running container by stopping it and starting it on the target; `target_storage` puts its disks on another storage there.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"target_host": "pve2", "restart": true}' \
  http://localhost:8080/api/v1/lxc/instances/100/migrate
```

#### GET `/lxc/instances/{instance_id}/storage`

List storage usage inside a container.

```bash
curl -H "X-API-Key: your-key" \
  http://localhost:8080/api/v1/lxc/instances/100/storage
```

#### GET `/lxc/instances/{instance_id}/scale-check`

Read-only scaling recommendation based on the `scaling` thresholds in `config.yaml`.

```bash
curl -H "X-API-Key: your-key" \
  http://localhost:8080/api/v1/lxc/instances/100/scale-check
```

#### GET `/lxc/instances/{instance_id}/net-check`

Check whether a TCP/UDP port is open on a container. `protocol` and `port` are both positional in `lxc net`.

```bash
curl -H "X-API-Key: your-key" \
  "http://localhost:8080/api/v1/lxc/instances/100/net-check?protocol=tcp&port=443"
```

#### GET `/lxc/instances/{instance_id}/info`

Retrieve IP address(es), in-container hostname, DNS servers, and the container's Proxmox-side hostname.

```bash
curl -H "X-API-Key: your-key" \
  http://localhost:8080/api/v1/lxc/instances/100/info
```

#### GET `/lxc/instances/{instance_id}/public-ip`

Retrieve the public IP address(es) of a container.

```bash
curl -H "X-API-Key: your-key" \
  http://localhost:8080/api/v1/lxc/instances/100/public-ip
```

#### GET `/lxc/instances/{instance_id}/health-check`

Run health checks on a container.

```bash
curl -H "X-API-Key: your-key" \
  "http://localhost:8080/api/v1/lxc/instances/100/health-check"
```

`?fix=true` adds `--fix`: when the disk is over 80% full, files older than 7 days in `/tmp` and `/var/tmp` are deleted, and when DNS fails, networking is restarted. In every query string, `true` and `false` are read as flags: `true` adds the option, `false` leaves it out.

#### POST `/lxc/instances/{instance_id}/restore`

Restore a vzdump backup with `pct restore`. `backup_file` is a path on the Proxmox host or a volume ID (`local:backup/...`). Optional fields: `storage` for the restored disks (default: `default_storage` from `config.yaml`; the request fails when neither is set), `no_start` to leave the container stopped.

The CLI asks for confirmation before it restores, and the API cannot answer: send `"force": true`, or the request fails. If the container exists, `force` replaces it, and its current disks are destroyed. The backup file itself is kept.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"backup_file": "/var/lib/vz/dump/vzdump-lxc-100-2026_10_10-02_00_00.tar.zst", "force": true}' \
  http://localhost:8080/api/v1/lxc/instances/100/restore
```

#### POST `/lxc/instances/{instance_id}/backup`

Create a vzdump backup of a container. The fields are the options of `lxc backup-create`: `destination` (a directory on the host, default `/var/lib/vz/dump`) or `storage` (a Proxmox backup storage), `mode` (`snapshot`, `suspend` or `stop`) and `compress` (`zstd`, `gzip`, `lzo` or `none`). An empty body uses the defaults. The response includes the archive name.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"storage": "backups", "mode": "snapshot", "compress": "zstd"}' \
  http://localhost:8080/api/v1/lxc/instances/100/backup
```

`download` copies the archive to the machine that runs the API, into its working directory.

#### GET `/lxc/instances/{instance_id}/report`

Generate a comprehensive report about a container.

```bash
curl -H "X-API-Key: your-key" \
  http://localhost:8080/api/v1/lxc/instances/100/report
```

#### GET `/lxc/instances/{instance_id}/resources`

Monitor container resources.

```bash
curl -H "X-API-Key: your-key" \
  http://localhost:8080/api/v1/lxc/instances/100/resources
```

### Docker/App Endpoints

#### POST `/lxc/instances/{instance_id}/app/setup`

Install Docker and Docker Compose in a running container. `"enable_nesting": true` first sets the LXC features Docker needs (`nesting=1`, and `keyctl=1` for unprivileged containers) and restarts the container.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{
    "enable_nesting": true,
    "region": "eu-south-1",
    "az": "az1"
  }' \
  http://localhost:8080/api/v1/lxc/instances/100/app/setup
```

#### POST `/lxc/instances/{instance_id}/app/run`

Run `docker run` in a container. `docker_command` holds the arguments of `docker run`, as a list or as one string.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{
    "docker_command": ["-d", "-p", "80:80", "nginx"],
    "region": "eu-south-1",
    "az": "az1"
  }' \
  http://localhost:8080/api/v1/lxc/instances/100/app/run
```

#### POST `/lxc/instances/{instance_id}/app/deploy`

Manage a Compose application. `action` is one of `install`, `uninstall`, `start`, `stop`, `restart` and `status`. `compose_file` is a path on the machine that runs the API, or a URL; it is copied into the container under `/opt/lws/apps/<app>/`, where `<app>` is the first service name. `auto_start` (with `install`) adds a systemd unit in the container that starts the application at boot.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "install",
    "compose_file": "/path/to/docker-compose.yml",
    "auto_start": true,
    "region": "eu-south-1",
    "az": "az1"
  }' \
  http://localhost:8080/api/v1/lxc/instances/100/app/deploy
```

#### POST `/lxc/instances/{instance_id}/app/update`

Copy a new version of the Compose file into the container, pull its images and recreate the services that changed. `compose_file` is required.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"compose_file": "/path/to/docker-compose.yml"}' \
  http://localhost:8080/api/v1/lxc/instances/100/app/update
```

#### GET `/lxc/instances/{instance_id}/app/logs/{container_name}`

Get Docker logs.

```bash
curl -H "X-API-Key: your-key" \
  "http://localhost:8080/api/v1/lxc/instances/100/app/logs/nginx?tail=100"
```

`tail` is the number of lines from the end of the log, or `all` (the default). Streaming (`docker logs --follow`) is not available: the request returns the log as it is when the request arrives.

#### GET `/lxc/instances/{instance_id}/app/containers`

List Docker containers running inside an LXC container.

```bash
curl -H "X-API-Key: your-key" \
  http://localhost:8080/api/v1/lxc/instances/100/app/containers
```

#### POST `/lxc/instances/app/remove`

Uninstall Docker and Compose from one or more containers. `instance_ids` is a list of positional arguments; every element must be numeric or the request is rejected with 400. `"purge": true` first removes all Docker containers, images, volumes and networks.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"instance_ids": ["100", "101"]}' \
  http://localhost:8080/api/v1/lxc/instances/app/remove
```

### Security Endpoints

#### GET `/sec/discovery`

Discover reachable hosts. `sec discovery`'s `lxc_id` argument is optional and, when present, positional — as in the example below with `?lxc_id=...`.

```bash
curl -H "X-API-Key: your-key" \
  "http://localhost:8080/api/v1/sec/discovery?lxc_id=100"
```

#### GET `/lxc/instances/{instance_id}/sec/scan`

Security scan a container.

```bash
curl -H "X-API-Key: your-key" \
  "http://localhost:8080/api/v1/lxc/instances/100/sec/scan?scan_type=full"
```

## Web UI

The API includes a simple web interface at the root URL:

```
http://localhost:8080/
```

The Web UI provides:
- API key configuration
- Quick access to common operations
- Response visualization

## Swagger Documentation

Interactive API documentation is available at:

```
http://localhost:8080/api/v1/docs
```

Features:
- Interactive endpoint testing
- Request/response schemas
- Authentication testing

## Error Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 400 | Bad Request - Invalid parameters |
| 401 | Unauthorized - Invalid or missing API key |
| 404 | Not Found - Resource doesn't exist |
| 500 | Internal Server Error - Command execution failed |

## Rate Limiting

Currently, there are no rate limits. For production use, consider implementing rate limiting via a reverse proxy (nginx, Caddy).

## CORS Configuration

Configure allowed origins in `config.yaml`. Omitting `allowed_origins` denies all cross-origin browser access by default — this only affects browser-based JS; `curl`/scripts/server-to-server callers are never subject to CORS:

```yaml
api:
  allowed_origins:
    - "https://dashboard.example.net"
```

The web UI at `/` is served by the API itself, so it needs no entry.

## Production Deployment

`api.py` uses [waitress](https://pypi.org/project/waitress/), a production WSGI server, whenever `api.debug` is `false` (the default). `api.debug: true` switches to Flask's development server, meant for local use; the interactive debugger and the auto-reloader stay off either way, because Werkzeug's debugger allows arbitrary code execution.

[Running the API in production](api-in-production.html) covers the reverse proxy, TLS, a systemd unit and the Docker image.

## Example: Complete Workflow

### 1. Check API Health
```bash
curl http://localhost:8080/api/v1/health
```

### 2. List Proxmox Hosts
```bash
curl -H "X-API-Key: your-key" \
  http://localhost:8080/api/v1/px/hosts
```

### 3. Create Container
```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{
    "image_id": "local:vztmpl/ubuntu-22.04-standard_22.04-1_amd64.tar.zst",
    "size": "small",
    "hostname": "api-test"
  }' \
  http://localhost:8080/api/v1/lxc/instances
```

### 4. Monitor Container
```bash
curl -H "X-API-Key: your-key" \
  http://localhost:8080/api/v1/lxc/instances/100/resources
```

### 5. Execute Command
```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"command": "uptime"}' \
  http://localhost:8080/api/v1/lxc/instances/100/exec
```

## Python Client Example

```python
import requests

class LWSClient:
    def __init__(self, base_url, api_key):
        self.base_url = base_url
        self.headers = {'X-API-Key': api_key}

    def list_containers(self):
        url = f"{self.base_url}/api/v1/lxc/instances"
        response = requests.get(url, headers=self.headers)
        return response.json()

    def create_container(self, image_id, size='small'):
        url = f"{self.base_url}/api/v1/lxc/instances"
        data = {'image_id': image_id, 'size': size}
        response = requests.post(url, json=data, headers=self.headers)
        return response.json()

# Usage
client = LWSClient('http://localhost:8080', 'your-api-key')
containers = client.list_containers()
print(containers)
```
