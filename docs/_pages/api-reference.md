---
layout: default
title: API Reference
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

Configure your API key in `config.yaml`:

```yaml
# The server refuses to start if this is empty or one of a few recognized
# placeholders. Generate a real one:
# python3 -c 'import secrets; print(secrets.token_urlsafe(32))'
api_key: "REPLACE_ME_WITH_32_PLUS_RANDOM_CHARACTERS"
```

## Response Format

All responses are in JSON format:

### Success Response
```json
{
  "output": "command output here"
}
```
If the underlying command's stdout starts with `{` or `[` (e.g. commands run with a JSON output option), the API returns that parsed JSON directly instead of wrapping it in `"output"`.

### Error Response
```json
{
  "error": "Error description",
  "details": "Detailed error message",
  "return_code": 1
}
```

> **Known limitation affecting several endpoints below (marked ⚠️):** `run_lws_command` builds the underlying CLI call by appending every key still present in the request body as a `--key value` flag (`api.py:200-215`), even for keys the route handler already consumed to build a positional argument. When the corresponding `lws.py` command takes that value as a positional argument rather than an option — which is true for most of the endpoints marked below — the extra flag doesn't exist and the underlying CLI call fails with a Click "no such option" error. This is a bug in `api.py`, not something you can work around from the request body itself.

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

Back up the current configuration to a file. Unlike most POST handlers, this one builds `--timestamp`/`--compress` flags manually instead of forwarding the whole body, so it isn't affected by the known limitation below.

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

Run `apt-get update` on the machine running the API server — **not** on any Proxmox host. No request body needed.

```bash
curl -X POST -H "X-API-Key: your-key" \
  http://localhost:8080/api/v1/px/update
```

#### POST `/px/cluster/start` / `/px/cluster/stop` / `/px/cluster/restart`

Start, stop, or restart cluster services (`pve-cluster`, `corosync`) on a Proxmox host.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"region": "eu-south-1", "az": "az1"}' \
  http://localhost:8080/api/v1/px/cluster/start
```

#### POST `/px/backup-lxc` ⚠️

Back up a single LXC container via `vzdump` on the Proxmox host. Affected by the known limitation above: `vmid` is positional in `px backup-lxc` and gets duplicated.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"vmid": "100", "storage": "local-lvm", "mode": "snapshot"}' \
  http://localhost:8080/api/v1/px/backup-lxc
```

#### POST `/px/backup` ⚠️

Back up Proxmox host configuration (`/etc/pve`) to a local `.tar.gz`. Affected by the known limitation above: `backup_dir` is positional and gets duplicated.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"backup_dir": "/backups/px", "region": "eu-south-1", "az": "az1"}' \
  http://localhost:8080/api/v1/px/backup
```

#### POST `/px/image` ⚠️

Create a template image from an LXC container. Affected by the known limitation above: `instance_id` and `template_name` are both positional and get duplicated.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"instance_id": "100", "template_name": "my-template"}' \
  http://localhost:8080/api/v1/px/image
```

#### DELETE `/px/image/{template_name}`

Delete a template image from the Proxmox template cache. `template_name` comes from the URL, so it isn't affected by the known limitation.

```bash
curl -X DELETE -H "X-API-Key: your-key" \
  "http://localhost:8080/api/v1/px/image/my-template?region=eu-south-1&az=az1"
```

#### GET `/px/security-groups`

List all security groups and their rules in the cluster firewall.

```bash
curl -H "X-API-Key: your-key" \
  "http://localhost:8080/api/v1/px/security-groups?region=eu-south-1&az=az1"
```

#### POST `/px/security-groups` ⚠️

Create a security group. Affected by the known limitation above: `group_name` is positional and gets duplicated.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"group_name": "web", "description": "Web tier"}' \
  http://localhost:8080/api/v1/px/security-groups
```

#### DELETE `/px/security-groups/{group_name}`

Delete a security group. `group_name` comes from the URL, so it isn't affected by the known limitation.

```bash
curl -X DELETE -H "X-API-Key: your-key" \
  "http://localhost:8080/api/v1/px/security-groups/web?region=eu-south-1&az=az1"
```

#### POST `/px/security-groups/{group_name}/rules` / DELETE `.../rules`

Add or remove a firewall rule within an existing security group. `group_name` comes from the URL; the rule fields (`direction`, `action`, `protocol`, `source_ip`, `source_port`, `destination_ip`, `destination_port`) are all real options on `px security-group-rule-add`/`rule-rm`, so this pair isn't affected by the known limitation.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"direction": "IN", "protocol": "tcp", "destination_port": "443"}' \
  http://localhost:8080/api/v1/px/security-groups/web/rules
```

#### POST `/px/security-groups/attach` / `/px/security-groups/detach` ⚠️

Attach or detach a security group from a container's firewall config. Affected by the known limitation above: `group_name` and `vmid` are both positional and get duplicated.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"group_name": "web", "vmid": "100"}' \
  http://localhost:8080/api/v1/px/security-groups/attach
```

#### POST `/px/upload` ⚠️

Upload an LXC template to a Proxmox host. Affected by the known limitation above: `local_path` and `remote_template_name` are both positional and get duplicated.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"local_path": "./ubuntu-22.04.tar.gz", "remote_template_name": "ubuntu-22.04"}' \
  http://localhost:8080/api/v1/px/upload
```

#### POST `/px/exec`

Execute an arbitrary command on a Proxmox host over SSH. The handler filters the request body down to `region`/`az` before forwarding it, so — unlike most of the endpoints above — it isn't affected by the known limitation.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"command": "df -h /var/lib/vz"}' \
  http://localhost:8080/api/v1/px/exec
```

### LXC Container Endpoints

#### POST `/lxc/instances`

Create and start LXC containers.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{
    "image_id": "local:vztmpl/ubuntu-22.04.tar.gz",
    "size": "medium",
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
  "region": "string",
  "az": "string"
}
```

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

#### POST `/lxc/instances/start` ⚠️

Start containers. Affected by the known limitation above: `instance_ids` stays in the request body and gets appended a second time as `--instance-ids "['100', ...]"` — a stringified Python list, not a real flag `lxc start` accepts.

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

#### POST `/lxc/instances/stop` ⚠️

Stop containers. Affected by the same `instance_ids` duplication described above.

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

#### POST `/lxc/instances/terminate` ⚠️

Terminate (destroy) containers. Affected by the same `instance_ids` duplication described above.

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

#### POST `/lxc/instances/reboot` ⚠️

Reboot running containers. Affected by the same `instance_ids` duplication described above.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"instance_ids": ["100", "101"], "region": "eu-south-1", "az": "az1"}' \
  http://localhost:8080/api/v1/lxc/instances/reboot
```

#### POST `/lxc/instances/status` ⚠️

A one-shot resource snapshot (load average, memory, disk, swap) for one or more containers. Affected by the same `instance_ids` duplication described above.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"instance_ids": ["100", "101"], "region": "eu-south-1", "az": "az1"}' \
  http://localhost:8080/api/v1/lxc/instances/status
```

#### POST `/lxc/instances/scale` ⚠️

Scale container resources. Affected by the same `instance_ids` duplication described above (the `memory`/`cpulimit`/`storage_size` options themselves are unaffected — they're real options, not positional).

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

#### POST `/lxc/instances/clone` ⚠️

Clone an LXC container. Affected by the known limitation above: `source_instance_id` and `target_instance_id` are both positional in `lxc clone` and get duplicated.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"source_instance_id": "100", "target_instance_id": "200", "full": true}' \
  http://localhost:8080/api/v1/lxc/instances/clone
```

#### POST `/lxc/instances/{instance_id}/exec`

Execute command in container.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{
    "command": "apt update && apt upgrade -y",
    "region": "eu-south-1",
    "az": "az1"
  }' \
  http://localhost:8080/api/v1/lxc/instances/100/exec
```

#### POST `/lxc/instances/{instance_id}/snapshots` ⚠️

Create a snapshot. Affected by the known limitation above: `snapshot_name` is a positional argument in `lxc snapshot-add`, so it gets sent twice (once correctly, once as a nonexistent `--snapshot-name` flag) and the call fails.

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

#### POST `/lxc/instances/{instance_id}/volumes/attach` ⚠️

Attach a storage volume. Affected by the known limitation above: `volume_name` and `volume_size` are both positional in `lxc volume-attach` and get duplicated.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"volume_name": "local-lvm", "volume_size": "16G", "mount_point": "/mnt/data"}' \
  http://localhost:8080/api/v1/lxc/instances/100/volumes/attach
```

#### POST `/lxc/instances/{instance_id}/volumes/detach` ⚠️

Detach a storage volume — this always removes the container's `mp0` mount, regardless of `volume_name`. Affected by the known limitation above: `volume_name` is positional and gets duplicated.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"volume_name": "local-lvm"}' \
  http://localhost:8080/api/v1/lxc/instances/100/volumes/detach
```

#### POST `/lxc/instances/{instance_id}/service` ⚠️

Run a `systemctl` action against a service inside a container. Affected by the known limitation above: `action` and `service_name` are both positional in `lxc service` and get duplicated.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"action": "restart", "service_name": "nginx"}' \
  http://localhost:8080/api/v1/lxc/instances/100/service
```

#### POST `/lxc/instances/{instance_id}/migrate`

Migrate a container to another Proxmox host. `target_host` is a real option (not positional), so this one isn't affected by the known limitation.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"target_host": "proxmox2.example.com"}' \
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

#### GET `/lxc/instances/{instance_id}/net-check` ⚠️

Check whether a TCP/UDP port is open on a container. Affected by the known limitation above: `protocol` and `port` are both positional in `lxc net` and get duplicated as query params turned back into flags.

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
  "http://localhost:8080/api/v1/lxc/instances/100/health-check?fix=true"
```

#### POST `/lxc/instances/{instance_id}/restore`

Restore a container from a backup file. `backup_file` is a real option (not positional), so this one isn't affected by the known limitation.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"backup_file": "/var/lib/vz/dump/vzdump-lxc-100.tar.gz"}' \
  http://localhost:8080/api/v1/lxc/instances/100/restore
```

#### POST `/lxc/instances/{instance_id}/backup`

Create a backup of a container. All fields (`destination`, `download`, `compress_level`) are real options, so this one isn't affected by the known limitation. An empty body is fine — it uses `lxc backup-create`'s defaults.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"download": true}' \
  http://localhost:8080/api/v1/lxc/instances/100/backup
```

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

#### POST `/lxc/instances/{instance_id}/app/setup` ⚠️

Install Docker in a container. Affected by the known limitation above: `package_name` is positional in `app setup` and gets duplicated.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{
    "package_name": "docker",
    "region": "eu-south-1",
    "az": "az1"
  }' \
  http://localhost:8080/api/v1/lxc/instances/100/app/setup
```

#### POST `/lxc/instances/{instance_id}/app/run`

Run Docker container.

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

#### POST `/lxc/instances/{instance_id}/app/deploy` ⚠️

Deploy Docker Compose app. Affected by the known limitation above (`action` is positional and gets duplicated) **and** a second, separate issue: the request body's `compose_file`/`auto_start` get turned into `--compose-file`/`--auto-start` (hyphens), while the actual CLI command only accepts `--compose_file`/`--auto_start` (underscores). Either issue alone breaks the call.

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

#### POST `/lxc/instances/{instance_id}/app/update` ⚠️

Update a Compose app by re-deploying a new Compose file. **This endpoint cannot currently work**: `compose_file` is a required positional argument on `app update`, but the handler never adds it to the command at all — it only ever ends up as a `--compose_file`/`--compose-file` flag, which doesn't exist as an option on this command either. The call fails regardless of what you send.

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
  "http://localhost:8080/api/v1/lxc/instances/100/app/logs/nginx?follow=false&lines=100"
```

#### GET `/lxc/instances/{instance_id}/app/containers`

List Docker containers running inside an LXC container.

```bash
curl -H "X-API-Key: your-key" \
  http://localhost:8080/api/v1/lxc/instances/100/app/containers
```

#### POST `/lxc/instances/app/remove` ⚠️

Uninstall Docker and Compose from one or more containers. **This endpoint always returns a 500**: the view function is declared as `app_remove(instance_ids)`, but its route has no `<instance_ids>` path segment, so Flask calls it with no arguments and Python raises `TypeError: app_remove() missing 1 required positional argument`. This is unrelated to the request body shown below — no request would succeed against this endpoint as currently written.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"instance_ids": ["100", "101"]}' \
  http://localhost:8080/api/v1/lxc/instances/app/remove
```

### Security Endpoints

#### GET `/sec/discovery`

Discover reachable hosts. Called with no query parameters, this works fine (`sec discovery`'s `lxc_id` argument is optional). ⚠️ Called *with* `?lxc_id=...` as shown below, it hits the known limitation above — `lxc_id` is positional and gets duplicated as a nonexistent `--lxc-id` flag, so the call fails.

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

Configure allowed origins in `config.yaml`:

```yaml
api:
  allowed_origins:
    - "http://localhost:8080"
    - "https://yourdomain.com"
```

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
    "image_id": "local:vztmpl/ubuntu-22.04.tar.gz",
    "size": "medium",
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

    def create_container(self, image_id, size='medium'):
        url = f"{self.base_url}/api/v1/lxc/instances"
        data = {'image_id': image_id, 'size': size}
        response = requests.post(url, json=data, headers=self.headers)
        return response.json()

# Usage
client = LWSClient('http://localhost:8080', 'your-api-key')
containers = client.list_containers()
print(containers)
```

---

[← CLI Reference](cli-reference.html) | [Next: Configuration →](configuration.html)
