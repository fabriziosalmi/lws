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
api_key: "your-secure-api-key-here"
```

## Response Format

All responses are in JSON format:

### Success Response
```json
{
  "output": "command output here"
}
```

### Error Response
```json
{
  "error": "Error description",
  "details": "Detailed error message",
  "return_code": 1
}
```

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

#### POST `/lxc/instances/start`

Start containers.

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

Stop containers.

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

Terminate (destroy) containers.

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

#### POST `/lxc/instances/scale`

Scale container resources.

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

#### POST `/lxc/instances/{instance_id}/snapshots`

Create a snapshot.

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

#### GET `/lxc/instances/{instance_id}/resources`

Monitor container resources.

```bash
curl -H "X-API-Key: your-key" \
  http://localhost:8080/api/v1/lxc/instances/100/resources
```

### Docker/App Endpoints

#### POST `/lxc/instances/{instance_id}/app/setup`

Install Docker in a container.

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

#### POST `/lxc/instances/{instance_id}/app/deploy`

Deploy Docker Compose app.

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

#### GET `/lxc/instances/{instance_id}/app/logs/{container_name}`

Get Docker logs.

```bash
curl -H "X-API-Key: your-key" \
  "http://localhost:8080/api/v1/lxc/instances/100/app/logs/nginx?follow=false&lines=100"
```

### Security Endpoints

#### GET `/sec/discovery`

Discover reachable hosts.

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
