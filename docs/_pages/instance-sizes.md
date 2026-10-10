---
title: Instance sizes
seo_title: "LXC instance sizes: memory, CPU and disk presets in LWS"
description: "The named sizes in config.yaml.example that lws lxc run --size accepts, with the memory, CPU limit and root disk each one gives a container."
---

# Instance sizes

`lws lxc run --size <name>` creates a container with the memory, CPU limit and
root disk of a named size. Sizes are defined under `instance_sizes` in
`config.yaml`; this page lists the ones that ship in `config.yaml.example`.
Edit, remove or add sizes in your own `config.yaml`: `--size` accepts exactly
the names defined there, and `small` is the default.

## What each value sets

Each size has three keys, passed to `pct create` when the container is made:

| Key | Passed as | Meaning |
|---|---|---|
| `memory` | `--memory` | RAM in MB. |
| `cpulimit` | `--cpulimit` | CPU time limit, in CPUs. `2` means at most the time of two CPUs. LWS does not pass `--cores`, so the container still sees every CPU of the host. |
| `storage` | `--rootfs` | `storage:size`: the Proxmox storage and the root disk size in GiB. `local-lvm:8` is an 8 GiB disk on the `local-lvm` storage. |

The `t2-*`, `m5-*`, `c5-*`, `r5-*`, `x1e-*`, `i3-*` and `p3-*` names borrow
the shape of cloud instance families. They only set the three values above:
nothing about the CPU type, disk type or GPUs is configured.

## Choosing and overriding a size

```bash
# 2 GB of RAM, a 2-CPU limit, a 16 GiB disk
lws lxc run --size mid --image-id local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst

# Change the resources of an existing container later
lws lxc scale 100 --memory 4096 --cpulimit 2
```

`lxc run --storage-size` replaces the disk of the chosen size with
`<default_storage>:<value>`, where `default_storage` comes from `config.yaml`.
Proxmox reads that value as a size in GiB, so give a plain number:
`--storage-size 24` for a 24 GiB disk.

`lxc scale --memory` and `--cpulimit` change a running container's limits
with `pct set`; they do not change its size name, which LWS does not record.

To add a size, add an entry under `instance_sizes` with the same three keys:

```yaml
instance_sizes:
  ci-runner:
    memory: 6144
    cpulimit: 4
    storage: local-lvm:40
```

## Sizes in config.yaml.example

The tables below are checked against `config.yaml.example` by the test suite,
so they list exactly what the example file defines.

### Generic sizes

| Size | Memory | CPU limit | Root disk |
|---|---|---|---|
| `micro` | 512 MB | 1 | `local-lvm:4` |
| `small` | 1024 MB | 1 | `local-lvm:8` |
| `mid` | 2048 MB | 2 | `local-lvm:16` |
| `large` | 4096 MB | 2 | `local-lvm:32` |
| `x-large` | 8192 MB | 4 | `local-lvm:64` |
| `xx-large` | 16384 MB | 8 | `local-lvm:128` |

### Application sizes

| Size | Memory | CPU limit | Root disk | Example in config.yaml.example |
|---|---|---|---|---|
| `lws-minio` | 4096 MB | 2 | `local-lvm:50` | MinIO for object storage |
| `lws-postgres` | 4096 MB | 2 | `local-lvm:40` | PostgreSQL for relational database |
| `lws-mysql` | 4096 MB | 2 | `local-lvm:40` | MySQL for relational database |
| `lws-nosql` | 8192 MB | 4 | `local-lvm:50` | MongoDB for NoSQL database |
| `lws-cdn` | 1024 MB | 1 | `local-lvm:10` | Caddy for reverse proxy and CDN |
| `lws-metrics-monitoring` | 2048 MB | 1 | `local-lvm:20` | Prometheus for metrics and monitoring |
| `lws-metrics-visualization` | 2048 MB | 1 | `local-lvm:20` | Grafana for data visualization |
| `lws-mq` | 2048 MB | 1 | `local-lvm:20` | Apache ActiveMQ for messaging queues |
| `lws-firewall` | 4096 MB | 2 | `local-lvm:20` | An nftables firewall and router |
| `lws-search-analytics` | 8192 MB | 4 | `local-lvm:50` | OpenSearch for search and analytics |
| `lws-serverless` | 2048 MB | 2 | `local-lvm:20` | OpenFaaS for serverless functions |
| `lws-email` | 4096 MB | 2 | `local-lvm:40` | Mailcow for email management |
| `lws-machine-learning` | 8192 MB | 4 | `local-lvm:50` | Hugging Face Transformers for machine learning models |
| `lws-identity-management` | 8192 MB | 4 | `local-lvm:50` | Keycloak for identity and access management |
| `lws-file-storage` | 4096 MB | 2 | `local-lvm:50` | Nextcloud for file storage and collaboration |
| `lws-data-warehouse` | 16384 MB | 4 | `local-lvm:100` | ClickHouse for data warehousing |
| `lws-messaging-broker` | 4096 MB | 2 | `local-lvm:40` | RabbitMQ for messaging broker |
| `lws-code-server` | 2048 MB | 2 | `local-lvm:20` | Coder or code-server for online development environment |
| `lws-log-aggregation` | 8192 MB | 4 | `local-lvm:50` | Loki for log aggregation |
| `lws-container-registry` | 4096 MB | 2 | `local-lvm:50` | Harbor for container registry |
| `lws-web` | 2048 MB | 2 | `local-lvm:20` | Nginx for web server |
| `lws-load-balancer` | 2048 MB | 2 | `local-lvm:20` | HAProxy for load balancing |
| `lws-redis` | 2048 MB | 1 | `local-lvm:10` | Redis for in-memory caching |
| `lws-vpn` | 2048 MB | 1 | `local-lvm:10` | OpenVPN for VPN server |
| `lws-backup-system` | 4096 MB | 2 | `local-lvm:50` | Restic or Bacula for backup solutions |
| `lws-static-site-generator` | 2048 MB | 1 | `local-lvm:10` | Hugo for static site generation |
| `lws-dns` | 1024 MB | 1 | `local-lvm:10` | PowerDNS for DNS management |

### General purpose (`t2-*`, `m5-*`)

| Size | Memory | CPU limit | Root disk |
|---|---|---|---|
| `t2-pico` | 512 MB | 1 | `local-lvm:8` |
| `t2-micro` | 1024 MB | 1 | `local-lvm:8` |
| `t2-small` | 2048 MB | 1 | `local-lvm:20` |
| `t2-medium` | 4096 MB | 2 | `local-lvm:40` |
| `m5-large` | 8192 MB | 2 | `local-lvm:50` |
| `m5-xlarge` | 16384 MB | 4 | `local-lvm:100` |
| `m5-2xlarge` | 32768 MB | 8 | `local-lvm:200` |

### More CPU (`c5-*`)

| Size | Memory | CPU limit | Root disk |
|---|---|---|---|
| `c5-large` | 4096 MB | 2 | `local-lvm:50` |
| `c5-xlarge` | 8192 MB | 4 | `local-lvm:100` |
| `c5-2xlarge` | 16384 MB | 8 | `local-lvm:200` |
| `c5-4xlarge` | 32768 MB | 16 | `local-lvm:400` |

### More memory (`r5-*`, `x1e-*`)

| Size | Memory | CPU limit | Root disk |
|---|---|---|---|
| `r5-large` | 16384 MB | 2 | `local-lvm:100` |
| `r5-xlarge` | 32768 MB | 4 | `local-lvm:200` |
| `r5-2xlarge` | 65536 MB | 8 | `local-lvm:400` |
| `x1e-xlarge` | 65536 MB | 4 | `local-lvm:200` |
| `x1e-2xlarge` | 131072 MB | 8 | `local-lvm:400` |
| `x1e-4xlarge` | 262144 MB | 16 | `local-lvm:800` |

### More disk (`i3-*`)

| Size | Memory | CPU limit | Root disk |
|---|---|---|---|
| `i3-large` | 15360 MB | 2 | `local-lvm:500` |
| `i3-xlarge` | 30720 MB | 4 | `local-lvm:1000` |
| `i3-2xlarge` | 61440 MB | 8 | `local-lvm:2000` |
| `i3-4xlarge` | 122880 MB | 16 | `local-lvm:4000` |

### `p3-*` sizes

| Size | Memory | CPU limit | Root disk |
|---|---|---|---|
| `p3-large` | 15360 MB | 2 | `local-lvm:100` |
| `p3-xlarge` | 30720 MB | 4 | `local-lvm:200` |
| `p3-2xlarge` | 61440 MB | 8 | `local-lvm:400` |
| `p3-8xlarge` | 245760 MB | 32 | `local-lvm:1600` |


The examples in the application table come from comments in
`config.yaml.example`. They are starting points, not tested requirements.
Containers share the Linux kernel of the host, so FreeBSD-based software such
as OPNsense or pfSense needs a virtual machine instead.
