---
title: Configuration
seo_title: "Configuration: config.yaml for Proxmox hosts and sizes"
description: "Reference for config.yaml: Proxmox hosts grouped into regions and availability zones, instance sizes, scaling thresholds, the API key and storage."
---

# Configuration

LWS reads a single YAML file, `config.yaml`. Start from the example in the
repository and edit it:

```bash
cp config.yaml.example config.yaml
chmod 600 config.yaml   # it holds root passwords
```

## Where the file is read from

- **The CLI** (`lws.py`) reads `config.yaml` from the current directory. Run
  it from the folder that holds the file.
- **The REST API** (`api.py`) reads the `config.yaml` next to `api.py`. The
  CLI commands it starts read the one in the current directory, so start the
  API from that same folder.

`lws conf validate` checks the file, and `lws conf show` prints it with
passwords and keys masked.

## A minimal configuration

```yaml
use_local_only: false
start_vmid: 10000
default_storage: local-lvm
default_network: vmbr0

api_key: ""   # only needed for the REST API; see below

regions:
  eu-south-1:
    availability_zones:
      az1:
        host: pve1.example.net
        user: root
        ssh_password: "a-long-password"

instance_sizes:
  small:
    memory: 1024
    cpulimit: 1
    storage: local-lvm:8
```

`regions` and `instance_sizes` are required; LWS refuses to load a file
without them. The other sections are optional.

## General settings

| Key | Default | Used for |
|---|---|---|
| `use_local_only` | `false` | `true` runs most commands on the machine LWS runs on, instead of over SSH. Use it when LWS is installed on the Proxmox host it manages. Some commands, such as `px status`, `px exec`, `px reboot`, `px backup-lxc` and the `px cluster-*` commands, connect over SSH in every case. Keep the key in the file: most commands expect it. |
| `start_vmid` | `10000` | The ID of the first container `lxc run` creates on a host that has none. On a host with containers, the next ID is the highest existing one plus one. |
| `default_storage` | none | The storage for `--storage-size` in `lxc run`. Required if you use that option. `lxc scale --storage-size` grows the disk where it already is. |
| `default_network` | `vmbr0` | The bridge in the default `--net0` of `lxc run`: `name=eth0,bridge=<default_network>`. |
| `default_onboot` | `true` | The default of `lxc run --onboot`. |
| `ssh_command_timeout` | `3600` | Seconds one remote command may run over SSH before LWS stops it. `0` removes the limit. A command that times out is not run again. |

Older configuration files may contain a `minimum_resources` block. No command
reads it.

## Hosts: regions and availability zones

```yaml
regions:
  <region>:
    availability_zones:
      <zone>:
        host: <hostname or IP>
        user: <SSH user>
        ssh_password: <password>
```

Each zone is one Proxmox host, and all three keys are required. Commands pick
a host with `--region` and `--az`, which default to `eu-south-1` and `az1`.
[Several Proxmox hosts](multiple-hosts.html) covers this in detail.

LWS authenticates with the password through `sshpass`. It does not support
SSH keys, and it reads `ssh_password` as a literal value: there is no
environment variable substitution. If you keep secrets in a vault, generate
`config.yaml` from it before running LWS.

## Instance sizes

```yaml
instance_sizes:
  <name>:
    memory: <MB>              # passed to pct create --memory
    cpulimit: <CPUs>          # passed to pct create --cpulimit (a CPU time limit)
    storage: <storage>:<GiB>  # passed to pct create --rootfs
```

`lxc run --size` accepts exactly the names defined here, with `small` as the
default. [Instance sizes](instance-sizes.html) lists the sizes in
`config.yaml.example` and explains each value.

## REST API

```yaml
api_key: ""
api:
  host: "127.0.0.1"
  port: 8080
  debug: false
  log_level: "INFO"
  command_timeout: 3600
  allowed_origins: []
```

| Key | Default | Meaning |
|---|---|---|
| `api_key` | none | The key clients send in the `X-API-Key` header. The API refuses to start when it is empty or one of the example values from the repository, and warns when it is shorter than 32 characters. |
| `api.host` | `127.0.0.1` | The address the API listens on. Anything other than loopback exposes root access to every host in `regions` to that network. |
| `api.port` | `8080` | The port. |
| `api.debug` | `false` | `true` runs Flask's development server instead of waitress. The interactive debugger stays off either way. |
| `api.log_level` | `INFO` | How much the API writes to `api.log`. |
| `api.command_timeout` | `3600` | Seconds the API waits for one `lws` command before it stops the command and answers with an error. |
| `api.allowed_origins` | none | Origins allowed to call the API from a browser (CORS). Without the key, browsers on other origins are refused. Scripts and `curl` are not affected by CORS. |

Generate a key and write it into the file:

```bash
KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
sed -i "s|^api_key:.*|api_key: \"$KEY\"|" config.yaml   # on macOS: sed -i ''
```

The web UI is served by the API itself, at `/`, so it needs no entry in
`allowed_origins`. Opening `ui.html` from disk does not work: it calls the
API at a relative address. Configuration files from earlier versions may list
`"null"`, the origin browsers give to pages opened from a file or sandboxed;
remove it.

## Scaling thresholds

`lxc scale-check` reads the `scaling` section to suggest new CPU, memory and
disk values for a container. Nothing runs automatically: the command prints
suggestions, and `lxc scale` applies the values you give it.

```yaml
scaling:
  lxc_cpu:
    min_threshold: 0.30        # suggest more if below this share of the host
    max_threshold: 0.80        # suggest less if above this share of the host
    step: 1
    scale_up_multiplier: 1.5
    scale_down_multiplier: 0.5
  lxc_memory:
    min_threshold: 0.40
    max_threshold: 0.70
    step_mb: 256
    scale_up_multiplier: 1.25
    scale_down_multiplier: 0.75
  lxc_storage:
    min_threshold: 0.50
    max_threshold: 0.85
    step_gb: 10
    scale_up_multiplier: 1.5
    scale_down_multiplier: 0.5
  limits:
    min_cpu_cores: 1
    max_cpu_cores: 16
    min_memory_mb: 512
    max_memory_mb: 32768
    min_storage_gb: 10
    max_storage_gb: 1024
```

How the suggestion is worked out, for CPU (memory follows the same pattern
with its own keys, and disk too, except that it is only ever increased):

- The container's allocation is compared with the host's total: cores from
  `lscpu`, memory from `free -m`. For disk, the comparison is with
  `max_storage_gb`. A container without a `cores` setting counts as its
  `cpulimit` rounded up, or as every host core when it has neither.
- Below `min_threshold` × total, it suggests the current value plus
  `step` × `scale_up_multiplier`.
- Above `max_threshold` × total, it suggests the current value minus
  `step` × `scale_down_multiplier`. Proxmox cannot shrink a container's
  disk, so no smaller disk is ever suggested.
- The result is rounded down to a whole number and kept between the
  `limits` minimum and maximum.

Thresholds are fractions between 0 and 1: `0.30` means 30%. A value above 1
is read as a percentage, so `80` means `0.80`. The comparison uses what the
container is allocated in `pct config`, not what it is using at the moment;
for live usage, see `lxc resources` and `lxc status`.

Configuration files written for 1.4.3 or earlier may also contain `host_cpu`,
`host_memory`, `host_storage` and `general` blocks under `scaling`. They are
ignored, except `host_storage.total_storage_gb`, which is used as
`max_storage_gb` when `limits` does not set it.

## Network discovery

```yaml
security:
  discovery:
    discovery_methods: ['ping']
    max_parallel_workers: 10
```

Used by `lws sec discovery`, which pings the /24 networks around the client,
the Proxmox host and optionally a container. `ping` is the only method;
`max_parallel_workers` is the number of pings in flight. Older files may also
have `proxmox_timeout` and `lxc_timeout` keys; they are not read.

## Storage values

The `storage` of a size, and `default_storage`, name a storage defined on the
Proxmox host (Datacenter > Storage in the web interface):

```yaml
storage: local-lvm:20      # LVM-thin, the default on most installs
storage: local-zfs:20      # ZFS
storage: ceph-pool:20      # a Ceph RBD storage, if the cluster has one
```

The storage must allow container root disks. The number after the colon is
the size in GiB.

## Backing up the configuration

```bash
lws conf backup /backup/lws-config.yaml --timestamp
lws conf backup /backup/lws-config.yaml --timestamp --compress
```

The copy contains the passwords and the API key in clear text: store it with
the same care as `config.yaml`.

## Upgrading

- **To 1.4.2 or later:** the REST API no longer starts with an empty
  `api_key` or one of the example values, and `config.yaml.example` binds it
  to `127.0.0.1`. Set a random key, and set `api.host` explicitly if the API
  must listen on another address. The CLI is not affected.
- **To 1.4.3 or later:** without `api.allowed_origins`, browsers on other
  origins can no longer call the API; before, every origin was allowed. List
  the origins that need access.
- Configuration files from earlier versions otherwise load unchanged. See
  [Release notes](release-notes.html).
