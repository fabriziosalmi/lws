---
title: Troubleshooting
seo_title: "Troubleshooting LWS: SSH, configuration and API errors"
description: "Causes and fixes for the errors LWS users hit most often: missing config.yaml, sshpass, SSH timeouts and host keys, rejected options and API startup refusals."
---

# Troubleshooting

The messages below are the ones LWS prints, quoted as they appear. Search this
page for the text of your error.

## Configuration

### `Configuration error: Configuration file not found at ...`

The CLI reads `config.yaml` from the directory you run it in, not from the
directory that holds `lws.py`. Run it from the folder with your `config.yaml`,
or create one there:

```bash
cd /path/to/lws
cp config.yaml.example config.yaml
```

When the file cannot be loaded, LWS continues with an empty configuration, so
the error is followed by others: no regions are known, and `--size` accepts no
value at all.

### `Invalid value for '--size': 'medium' is not one of ...`

`--size` accepts the names under `instance_sizes` in your `config.yaml`, and
the list in the message is exactly that. `config.yaml.example` has no `medium`;
the nearest is `mid`. See [Instance sizes](instance-sizes.html).

### `An unexpected error occurred: 'az1'`

A quoted name after "unexpected error" is usually a region or availability
zone that is not in `config.yaml`. Every command defaults to
`--region eu-south-1 --az az1`; if your configuration uses other names, pass
both options:

```bash
lws lxc show --region eu-central-1 --az pve-rhine
```

### `Missing 'ssh_password' for availability zone ...`

Each availability zone needs `host`, `user` and `ssh_password`. See
[Several Proxmox hosts](multiple-hosts.html).

## SSH

### `sshpass command not found. Please install it with 'apt install sshpass' or equivalent.`

LWS logs in to Proxmox hosts with a password through `sshpass`. Install it on
the machine that runs LWS: `apt install sshpass` on Debian and Ubuntu,
`dnf install sshpass` on Fedora.

### `Error: SSH command timed out after 3600 seconds`

LWS stops a remote command that is still running after
`ssh_command_timeout` seconds (3600 by default, see
[Configuration](configuration.html#general-settings)). The limit is there to
catch a command that hangs; backups, package installs and migrations normally
finish well within it.

A command that timed out is not run again: it may have changed something on
the host before it was stopped. Check the state of the host or container
before you retry it by hand.

If your operations legitimately take longer, raise the limit, or set it to
`0` to remove it:

```yaml
ssh_command_timeout: 7200
```

Only a connection that fails before the command starts (`Connection refused`
or `Connection timed out` from SSH itself) is retried, up to twice.

### `Host key verification failed`

LWS accepts a host's SSH key the first time it connects and refuses a
different key afterwards (`StrictHostKeyChecking=accept-new`). A reinstalled
Proxmox host has a new key. If you know why the key changed, remove the old
one and connect again:

```bash
ssh-keygen -R pve1.example.net
```

If you do not know why it changed, do not remove it: something may be
answering in place of your host.

### `Permission denied, please try again.`

The `user` and `ssh_password` of that zone are wrong, or the host does not
allow password logins for that user. LWS needs password authentication;
key-only hosts are not supported.

## Commands

### `No such option: -d` or a help page instead of the result

Words after the command that start with `-` are read as LWS options. Put `--`
before them:

```bash
lws app run 100 -- -d -p 80:80 nginx
lws px exec -- df -h /var/lib/vz
```

`lws lxc exec` takes the command as one quoted string instead:

```bash
lws lxc exec 100 "df -h /"
```

The string is split into words the way a shell would split it, and the
command runs in the container without a shell. To use `&&`, `|`, `>` or
variables, pass a shell explicitly:

```bash
lws lxc exec 100 "sh -c 'apt-get update && apt-get -y upgrade'"
```

### `invalid instance id: ...` and other `invalid ...` messages

LWS checks values that end up in commands on the host: instance IDs are
digits only, names are letters, digits, `-` and `_`, IP addresses must parse.
The message names the value it rejected.

## REST API

### `api_key is not set in config.yaml. Refusing to start`

The API needs a key, because it can run any LWS command, and those run as
root on your hosts. Generate one and write it into `config.yaml`:

```bash
KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
sed -i "s|^api_key:.*|api_key: \"$KEY\"|" config.yaml   # on macOS: sed -i ''
```

The message `api_key is still the placeholder shipped in this repository` means
the key is one of the example values from the repository, which are public.

### `Unauthorized: Invalid or missing API key.`

Every endpoint except `/api/v1/health`, the Swagger documentation and the web
UI page itself needs the key in the `X-API-Key` header:

```bash
curl -H "X-API-Key: $LWS_API_KEY" http://127.0.0.1:8080/api/v1/lxc/instances
```

### The API starts, but commands report a configuration error

`api.py` reads the `config.yaml` next to `api.py`, while the `lws.py` commands
it starts read `config.yaml` from the current directory. Start the API from
the folder that contains both:

```bash
cd /path/to/lws && python3 api.py
```

### `Command execution timed out after 3600 seconds.`

The API stops an `lws` command that runs longer than `api.command_timeout`
seconds (3600 by default). The remote step it started on the host may still be
running; check the host or container before sending the request again, and
raise `api.command_timeout` if your operations need longer.

## Logs

The CLI writes errors to `lws.log` and `lws.json.log` in the current
directory. The API writes to `api.log` in its current directory and to its
standard output; `api.log_level` in `config.yaml` sets how much it writes.
