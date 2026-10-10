---
title: Security model
seo_title: "LWS security model: root SSH, API key and trust boundaries"
description: "What LWS can do on your Proxmox VE hosts, the trust boundaries around config.yaml, SSH and the REST API, and what LWS leaves to you."
---

# Security model

LWS logs in to Proxmox VE hosts as root and runs commands there. This page
describes what that gives access to, where the trust boundaries are, how LWS
protects values and secrets on the way, and what it leaves to you.

## What LWS can do

For each availability zone under `regions` in `config.yaml`, LWS opens an SSH
connection as the zone's `user`, normally `root`, with the zone's
`ssh_password` passed to `sshpass`. On the host it runs `pct` for containers,
`pvesh` for firewall security groups, `vzdump` for backups and `apt-get` for
host updates, and `px exec` runs any command you give it. Inside containers,
commands run through `pct exec` as the container's root. With
`use_local_only: true`, most of these commands run on the local machine
instead, which then has to be the Proxmox host itself.

The consequence is simple: whoever can run LWS with your `config.yaml`, or
call the REST API with its key, has root on every host in that file. The
[security policy](https://github.com/fabriziosalmi/lws/blob/main/SECURITY.md)
treats this as by design.

## Trust boundaries

### The machine that runs LWS

Root on this machine, and the account that runs LWS, can read `config.yaml`
and act as LWS. Use a machine that only administrators can log in to, keep it
patched, and run LWS under its own account.

### `config.yaml`

The file holds the SSH password of every host and the API key in plain text.
LWS does not encrypt it and does not read secrets from environment variables.
Keep it mode `0600`, owned by the account that runs LWS, and out of version
control (the repository's `.gitignore` excludes it):

```bash
chmod 600 config.yaml
lws conf backup /backup/lws-config.yaml --timestamp
```

`lws conf backup` writes its copy with mode `0600`, also when it replaces an
existing file. The copy is still in clear text, and `--compress` only
compresses it. `lws conf show` prints the file with values of keys containing
`password`, `secret` or `key` masked.

### The network path to the hosts

SSH encrypts the connection, including the password. LWS calls `ssh` with
`StrictHostKeyChecking=accept-new`: the first time it connects to a host, it
accepts the host's key and stores it in `~/.ssh/known_hosts` of the account
that runs LWS; afterwards, a different key for that host is refused with
`Host key verification failed`, and the command does not run.

That first connection is trust on first use. Make it over a network you
trust, then compare the stored fingerprint (`ssh-keygen -lF <host>` as the
LWS account) with the one shown on the host's console
(`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`). `known_hosts` belongs to
an account: the CLI run as you and the API run as a service account trust
separately, and a container keeps it only on a volume.

A changed key usually means the host was reinstalled. If you cannot explain
it, do not remove the old key: something else may be answering in place of
your host. [Troubleshooting](troubleshooting.html#host-key-verification-failed)
shows how to replace a key you know has changed.

### The REST API

- The API key is equivalent to root on every configured host. It also lets
  a client write a copy of `config.yaml` to any path the API's account can
  write (`POST /api/v1/conf/backup`), and send any file that account can read
  to a host (`POST /api/v1/px/upload`).
- The API refuses to start without a key or with an example value from the
  repository, and warns when the key is shorter than 32 characters. It
  compares keys in constant time (`hmac.compare_digest`).
- It listens on `127.0.0.1` by default. It has no TLS of its own: across a
  network, the key travels in clear text unless a TLS proxy is in front.
- Browsers on other origins are refused unless `api.allowed_origins` lists
  them (CORS). This does not affect `curl` or scripts.
- Error responses do not include exception details; those go to `api.log`.

[Running the API in production](api-in-production.html) covers the proxy,
the service account and the checklist.

## How LWS keeps values out of shells

OpenSSH joins every argument after `user@host` into one string, which the
host's shell parses again. An argument list that is safe for a local
`subprocess` call is therefore not safe over SSH:
`pct exec 100 -- ls && reboot` would run `reboot` on the host. LWS uses two
layers against this.

- **Allow-list validation.** Values that end up in host commands are checked
  first: container IDs are digits only; names of security
  groups and storages use letters, digits, `-` and `_`; template names,
  host names, service names, paths, ports and protocols have their own
  patterns; IP addresses and CIDRs must parse. A rejected value stops the
  command with an `invalid ...` message before anything runs.
- **Quoting.** `run_argv` sends the remote copy of each command through
  `shlex.join`, so the host's shell sees exactly the intended arguments.
  `lxc run` quotes its free-text values (host name, password, DNS, `net0`)
  with `shlex.quote` in the same way.

Two commands run arbitrary commands on purpose:

- `px exec` hands the command to the host's shell as written, so pipes, `&&`
  and redirections work. It is root command execution on the host.
- `lxc exec` splits the command into words and runs it in the container
  without a shell; `&&` or `|` arrive as plain arguments. Call a shell
  explicitly for a pipeline:

```bash
lws lxc exec 100 "sh -c 'apt-get update && apt-get -y upgrade'"
```

The REST API starts `lws.py` without a shell, one argument per value, and
refuses requests whose command words (IDs, names, the command of the exec
endpoints) contain any of `` ; & | ` $ ( ) { } ``. It also rejects
non-numeric instance IDs in URLs. This keeps shell syntax out of commands; it
is not a sandbox, since `/api/v1/px/exec` still runs any command on the host.

## Secrets in process lists and logs

- The SSH password reaches `sshpass` through the `SSHPASS` environment
  variable (`sshpass -e`), not `-p`, so it does not appear in the command
  lines that `ps` shows to other users. The environment of a process is
  readable by its own account and root only.
- LWS does not write the SSH password to its logs.
- `lxc run --password` does not pass the container's root password to
  `pct create`. Once the container runs, LWS sets it with `chpasswd` inside
  the container, which reads it from standard input, so it appears neither
  in the Proxmox host's process list nor in LWS's logs. It is still an
  argument of `lws` itself, so it stays in the shell history and the process
  list of the machine you typed it on. Leave it out when you do not need it.
- The API logs each command before running it, with the values of options
  whose name contains `password`, `secret`, `token` or `key` replaced by
  `***`. The text of `exec` commands is logged as sent, and at
  `api.log_level: DEBUG` the API also logs the output of every command.
- The CLI writes errors to `lws.log` and `lws.json.log` in the current
  directory. They can include the error output of failed host commands.

## Containers: privileged and unprivileged

`lxc run` creates a privileged container unless you pass `--unprivileged`.
In a privileged container, the container's root is user ID 0 on the host
kernel, so an escape from the container is root on the host. An unprivileged
container maps its root to an unprivileged user ID range on the host.
Prefer unprivileged containers:

```bash
lws lxc run --image-id local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst --unprivileged
```

Docker inside a container needs the LXC feature `nesting=1`, plus
`keyctl=1` in an unprivileged container. `lws app setup 100 --enable-nesting`
sets them and restarts the container. Nesting exposes more of the host's
`/proc` and `/sys` to the container and weakens its isolation, much more so
in a privileged one. For workloads you do not trust, a virtual machine is the
stronger boundary; LWS does not manage virtual machines. See
[Docker in LXC](docker-in-lxc.html).

## What LWS does not do

- **SSH keys.** LWS logs in with passwords only, so each host must accept
  password logins for the configured user.
- **Roles or per-user access.** One `config.yaml`, and one API key, give
  full access to every host listed. There is no read-only key.
- **Proxmox permissions.** LWS does not use Proxmox users, roles or API
  tokens. It acts as the SSH user, so Proxmox's permission system does not
  limit what it does.
- **Audit log.** Besides the log files above, nothing records who did what.
  `api.log` has the commands and the client address (the proxy's, behind a
  proxy), not a user name.
- **Encryption at rest.** `config.yaml` and its backups are plain text.
- **TLS and rate limiting** in the API. A reverse proxy provides both.

## Recommendations

- Run LWS on a dedicated management machine or VM, under its own account.
- Firewall the hosts' SSH port so that it accepts connections only from that
  machine and your administration network. Do not expose it to the internet.
  If root password logins are only needed for LWS, limit them to its
  address with a `Match Address` block in the hosts' `sshd_config`.
- Give every host a long, unique root password, and change it when someone
  who knew it leaves.
- Keep the API on loopback, behind a proxy with TLS and its own
  authentication.
- Create containers with `--unprivileged`, and enable nesting only where
  Docker runs.
- If you need limited access, such as read-only monitoring or a team
  restricted to some resources, use Proxmox API tokens with roles directly,
  not LWS.
- To separate teams, give each its own `config.yaml` listing only its hosts,
  run by its own account and, for the API, its own instance and key. Root on
  one node of a Proxmox cluster controls the whole cluster, so separate by
  cluster, not by node.
- Keep LWS up to date: only the latest release receives security fixes.

## Reporting a vulnerability

Do not open a public issue. Follow the
[security policy](https://github.com/fabriziosalmi/lws/blob/main/SECURITY.md):
on GitHub, open the repository's **Security** tab and choose
**Report a vulnerability**, which creates a private advisory. The policy
lists what to include and what is in scope; issues that need the API key or
`config.yaml` are out of scope, since both grant root by design.

## Related pages

- [Running the API in production](api-in-production.html)
- [Configuration](configuration.html)
- [Several Proxmox hosts](multiple-hosts.html)
- [Firewall security groups](firewall-security-groups.html)
- [Troubleshooting](troubleshooting.html)
