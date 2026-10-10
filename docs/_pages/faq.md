---
title: FAQ
seo_title: "LWS FAQ: Proxmox LXC management from the command line"
description: "Short answers about LWS: what it manages, what it needs on your machine and on Proxmox VE, how it connects, and what it does not do."
---

# Frequently asked questions

## What is LWS?

A command-line tool, `lws.py`, for managing LXC containers and some host tasks
on one or more Proxmox VE hosts. A REST API, `api.py`, runs the same commands
over HTTP, with a minimal web UI. It is open source under the MIT License.

## Does LWS manage virtual machines?

No. It manages LXC containers only; nothing in it calls `qm`, the Proxmox tool
for QEMU virtual machines. See [LWS compared](comparison.html) for tools that
manage both.

## How does LWS talk to Proxmox?

Over SSH. It logs in to the host with the user and password in `config.yaml`
and runs Proxmox's command-line tools there, mostly `pct`, plus `vzdump` and
ordinary shell commands. It does not use the Proxmox HTTP API on port 8006.

## Does anything have to be installed on the Proxmox host?

No agent or service. The container and host commands use the tools a Proxmox
VE host already has. The machine that runs LWS needs Python 3.10 or later, the
packages in `requirements.txt` and `sshpass`.

## Can LWS use SSH keys instead of passwords?

Not at the moment. Authentication goes through `sshpass` with the password in
`config.yaml`, so treat that file as a credentials file: keep it out of
version control and readable only by you.

## Which user does LWS log in as?

The `user` of each host in `config.yaml`, `root` in the example. The commands
it runs, such as `pct create`, need root on the host.

## How do I install it?

LWS runs from a checkout of the repository; it is not published on PyPI:

```bash
git clone https://github.com/fabriziosalmi/lws.git
cd lws && pip install -r requirements.txt
cp config.yaml.example config.yaml
python3 lws.py --help
```

[Getting Started](getting-started.html) covers the configuration.

## Can I run LWS on the Proxmox host itself?

Yes. Set `use_local_only: true` and most commands run directly on that host
instead of over SSH. A few commands connect over SSH in every case, so the
host still needs its entry under `regions`.

## Does LWS scale containers automatically?

No. Nothing in LWS runs in the background. `lws lxc scale-check` prints
suggested changes when you run it, and `lws lxc scale` applies the changes you
pass to it.

## What is a region, and what is an availability zone?

Names for grouping hosts, borrowed from cloud providers. An availability zone
is one Proxmox host; a region is a group of them. They exist only in LWS's
configuration. See [Several Proxmox hosts](multiple-hosts.html).

## What do sizes such as `small` or `lws-web` mean?

Presets of memory, CPU limit and root disk for new containers, defined in
`config.yaml`. See [Instance sizes](instance-sizes.html).

## Is it safe to expose the REST API on the internet?

No. The API key gives control over every configured host as root, and the API
has no TLS and no rate limiting of its own. By default it listens on
`127.0.0.1`. To reach it from elsewhere, keep it on a private network or VPN,
or put it behind a reverse proxy that adds TLS and its own authentication.

## Why does a long operation fail after a minute?

Each remote command run over SSH is stopped after 60 seconds and retried up to
twice. See [Troubleshooting](troubleshooting.html#error-ssh-command-timed-out-after-60-seconds).

## Where do I report a bug?

In the [GitHub issues](https://github.com/fabriziosalmi/lws/issues). Include
the command, the output and your Proxmox VE version, and remove passwords and
API keys from anything you paste.
