---
title: LWS compared
seo_title: "LWS vs pct, the Proxmox API, Ansible and Terraform"
description: "When LWS fits and when another tool is the better choice for managing LXC containers on Proxmox VE: pct, the Proxmox API, Ansible or Terraform."
---

# LWS compared with other Proxmox tools

LWS is one of several ways to manage LXC containers on Proxmox VE. This page
describes what each tool is built for, so you can pick the one that fits.

## In short

LWS suits a small number of Proxmox hosts that you already reach over SSH, when
you want short commands for everyday container work: create a container from a
named size, take a snapshot, run a command in it, install Docker in it. It does
not manage virtual machines, keeps no state, and logs in as a user with a
password.

If you need virtual machines, fine-grained permissions, a record of the desired
state, or many hosts, one of the other tools below is a better fit, and they
can be used side by side with LWS.

## How the tools compare

| | LWS | `pct` | Proxmox VE API | Ansible | Terraform / OpenTofu |
|---|---|---|---|---|---|
| Runs on | Your machine, or the Proxmox host | The Proxmox host | Anywhere with HTTPS access to port 8006 | Your machine | Your machine |
| Reaches Proxmox through | SSH, then `pct` and shell commands on the host | Local | HTTPS REST API | The Proxmox API (Proxmox modules) and SSH (inside guests) | The Proxmox API |
| Authentication | SSH user and password from `config.yaml` | Local root | API tokens or users, with roles and ACLs | API tokens or users | API tokens or users |
| LXC containers | Yes | Yes, every option | Yes | Yes | Yes (provider dependent) |
| Virtual machines (QEMU) | No | No (`qm` does that) | Yes | Yes | Yes |
| Several hosts | Yes, grouped as regions and availability zones in `config.yaml` | One host per call | One API call per node or cluster | Yes, through the inventory | Yes |
| Desired state and drift detection | No, commands run once | No | No | Idempotent tasks | Yes, with a state file and `plan` |
| Docker inside containers | `lws app` commands | No | No | Yes, with Docker modules | No |
| REST API of its own | Yes, `api.py` | No | It is the API | No | No |

## When LWS is a good fit

- You manage a handful of Proxmox hosts and want one command line for all of
  them, with the host chosen by `--region` and `--az`.
- You want containers created from named sizes (`small`, `lws-web`, ...) rather
  than repeating memory, CPU and disk values. See [Instance sizes](instance-sizes.html).
- You want quick operations without writing playbooks or modules first:
  `lws lxc exec`, `lws lxc snapshot-add`, `lws lxc show`.
- You want a small HTTP API with a key, in front of those same commands.

## When another tool is a better fit

- **Virtual machines.** LWS only manages LXC containers. Use the Proxmox API,
  Ansible or Terraform.
- **Least-privilege access.** LWS logs in over SSH as the user in `config.yaml`,
  usually `root`, so whoever can run LWS has root on the hosts. The Proxmox API
  can give a token only the permissions it needs.
- **SSH keys only.** LWS currently supports password authentication through
  `sshpass`; key-based authentication is not implemented.
- **Declared infrastructure.** If you want the configuration of every
  container kept in files and compared against reality, use Terraform or
  OpenTofu, or Ansible.
- **Every container option.** `pct` on the host exposes every option of
  Proxmox containers. LWS covers the common ones; anything else can be run
  through `lws px exec`.
- **Long-running operations over SSH.** Each remote command LWS runs over SSH
  stops after 60 seconds and is retried up to twice (`lws_core/ssh.py`). Slow
  operations, such as large backups or package installs, are better run on the
  host. With `use_local_only: true` in `config.yaml` and LWS installed on the
  Proxmox host, most commands run locally, without that limit.

## Using LWS next to other tools

LWS does not keep its own record of containers: every command reads the
current state from the host. Containers created with `pct`, the web interface,
Ansible or Terraform show up in `lws lxc show` like any other, and the reverse
is also true. Be careful with Terraform: a change LWS makes to a container
that Terraform manages (memory, disk) is reported as drift on the next `plan`.
