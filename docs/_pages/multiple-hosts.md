---
title: Several Proxmox hosts
seo_title: "Manage several Proxmox VE hosts with regions and zones"
description: "Configure several Proxmox VE hosts in LWS as regions and availability zones, pick one per command with --region and --az, and check which hosts are reachable."
---

# Managing several Proxmox hosts

LWS keeps a list of Proxmox VE hosts in `config.yaml` and runs each command
against one of them. Hosts are grouped in two levels, named after cloud
providers: a **region** holds one or more **availability zones**, and each
availability zone is one Proxmox host.

The names carry no meaning for Proxmox. A region can be a site, a rack or a
customer; an availability zone is simply the name you give a host.

## Describing the hosts

Each availability zone needs exactly three keys:

```yaml
regions:
  eu-south-1:
    availability_zones:
      az1:
        host: pve1.example.net     # hostname or IP address
        user: root
        ssh_password: "a-long-password"
      az2:
        host: 10.10.0.12
        user: root
        ssh_password: "another-password"

  lab:
    availability_zones:
      pve-lab:
        host: pve-lab.local
        user: root
        ssh_password: "lab-password"
```

- `host`, `user` and `ssh_password` are required. LWS refuses to load a
  configuration where one is missing and names the zone that lacks it.
- Other keys under a zone are ignored. In particular there is no `port` key:
  LWS connects to the SSH port that `ssh` would use for that host.
- Quote passwords. An unquoted password made only of digits is read by YAML as
  a number, and the SSH call fails.
- LWS logs in with the password through `sshpass`, so `sshpass` must be
  installed on the machine that runs LWS. Key-based authentication is not
  supported.

The file holds root passwords. Keep it out of version control (the
repository's `.gitignore` already excludes it) and readable only by you:
`chmod 600 config.yaml`. LWS reads `config.yaml` from the directory you run it
in.

## Choosing the host for a command

Every command that acts on a host takes `--region` and `--az`, with the
aliases `--location` and `--node`:

```bash
# These two are the same command
lws lxc show --region eu-south-1 --az az2
lws lxc show --location eu-south-1 --node az2

# Start container 105 on the lab host
lws lxc start 105 --region lab --az pve-lab
```

The defaults are `--region eu-south-1` and `--az az1`, which match the
example configuration. If your configuration uses other names, pass both
options every time: with a region that has no zone called `az1`, leaving out
`--az` makes the command fail.

## Checking which hosts are reachable

`lws px list` checks every configured host in parallel and prints one line
per host:

```bash
lws px list
lws px list --region eu-south-1
```

| Marker | Meaning |
|---|---|
| Green | The SSH port (22) accepts connections. |
| Yellow | The host answers ping, but port 22 does not accept connections. |
| Red | The name does not resolve, or the host does not answer. |

`px list` only tests reachability: it does not log in. `lws px status` logs in
to one host and shows its load, disk and swap.

## Container IDs across hosts

When `lws lxc run` creates a container, it asks the target host for its
existing containers (`pct list`) and uses the highest ID plus one. If the host
has no containers yet, it starts from `start_vmid` (10000 in the example
configuration).

LWS only looks at the target host. Two separate hosts can therefore end up
with the same container ID, which matters if you later join them into a
cluster. Inside a Proxmox cluster, IDs must be unique across all nodes, but
`pct list` on one node does not show the containers of the others: if LWS
picks an ID that another node already uses, Proxmox refuses to create the
container and the command fails. Pick the ID ranges per node with care, or
create the container on the node that holds the highest IDs.

## Running LWS on the Proxmox host itself

With `use_local_only: true`, LWS runs most commands directly on the machine it
runs on instead of over SSH. Use this when LWS is installed on a Proxmox host
and manages only that host: there is no SSH connection and no 60-second limit
per remote command.

Some commands always connect over SSH even in this mode, among them
`px status`, `px exec`, `px backup-lxc`, `lxc migrate` and the security group
commands. They still need the host's entry in `regions`.

## Moving containers between hosts

`lws lxc migrate` moves a container to another node of the same Proxmox
cluster, using Proxmox's own migration:

```bash
lws lxc migrate 105 --target-host pve2 --region eu-south-1 --az az1
```

`--target-host` is the Proxmox node name as the cluster knows it
(`lws px clusters` shows the cluster members), not a zone from `config.yaml`.
Hosts that are not in the same cluster cannot be targets.

The command runs `pct migrate` on the source host without `--restart`, and
Proxmox does not move a running container without it, so stop the container
first. The migration runs over SSH, which LWS stops after 60 seconds: for a
container whose disk takes longer than that to copy, run `pct migrate` on the
host or use the Proxmox web interface.
