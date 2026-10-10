---
title: Firewall security groups
seo_title: "Proxmox firewall security groups for LXC containers"
description: "Create Proxmox VE firewall security groups with LWS, add rules, attach them to LXC containers and check which rules the firewall applies."
---

# Firewall security groups

A security group is a named set of firewall rules that you define once and
attach to as many containers as you need. LWS creates security groups in the
Proxmox VE firewall, edits their rules and attaches them to LXC containers.
It has no firewall of its own: Proxmox stores the rules and applies them.

## How the Proxmox firewall is layered

The Proxmox VE firewall has three levels. Each has its own rules and its own
on/off switch:

| Level | In the web interface | What it covers | What LWS does there |
|---|---|---|---|
| Datacenter (cluster) | Datacenter > Firewall | Security groups, aliases and IP sets, and rules for all hosts | Creates and deletes security groups and their rules. Reads the on/off switch, never changes it. |
| Node | Node > Firewall | Traffic to the Proxmox host itself | Nothing |
| Guest | Container > Firewall | Traffic to and from one container or VM | Adds and removes group references. Turns the container's firewall on with `--enable-firewall`. |

For a rule to reach a container, three switches must be on:

1. The datacenter firewall (Datacenter > Firewall > Options).
2. The container's firewall (the container's Firewall > Options).
3. The `firewall=1` flag on the container's network interface (`net0`,
   `net1`, ...). An interface without it is not filtered.

LWS turns on the last two for you when you ask. It never turns on the first.

## The datacenter switch

While the datacenter firewall is off, Proxmox applies no rule at any level:
groups, rules and container settings are stored but have no effect.
`security-group-attach` warns when the switch is off and leaves it alone,
because enabling it also filters traffic to the Proxmox hosts themselves.

**Warning:** once the datacenter firewall is on, traffic to the hosts that no
rule allows is dropped. Proxmox keeps some management access open by
default, such as SSH and the web interface on port 8006 from the hosts' local
network, but if you reach the hosts from elsewhere (a VPN, a public address)
you can lock yourself out. LWS also needs SSH to every host. Before you
enable it, read the default rules in the Proxmox firewall documentation, add
rules for SSH and port 8006 from the networks you use, and make sure you have
console access to the hosts.

When you are ready, enable it under Datacenter > Firewall > Options, or on a
host:

```bash
pvesh get /cluster/firewall/options
pvesh set /cluster/firewall/options --enable 1
```

## Security groups in Proxmox

A security group is a list of rules defined at cluster level, under
`/cluster/firewall/groups` in the Proxmox API. A group does nothing on its
own. A container uses it through a rule of type `group` in its own rule list,
shown as `GROUP web` in its firewall configuration. Several containers can
reference the same group, and a change to the group's rules applies to all of
them.

## Creating a group and its rules

`px security-group-add` creates an empty group, `px security-group-rule-add`
adds a rule to it and `px security-groups` lists all groups with their rules.
The [worked example](#worked-example-a-web-group) below uses all three.

LWS accepts group names made of letters, digits, `-` and `_`. Proxmox checks
names again and LWS prints its error if it refuses one; short names that start
with a letter, such as `web` or `db-internal`, are safe. The description may
contain letters, digits, spaces and `. _ , : / -`.

`security-group-rule-add` and `security-group-rule-rm` take the same options:

| Option | Default | Proxmox field | Values |
|---|---|---|---|
| `--direction` | required | `type` | `IN` or `OUT` (any case) |
| `--action` | `ACCEPT` | `action` | `ACCEPT`, `DROP` or `REJECT` |
| `--protocol` | `tcp` | `proto` | A protocol name or number, e.g. `tcp`, `udp`, `icmp` |
| `--source-ip` | none (any) | `source` | One IPv4 or IPv6 address or CIDR |
| `--source-port` | none (any) | `sport` | One port (`22`) or range (`8000:8080`) |
| `--destination-ip` | none (any) | `dest` | One IPv4 or IPv6 address or CIDR |
| `--destination-port` | none (any) | `dport` | One port or range |

`DROP` discards a packet silently; `REJECT` answers that the port is closed.
Every rule LWS adds is enabled. Each rule takes one port or range, so ports 80
and 443 need two rules. LWS has no options for comments, macros, logging,
aliases, IP sets or a rule's position; use the web interface for those.

Proxmox checks rules from top to bottom and the first match decides; a group
reference takes one place in a container's list, and the group's rules are
checked in their order at that place. A new rule goes to the top of the group
(position 0), so the rule you add last is checked first. This matters when
you mix `ACCEPT` and `DROP`: `lws px security-groups` shows each position.

## Attaching a group to a container

```bash
lws px security-group-attach web 100 --enable-firewall
```

`security-group-attach` checks that the group exists, then adds an enabled
`group` rule to the container's firewall rules. If the container already
references the group, LWS enables the reference instead of adding a second
one, so running the command twice is harmless. Run it against the host that
runs the container (`--region`, `--az`): LWS addresses the container on that
host's node.

With `--enable-firewall`, LWS also sets `enable=1` in the container's
firewall options and adds `firewall=1` to every network interface (`net0`,
`net1`, ...) that lacks it, with `pct set`, keeping its other settings.
Changing the interface of a running container can interrupt its network for
a moment. Without `--enable-firewall`, the command only warns when the
container's firewall is off.

**Note:** once a container's firewall is on, Proxmox drops incoming traffic
that no rule accepts: the default input policy of a guest is `DROP`. Attaching
a group that only allows port 443 therefore blocks everything else coming in,
including SSH and ping. Outgoing traffic is accepted by default, and replies
to connections the container opens itself are let back in. Check the
container's Firewall > Options (`policy_in`, `policy_out`, and `dhcp` if it
gets its address over DHCP) after the first attach.

## Worked example: a web group

Two web servers, containers 100 and 101, should accept HTTP and HTTPS from
anywhere and SSH only from an admin network, 203.0.113.0/24. Create the group
and its rules first, then attach it, so the containers are never firewalled
without their rules:

```bash
lws px security-group-add web --description "Web servers"
lws px security-group-rule-add web --direction IN --protocol tcp --destination-port 80
lws px security-group-rule-add web --direction IN --protocol tcp --destination-port 443
lws px security-group-rule-add web --direction IN --protocol tcp --destination-port 22 --source-ip 203.0.113.0/24
lws px security-groups
```

`px security-groups` shows the group with its rules, newest first:

```text
[group web] - Web servers
    0: IN ACCEPT -p tcp --source 203.0.113.0/24 --dport 22
    1: IN ACCEPT -p tcp --dport 443
    2: IN ACCEPT -p tcp --dport 80
```

Attach it to both containers and turn their firewalls on:

```bash
lws px security-group-attach web 100 --enable-firewall
lws px security-group-attach web 101 --enable-firewall
```

If the datacenter firewall is still off, both commands end with the warning
described above, and nothing is filtered yet. To let the containers answer
ping as well, add a rule to the group with `--direction IN --protocol icmp`
and no port.

## Removing rules, detaching and deleting groups

`security-group-rule-rm` removes the rules whose direction, action, protocol,
addresses and ports are exactly the ones you give. The defaults count
(`ACCEPT`, `tcp`), and an option you leave out must be absent from the rule:

```bash
# Removes the SSH rule from the example
lws px security-group-rule-rm web --direction IN --destination-port 22 --source-ip 203.0.113.0/24

# Matches nothing: the rule has a source address, this command has none
lws px security-group-rule-rm web --direction IN --destination-port 22
```

All identical rules are removed together. The command fails when no rule
matches. Rules made in the web interface with a macro (such as `SSH`) have no
protocol, so `rule-rm` cannot match them; remove those in the web interface.

`security-group-detach` removes every reference to the group from the
container's rules:

```bash
lws px security-group-detach web 101
```

**Note:** detaching does not turn the container's firewall off. If the group
was the only thing letting traffic in, the container now accepts nothing from
outside. Attach another group, or turn the firewall off in the container's
Firewall > Options.

`security-group-rm` deletes a group. It refuses a group that still has rules
unless you pass `--force`, which deletes the rules first:

```bash
lws px security-group-rm web --force
```

LWS does not check whether containers still reference the group. Detach it
from every container before you delete it.

## Checking the result

In the Proxmox web interface, Datacenter > Firewall > Security Group lists
the groups and their rules, the container's Firewall panel lists its rules
(including `group web`), and its Firewall > Options shows whether the
firewall is on and the input and output policies.

On the host, with `pvesh`, where `pve1` is the node name (the host's short
hostname, which is also what LWS uses):

```bash
pvesh get /cluster/firewall/groups/web
pvesh get /nodes/pve1/lxc/100/firewall/rules
pvesh get /nodes/pve1/lxc/100/firewall/options
pct config 100
```

The rules list should contain an entry with `type` `group`, `action` `web`
and `enable` `1`, and each `net` line of `pct config` should contain
`firewall=1`. From the machine that runs LWS, prefix a command with
`lws px exec --`, for example
`lws px exec -- pvesh get /nodes/pve1/lxc/100/firewall/rules`.

## Where the changes are stored

Every change goes through `pvesh`, the command-line client of the Proxmox VE
API, run on the host you select. The API validates each rule and writes the
firewall configuration under `/etc/pve/firewall/`, which Proxmox shares
between all nodes of a cluster. A change to a group therefore applies to the
whole cluster, whichever node you run the command on, and every change
survives reboots.

Each separate Proxmox installation that is not in a cluster has its own
security groups. With several such hosts, create the group on each one, using
`--region` and `--az` to pick the host.

## Related pages

- [CLI reference](cli-reference.html) lists every option of the security
  group commands.
- [API reference](api-reference.html) has the same operations over HTTP.
- [Several Proxmox hosts](multiple-hosts.html) explains `--region` and `--az`.
- [Security model](security-model.html) covers the security of LWS itself.
