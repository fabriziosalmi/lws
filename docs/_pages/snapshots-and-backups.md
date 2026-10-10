---
title: Snapshots and backups
seo_title: "Proxmox LXC snapshots, vzdump backups and restores with LWS"
description: "Snapshots and vzdump backups of Proxmox LXC containers with LWS: backup modes, compression, restoring in place or as a copy, schedules and retention."
---

# Snapshots and backups

LWS drives two Proxmox mechanisms for LXC containers: storage snapshots
(`pct snapshot`) and vzdump backups (`vzdump`, restored with `pct restore`).
They protect against different failures, and most containers need both.

## Snapshots or backups

| | Snapshot | Backup |
|---|---|---|
| What it is | The container's disks and configuration at one moment, on the same storage | An archive of the container's files and configuration, on a backup storage |
| Takes | Seconds | Minutes or more, depending on the data |
| Protects against | A failed upgrade or a configuration mistake | A failed disk or host, a deleted container |
| Lost when | The container is destroyed or its storage fails | The storage holding the archive fails |
| Brings back | The container, in place | The container, in place or under a new ID, on any host that can read the archive |

A snapshot is not a backup: `lws lxc terminate` deletes it with the
container. A backup on the host's system disk shares that disk's fate, so
keep copies on another machine.

## Snapshots

Proxmox can snapshot a container only when all its volumes are on LVM-thin
(`local-lvm` on a default installation), ZFS (`local-zfs`), Ceph RBD or BTRFS
(a technology preview). Directory, NFS and CIFS storages and plain LVM
cannot: there, snapshots come from the qcow2 format, which only virtual
machine disks use; container disks are raw images.

```bash
lws lxc snapshot-add 100 before-upgrade-$(date +%Y%m%d)
lws lxc snapshots 100
lws lxc snapshot-rm 100 before-upgrade-20261010
```

These run `pct snapshot`, `pct listsnapshot` and `pct delsnapshot` on the
host. Proxmox accepts names of up to 40 letters, digits, `-` and `_` that
start with a letter. LWS has no rollback command: run `pct rollback` through
`lws px exec`, with the container stopped. A rollback discards every change
made since the snapshot; on ZFS, Proxmox rolls back only to the most recent
snapshot, so delete newer ones first.

```bash
lws lxc stop 100
lws px exec pct rollback 100 before-upgrade-20261010
lws lxc start 100
```

A snapshot holds on to every block changed since it was taken, in the same
pool as the container. Delete the ones you no longer need and watch the
pool's usage: in a full LVM-thin pool, writes fail for every guest on it.

## Backups with `lxc backup-create`

```bash
lws lxc backup-create 100 --storage backups
lws lxc backup-create 100 --compress gzip --download
```

LWS runs `vzdump` on the host and prints the path of the archive, named like
`vzdump-lxc-100-2026_10_10-02_00_00.tar.zst`.

- `--destination` (default `/var/lib/vz/dump`) is a directory on the host,
  passed to vzdump as `--dumpdir`; LWS creates it if needed. On a standard
  installation the default is the backup directory of the `local` storage,
  so its archives also have volume IDs such as `local:backup/vzdump-...`.
- `--storage` names a Proxmox storage that accepts backups, such as an NFS
  share or a Proxmox Backup Server, and replaces `--destination`.

Prefer `--storage` for backups you keep: the storage can be on another
machine, its backups show in the web interface, and its retention rules
apply. On a Proxmox Backup Server vzdump reports no file name, so LWS only
confirms the backup and points you to `pvesm list`.

`lws px backup-lxc 100 --storage backups` is an older command: it runs
`vzdump 100 --storage backups --mode snapshot` over SSH, even with
`use_local_only`. It takes `--mode` but not `--compress`, so the format comes
from `/etc/vzdump.conf` (uncompressed if that file sets none), and it does
not print the archive name. Prefer `lxc backup-create`.

### Modes

| `--mode` | What vzdump does | Downtime |
|---|---|---|
| `snapshot` (default) | Pauses the container for a moment, takes a temporary storage snapshot, archives it, deletes it | None noticeable |
| `suspend` | Copies the files with rsync to a temporary directory, suspends the container, copies what changed, resumes it | Short; needs space for a full copy |
| `stop` | Shuts the container down, archives it, starts it again | The whole backup |

`snapshot` needs every backed-up volume on storage with snapshot support;
otherwise vzdump logs `mode failure` and falls back to `suspend`. `stop`
gives the most consistent archive. The other two capture a running system in
the state a power cut would leave it, so databases recover as after a crash:
dump a database first, or use `stop`.

### Compression and download

`--compress` sets the format: `zstd` (default, `.tar.zst`) is fast and
compresses well, `gzip` (`.tar.gz`) is slower and readable everywhere, `lzo`
(`.tar.lzo`) is fast with larger files, and `none` writes a plain `.tar`.
`pct restore` reads all four. The hidden `--compress-level` of older
versions is ignored with a warning.

`--download` copies the archive with scp into the current directory; it also
stays on the host. It needs a file name, so it fails on a Proxmox Backup
Server. With `use_local_only: true` the archive is already local.

### What a backup contains

The archive holds the container's configuration and its root disk, which
includes Docker's data in `/var/lib/docker`. Volume mount points are included
only with the `backup=1` option, bind mounts never. `lws lxc volume-attach`
creates `mp0` without it; copy the `mp0:` line from `lws lxc show 100` and
add the option:

```bash
lws px exec -- pct set 100 --mp0 local-lvm:vm-100-disk-1,mp=/mnt/data,size=8G,backup=1
```

## Restoring a backup

`lxc backup-restore` runs `pct restore`. `--backup-file` is a path on the
host, a volume ID such as `local:backup/vzdump-lxc-...` (for the storage
`backups`, `lws px exec pvesm list backups` lists them), or a file on your
machine. LWS uploads a local file to `/var/tmp` on the host and deletes that
copy afterwards; a path that exists on your machine is always taken as local.
LWS never deletes the backup itself. The disks go to `--storage`, or to
`default_storage` from `config.yaml` when you leave it out; with neither,
LWS stops, because `pct restore` would use the storage named `local`, which
cannot hold container disks on a default installation.

```bash
lws lxc stop 100
lws lxc backup-restore 100 --backup-file local:backup/vzdump-lxc-100-2026_10_10-02_00_00.tar.zst --storage local-lvm
```

If container 100 exists, LWS asks before it replaces it. On yes, it stops
the container if it runs (with `pct stop`, which kills its processes; hence
the clean `lxc stop` first), restores with `pct restore --force 1`, and
starts it. The current disks are destroyed and the configuration becomes the
one in the backup. `--no-start` leaves the container stopped. LWS also asks
before it restores under a new ID; `--force` skips the question.

### Restoring as a new container

An unused ID gives you a copy and leaves the original alone. The copy has the
original's hostname, network configuration and MAC address, so restore it
stopped and replace `net0` first; a `net0` without `hwaddr` gets a new MAC.
To restore on another host, pass its `--region` and `--az`; the archive must
then be on your machine or on storage that host can read.

```bash
lws lxc backup-restore 205 --backup-file local:backup/vzdump-lxc-100-2026_10_10-02_00_00.tar.zst --storage local-lvm --no-start
lws px exec -- pct set 205 --net0 name=eth0,bridge=vmbr0,ip=dhcp
lws lxc start 205
```

## Scheduling backups

For routine backups, a Proxmox backup job is usually the better choice.
Create it under Datacenter > Backup in the web interface, with the
containers, a schedule, the storage, mode and compression. It runs on the
Proxmox nodes, without the LWS machine, SSH or `ssh_command_timeout`; its
runs appear in the task log, and it can send notifications.

Retention rules (`keep-last`, `keep-daily`, `keep-weekly`, `keep-monthly`
and others) delete old archives. Set them on the storage ("Backup Retention"
in its dialog under Datacenter > Storage, `prune-backups` in
`/etc/pve/storage.cfg`) or on a job. The storage's rules also apply to
`lxc backup-create --storage`:

```bash
lws px exec -- pvesm set backups --prune-backups keep-daily=7,keep-weekly=4,keep-monthly=6
```

To drive the schedule from LWS instead, use cron on its machine. Run
`python3 lws.py` (your virtual environment's `python3`, if any) from the
directory with `config.yaml`; the `lws` alias does not exist in cron:

```bash
# crontab -e: back up container 100 every night at 02:30
30 2 * * * cd /opt/lws && python3 lws.py lxc backup-create 100 --storage backups >> /opt/lws/backup.log 2>&1
```

The command exits non-zero when the backup fails. LWS stops a backup still
running after `ssh_command_timeout` seconds (3600 by default); raise it for
large containers ([Configuration](configuration.html#general-settings)).

## Backing up LWS and the hosts

```bash
lws conf backup /backup/lws-config.yaml --timestamp --compress
lws px backup /root
scp root@pve1.example.net:/root/proxmox-backup.tar.gz ./pve1-etc-pve.tar.gz
```

`conf backup` writes `/backup/lws-config_20261010020000.yaml.gz` here: a
copy of `config.yaml`, comments included. It holds the SSH passwords and the
API key in clear text, so LWS creates it with mode `0600`. Run it from the
directory with `config.yaml`; anywhere else it fails without writing
anything.

`px backup` archives `/etc/pve` of one host as `proxmox-backup.tar.gz` in the
given directory **on the host**, creating the directory if needed and
replacing the previous file. Copy the file off the host. `/etc/pve` holds
guest configurations, storage definitions, users, firewall rules, backup
jobs and private keys; it does not include `/etc/network/interfaces`. Run it
once per host, with its `--region` and `--az`.

## A restore drill

A backup you have never restored is a guess. Restore one into a spare ID
regularly, check it, and delete the copy:

```bash
lws px exec pvesm list backups
lws lxc backup-restore 900 --backup-file backups:backup/vzdump-lxc-100-2026_10_10-02_00_00.tar.zst --storage local-lvm --no-start --force
lws px exec -- pct set 900 --net0 name=eth0,bridge=vmbr0,ip=dhcp
lws lxc start 900
lws app list 900
lws lxc terminate 900
```

Check that the services start and the data is as recent as you expect, and
note how long the restore took: a real one takes as long.

**Warning:** `lxc terminate` destroys the container without asking. Check the
ID before you run it.

## Related pages

- [CLI reference](cli-reference.html): every option of these commands
- [Docker in LXC](docker-in-lxc.html)
- [Several Proxmox hosts](multiple-hosts.html)
- [Troubleshooting](troubleshooting.html)
