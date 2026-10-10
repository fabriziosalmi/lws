---
title: Scaling containers
seo_title: "Scale Proxmox LXC containers: CPU, memory, disk, network"
description: "Change the CPU, memory, root disk and network limits of Proxmox LXC containers with LWS, and see how lxc scale-check works out its suggestions."
---

# Scaling containers

`lws lxc scale` changes the resources of existing containers by running
`pct set` and `pct resize` on the Proxmox host, so the values land in the
container's Proxmox configuration like a change made in the web interface.
You decide the values; `lxc scale-check` can only suggest them.

## CPU: three settings in Proxmox

Proxmox gives an LXC container three CPU settings, which work together:

| Setting | What it controls | When unset | Set by LWS |
|---|---|---|---|
| `cores` | How many of the host's CPUs the container can use, and the number it sees | Every CPU of the host | `lxc scale --cpucores` |
| `cpulimit` | A cap on CPU time, counted in CPUs: `1.5` is the time of one and a half CPUs | No cap (`0`) | `lxc scale --cpulimit`, and the instance size at creation |
| `cpuunits` | A relative weight, used only when containers compete for CPU | The Proxmox default | Never |

A container created with `lws lxc run --size mid` gets `cpulimit: 2` and no
`cores`: it sees every CPU of the host but receives at most the time of two.
Programs that size their worker pools from the number of CPUs they see can
start more workers than that limit serves well. Set `--cpucores` as well when
that matters:

```bash
# Two CPUs visible, and at most the time of two CPUs
lws lxc scale 100 --cpucores 2 --cpulimit 2
```

`--cpucores` takes a whole number from 1 to 8192, `--cpulimit` a decimal
from 0 to 8192, where `0` removes the cap. LWS has no option for
`cpuunits`; to give one container more weight than its neighbours, run
`pct set 100 --cpuunits 200` on the host (or through `lws px exec`).

## Memory

`--memory` sets the container's memory limit in MB (at least 16) with
`pct set --memory`, and Proxmox applies it to a running container straight
away:

```bash
lws lxc scale 100 --memory 4096
```

**Warning:** lowering the limit below what the container is using makes the
kernel reclaim memory from it, and it may kill processes in the container to
stay under the limit. Check the usage first with `lxc status` or
`lxc resources` (see [Watching live usage](#watching-live-usage)).

LWS does not change swap. Use `pct set 100 --swap 1024` on the host for that.

## Root disk

`--storage-size` grows the root disk with `pct resize 100 rootfs <size>`. Give
an absolute size (`64G`) or an amount to add (`+8G`). The units are `K`, `M`,
`G` and `T`, and a plain number is read as GiB:

```bash
lws lxc scale 100 --storage-size 64G
lws lxc scale 100 --storage-size +8G
```

Disks only grow: Proxmox refuses a size smaller than the current one, and
LWS reports its error. Proxmox also grows the filesystem, so there is nothing
to run inside the container, which can keep running. `lxc show-storage` shows
the new size from inside. Only `rootfs` is resized; for a mount point such as
`mp0`, run `pct resize 100 mp0 +10G` on the host.

## Network rate limit

`--net-limit` sets the `rate` option of `net0`, in megabytes per second (not
megabits): `12.5` is about 100 Mbit/s. `0` removes the limit.

```bash
lws lxc scale 100 --net-limit 12.5
```

`pct set` replaces the whole `net0` definition, so LWS first reads the
current one from `pct config`, replaces only its `rate`, and writes it back:
the bridge, address, MAC address and firewall flag stay as they were. Only
`net0` is limited. A container without `net0` is reported as an error.

## Why there are no disk I/O limits

Proxmox has no setting that limits the disk bandwidth of a container; its
per-disk read and write limits exist only for virtual machines. `lxc scale`
still accepts the hidden options `--disk-read-limit` and `--disk-write-limit`,
only to refuse them with that explanation instead of failing with "No such
option". If a workload needs a disk bandwidth limit, run it in a VM.

## Several containers at once

`lxc scale` takes several container IDs and applies the same values to each,
one after the other:

```bash
lws lxc scale 100 101 102 --memory 2048
```

All of them must be on the host selected with `--region` and `--az`. If one
container fails, LWS reports it and goes on with the next; the command then
exits with status 1. For each container, CPU, memory and network changes are
made in one `pct set`, then the disk is resized. If `pct set` fails, that
container's disk is not resized. Passing no option at all is an error.

## Instance sizes and existing containers

`--size` exists only on `lxc run`: the size's `memory`, `cpulimit` and
`storage` are passed to `pct create`, and that is the only time they are
used. LWS does not record which size a container was made with, and editing
`instance_sizes` in `config.yaml` does not change existing containers.

To move a container to another size, pass that size's values, which
[Instance sizes](instance-sizes.html) lists. From `mid` (2048 MB, 2 CPUs,
16 GiB) to `large` (4096 MB, 2 CPUs, 32 GiB):

```bash
lws lxc scale 100 --memory 4096 --cpulimit 2 --storage-size 32G
```

## Suggestions with lxc scale-check

```bash
lws lxc scale-check 100
```

`scale-check` is read-only. It compares what a container is **allocated**
with what the host **has**, using the `scaling` block of `config.yaml`. It
does not look at what the container is using: an idle container and a busy
one with the same allocation get the same suggestions. It works on stopped
containers too, since it reads only `pct config`.

1. It reads the host's totals: the number of CPUs from the `CPU(s):` line of
   `lscpu` (logical CPUs, so threads count), and the total memory from
   `free -m`.
2. It reads the container's allocation from `pct config`: `cores`, or
   `cpulimit` rounded up when `cores` is unset, or every host CPU when both
   are unset; `memory`; and the `size` of `rootfs` in GB.
3. For each resource, it compares the allocation with a share of a reference
   and suggests one step up or down:

| Resource | Reference | Suggest more when below | Suggest less when above | Step up | Step down |
|---|---|---|---|---|---|
| CPU | Host CPUs | `min_threshold` × CPUs | `max_threshold` × CPUs | `step` × `scale_up_multiplier` | `step` × `scale_down_multiplier` |
| Memory | Host memory (MB) | `min_threshold` × memory | `max_threshold` × memory | `step_mb` × `scale_up_multiplier` | `step_mb` × `scale_down_multiplier` |
| Disk | `limits.max_storage_gb` | `min_threshold` × max | never | `step_gb` × `scale_up_multiplier` | none |

The new value is the current one plus or minus the step, with decimals
dropped, and kept between the `limits` minimum and maximum. A smaller disk is
never suggested, because Proxmox cannot shrink a container's disk.
Thresholds are fractions (`0.30` is 30%); a value above 1 is read as a
percentage. Keys missing from `config.yaml` take the values of
`config.yaml.example`, except that the CPU and memory maximums default to the
host's own. [Configuration](configuration.html#scaling-thresholds) lists the
keys.

### A worked example

Take a host where `lscpu` reports 16 CPUs and `free -m` reports 64000 MB in
total (a 64 GiB host shows a little less than 65536), with the thresholds of
`config.yaml.example`:

- CPU: more below 16 × 0.30 = 4.8 cores, less above 16 × 0.80 = 12.8; the
  step is 1 × 1.5 = 1.5 up and 1 × 0.5 = 0.5 down, so one core either way
  once decimals are dropped.
- Memory: more below 64000 × 0.40 = 25600 MB, less above 64000 × 0.70 =
  44800 MB; 256 × 1.25 = 320 MB up, 256 × 0.75 = 192 MB down.
- Disk: more below 1024 × 0.50 = 512 GB; 10 × 1.5 = 15 GB up.

| Container | Allocation | CPU | Memory | Disk |
|---|---|---|---|---|
| 100 (`--size mid`) | `cpulimit` 2, 2048 MB, 16 GB | 2 < 4.8: 3 | 2048 < 25600: 2368 | 16 < 512: 31 |
| 101 | `cores` 8, 32768 MB, 600 GB | none | none | none |
| 102 | no CPU settings, 49152 MB, 900 GB | counted as 16 > 12.8: 15 | 49152 > 44800: 32768 | none |

What the example shows:

- The thresholds express the share of the host one container should hold.
  With the example values, nearly every small container on a large host is
  told to grow. On a host shared by many small containers, lower the
  `min_threshold` values, for example to `0.05`.
- Each run suggests one step. After you apply it, the next run suggests
  another step while the value is still below the threshold.
- One step down from 49152 MB would be 48960 MB, still above
  `max_memory_mb` (32768), so the suggestion for 102 is the maximum itself.
- Container 102's disk is above 85% of `max_storage_gb`, but no smaller size
  is suggested: Proxmox cannot shrink it.
- The output ends with the `lxc scale` command that applies the
  suggestions. Container 100 is limited by `cpulimit`, so the command changes
  `--cpulimit`; for a container with `cores` set, it changes `--cpucores`:

```bash
lws lxc scale 100 --cpulimit 3 --memory 2368 --storage-size 31G
```

## Watching live usage

These commands run tools inside the container (`top`, `free`, `df`, `ps`)
and show what it is using now:

```bash
# CPU, memory, disk and process count every 5 seconds, 12 times
lws lxc resources 100 --interval 5 --count 12

# One reading per container: load average, memory, disk and swap
lws lxc status 100 101 102

# Configuration, usage, addresses and top processes, saved as JSON
lws lxc report 100 --output json --file report-100.json
```

`lxc resources` needs a running container. It starts by printing the
container's CPU and memory settings: its `cores`, its `cpulimit`, or "all
host CPUs" when it has neither. `lxc status` counts memory as total minus
free, so the page cache counts as used. For history over days, use the
graphs on the container's Summary page in the Proxmox web interface.

## No autoscaling

LWS has no background process and never changes a container by itself. The
most you can automate is a report: run `scale-check` from cron and read the
log, then apply what you agree with using `lxc scale`. Run it from the folder
that holds `config.yaml`, which LWS reads from the current directory:

```bash
# crontab on the machine that runs LWS: every Monday at 07:00
0 7 * * 1 cd /opt/lws && for id in 100 101 102; do python3 lws.py lxc scale-check $id; done >> /var/log/lws-scale-check.log 2>&1
```

## Related pages

- [Configuration](configuration.html#scaling-thresholds) describes the
  `scaling` keys.
- [Instance sizes](instance-sizes.html) lists the sizes for `lxc run`.
- [CLI reference](cli-reference.html) lists every option of `lxc scale`.
- [API reference](api-reference.html) has the same operations over HTTP.
