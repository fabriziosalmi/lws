---
title: Docker in LXC
seo_title: "Run Docker in Proxmox LXC containers with LWS"
description: "Install Docker and Compose in a Proxmox LXC container with LWS, set the nesting and keyctl features, then deploy, update and auto-start Compose apps."
---

# Docker in LXC containers

The `lws app` commands install Docker in a Debian or Ubuntu LXC container and
run single containers or Compose applications in it. LWS does all of it with
`pct exec` on the Proxmox host: nothing is installed on the host, and the
container does not need SSH.

## A container or a virtual machine

Proxmox recommends running Docker in a QEMU virtual machine. A VM is isolated
from the host's kernel and can be live-migrated; a container shares the
host's kernel and moves to another node only with a restart. Docker does run
in containers, which need less memory and start faster, provided they have
the LXC feature `nesting`, plus `keyctl` when unprivileged. Updates to the
host's kernel, LXC or AppArmor, or to Docker, have broken this setup before:
try host upgrades on a container that is not critical first. LWS manages
containers only; in a VM, install Docker with your usual tools.

## Privileged or unprivileged

`lws lxc run` creates a privileged container unless you pass
`--unprivileged`, because that is the default of `pct create`.

- In an **unprivileged** container, root inside is mapped to an unprivileged
  user on the host. Proxmox recommends this type. Docker needs `nesting=1`
  and `keyctl=1`.
- In a **privileged** container, root inside is root on the host, held back
  by AppArmor and seccomp. Proxmox advises it for trusted environments only.
  Docker needs `nesting=1`, which Proxmox notes exposes host procfs and sysfs
  content to the container.

Decide when you create the container: `pct set` cannot switch an existing
container between the two types.

## Creating a container for Docker

```bash
lws lxc run --size lws-web --unprivileged --features nesting=1,keyctl=1 \
  --hostname web --dhcp \
  --image-id local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst
```

LWS prints the ID it picked (`Instance 100 created successfully.`) and starts
the container, named `web-100`: LWS appends the ID to the hostname. This page
uses container 100. `lws-web` gives 2 GB of memory, a 2-CPU limit and a
20 GiB root disk ([Instance sizes](instance-sizes.html)); Docker keeps its
images and volumes on that disk, so size it for them.

## Enabling the features on an existing container

`app setup` checks the features first. When one is missing, it warns
(`Container 100 lacks the LXC feature(s) nesting, ...`) and installs Docker
anyway. `--enable-nesting` adds the missing features to those already set
(`pct set --features`) and restarts the container with `pct reboot`, which
interrupts what runs in it, before installing:

```bash
lws app setup 100 --enable-nesting
```

## Installing Docker

```bash
lws app setup 100
```

The container must be running. `app setup` installs from the distribution's
own apt repositories, not Docker's: `docker.io`, then `docker-compose-v2`
(Compose v2, on Ubuntu) or, where that package does not exist,
`docker-compose` (Debian; in Debian 12 it is the older Compose v1, 1.29).
The other `app` commands use `docker compose` when it works and
`docker-compose` otherwise, so either is fine. When Docker and Compose are
already there, from any source, `app setup` says so and installs nothing.

## Running a single container

`app run` passes the arguments after `--` to `docker run`. Use `-d`, or LWS
waits until the container exits; a restart policy brings it back after a
reboot. The `app deploy` actions do not see containers started this way.

```bash
lws app run 100 -- -d --name hello --restart unless-stopped -p 8080:80 nginx:1.27
```

## Deploying a Compose application

`app deploy` takes an action, the container ID and `--compose-file`, a path
on your machine or an `http://` or `https://` URL. LWS downloads a URL itself,
so the container does not need to reach it.

The **first service** in the file names the application. LWS copies the file
to `/opt/lws/apps/<app>/docker-compose.yml` in the container and uses `<app>`
as the Compose project name (`-p <app>`), so later actions find the same
containers. The name may contain letters, digits, `-` and `_`; keep it
lowercase, as Compose v2 rejects capitals in project names.

| Action | What runs in the container |
|---|---|
| `install` | copies the file, then `up -d` |
| `status` | `ps` |
| `stop`, `start`, `restart` | `stop`, `start`, `restart` |
| `uninstall` | `down`, then removes the auto-start unit |

Only `install` copies the file; the other actions read the app name from your
local file and use the copy in the container. `uninstall` leaves that copy in
place, and `down` keeps named volumes.

LWS copies the Compose file and nothing else. Relative paths in it resolve
against `/opt/lws/apps/<app>/` in the container, and a local `.env` file is
not copied. Use images rather than `build:`, and keep settings in the file or
in named volumes, or create the files in the container with `lws lxc exec`.

### Starting the app at boot

`--auto-start`, with `install` only, writes and enables a systemd unit,
`/etc/systemd/system/lws-<app>.service`, in the container. It runs `up -d`
after Docker has started and `down` when it stops, so the app's containers
are created afresh at each boot: keep data in volumes. The LXC container
starts with the host because `lxc run` sets `onboot` by default. Without
`--auto-start`, services come back only if they have a `restart:` policy.

## Updating an app

```bash
lws app update 100 docker-compose.yml
```

`app update` copies the new file over the old one, then runs `pull` and
`up -d`, which recreates the services whose image or configuration changed.
The file is a positional argument here. Keep the first service name, or LWS
treats the file as a new app and leaves the old one running. A snapshot
taken first gives you a way back; see
[Snapshots and backups](snapshots-and-backups.html).

## Logs, listing and removal

```bash
lws app list 100
lws app logs 100 web_web_1 --tail 100
lws app deploy uninstall 100 --compose-file docker-compose.yml
lws app remove 100
```

`app list` prints running Docker containers as `ID: name (image)`. Compose
names them after project and service: `web_web_1` with Compose v1,
`web-web-1` with v2. `app logs` prints the logs once; to follow them, run
`pct exec 100 -- docker logs -f web_web_1` on the host.

`app remove` runs `apt-get remove` for whichever of `docker.io`,
`docker-compose`, `docker-compose-v2` and `docker-compose-plugin` are
installed. It keeps images, volumes, `/opt/lws/apps` and the auto-start
units, so uninstall the apps first. `--purge` runs
`docker system prune -a -f --volumes` beforehand, which removes what no
running container uses (recent Docker versions prune only anonymous volumes).

## Worked example

An unprivileged Debian 12 container running nginx with Compose, started at
boot. Save this as `docker-compose.yml` on your machine; the service `web`
names the app:

```yaml
services:
  web:
    image: nginx:1.27
    ports:
      - "80:80"
    volumes:
      - html:/usr/share/nginx/html
    restart: unless-stopped

volumes:
  html:
```

Create the container and wait until `hostname -I` shows an address. Then
install Docker, deploy the app, check it, and request the page from your
machine at that address. The reboot at the end shows that the app comes back:

```bash
lws lxc run --size lws-web --unprivileged --features nesting=1,keyctl=1 \
  --hostname web --dhcp \
  --image-id local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst
lws lxc exec 100 "hostname -I"
lws app setup 100
lws app deploy install 100 --compose-file docker-compose.yml --auto-start
lws app deploy status 100 --compose-file docker-compose.yml
lws lxc exec 100 "systemctl is-enabled lws-web.service"
curl -I http://192.168.1.50/
lws lxc reboot 100
lws app list 100
```

To move to `nginx:1.28` later, change the image in your file, take a
snapshot with `lws lxc snapshot-add 100 before-nginx-update`, and run
`app update` as shown above.

## Docker's storage driver

Docker uses the `overlay2` storage driver where it can. The
`Storage Driver:` line of `lws lxc exec 100 "docker info"` shows the one in
use. `vfs` works but copies every image layer in full, which is slow and
takes much more disk space. It happens mostly with a root disk on ZFS,
depending on the OpenZFS and Docker versions; a root disk on LVM-thin
(`local-lvm`) does not have the problem.

## Troubleshooting

**`LXC container 100 is not running. Start it with: lws lxc start 100`**:
`app setup`, `run`, `deploy` and `update` need a running container.

**`Failed to install Docker in container 100: ...`**: the rest of the message
comes from apt. `Unable to locate package` or `Temporary failure resolving`
usually means the container has no network or DNS yet. If `apt-get` is not
found, the container is not Debian or Ubuntu.

**`Failed to extract application name from Docker Compose file.`**: the file
is not valid YAML, has no `services:`, or its first service name has other
characters than letters, digits, `-` and `_` (details in `lws.log`).

**Docker containers fail with `permission denied`**: an OCI runtime error
from `app run` or `app deploy install` mentioning `permission denied` usually
means a missing feature. Check the `features:` line of `lws lxc show 100` and
run `lws app setup 100 --enable-nesting`.

## Related pages

- [CLI reference](cli-reference.html): every `app` option
- [Snapshots and backups](snapshots-and-backups.html)
- [Firewall security groups](firewall-security-groups.html)
- [Troubleshooting](troubleshooting.html)
