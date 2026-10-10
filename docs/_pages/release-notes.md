---
title: Release notes
seo_title: "LWS release notes and changelog"
description: "What changed in each LWS release, from 1.0.0 to the current version: security fixes, API changes, supported Python versions and documentation."
---

# Release notes

The changes in each LWS release that affect people running it. The full list
of pull requests for every version is on the
[GitHub releases page](https://github.com/fabriziosalmi/lws/releases).

## Not yet released

Merged into `main` after 1.4.3:

- **Command injection over SSH.** OpenSSH joins the arguments of a remote
  command into one string for the host's shell. The remaining commands that
  did not go through LWS's hardened SSH helper now do: `px reboot`, `px exec`,
  `px upload`, the Compose file transfers in `app deploy` and `app update`,
  and the file copies in the backup commands. Values that end up in remote
  commands, such as `--target-host`, `--storage` and the `lxc clone` options,
  are now checked against allow-lists.
- **`lxc run`** quotes its free-text options (`--hostname`, `--password`,
  `--net0`, `--ip`, `--gateway`, `--dns` and others) before they reach the
  remote shell.
- **Web UI.** API responses are rendered as text instead of HTML, which closes
  a cross-site scripting hole in `ui.html`.
- **`lxc exec`** ran everything after a `&&`, `;` or `|` on the Proxmox host
  instead of in the container. The command now reaches the container as one
  argument list; use `sh -c '...'` for shell syntax.
- **Timeouts.** Remote commands were stopped after 60 seconds and started
  again up to twice, which cut off and repeated backups, package installs and
  migrations. The limit is now `ssh_command_timeout` (3600 seconds by default,
  `0` for none), a command that timed out is never run again, and only failed
  connections are retried. The API's limit is `api.command_timeout`.
- **`px update`** never updated a host. It now runs `apt-get dist-upgrade` on
  the selected host after a confirmation (`--yes` skips it).
- **Security groups** use the Proxmox API (`pvesh`) instead of editing files.
  `security-group-attach` used to add the group as a disabled rule; it now
  enables it, and `--enable-firewall` turns on the container's firewall.
  `security-group-rm` refuses a group that still has rules unless `--force`,
  and `security-group-rule-rm` removes exact matches only.
- **Backups.** `lxc backup-create` failed on every run (`--compress 6` is not
  a vzdump value); it now takes `--compress zstd|gzip|lzo|none`, `--mode` and
  `--storage`. `lxc backup-restore` restores vzdump archives with
  `pct restore` and no longer deletes the backup afterwards.
- **Scaling.** The example thresholds were written as percentages, so
  `lxc scale-check` always suggested more; values above 1 are now read as
  percentages. `lxc scale --storage-size` grows the disk with `pct resize`,
  and `--net-limit` keeps the rest of the network settings.
- **Docker apps.** `app setup` installs Docker and Compose from the
  container's package manager and checks the `nesting` and `keyctl` features
  (`--enable-nesting` sets them). `app deploy` keeps each Compose file in
  `/opt/lws/apps/<name>/`, and `--auto-start` installs a systemd unit inside
  the container instead of on the host.
- **Other commands.** `lxc run` gains `--features` and `--unprivileged`;
  `lxc clone` removes its temporary snapshot; `lxc migrate` gains
  `--restart` and `--target-storage`; `lxc health-check --fix` no longer runs
  placeholder commands; `lxc net` checks UDP ports with UDP.
- **API.** Passwords no longer appear in `api.log`, error responses no longer
  include exception text, and the Swagger page's "Try it out" calls the
  right URLs.
- **Configuration.** `config.yaml.example` drops the scaling, discovery and
  `minimum_resources` keys that no command read. Existing files load
  unchanged.

## 1.4.3 (2 October 2026)

- **SSH host keys** are now checked: `StrictHostKeyChecking=accept-new` trusts
  a host on first contact and refuses a changed key afterwards. Before, any key
  was accepted.
- **SSH passwords** are passed to `sshpass` through the environment instead of
  the command line, so they no longer show up in the process list.
- **Input validation**: instance IDs, group names, protocols, ports and IP
  addresses are checked before they are used in remote commands.
- **Exit codes**: the bulk `lxc` commands and 44 other failure paths now exit
  with a non-zero status, so the REST API reports those failures as errors.
- **`lxc exec`** keeps quoted arguments that contain spaces intact.
- **REST API**: CORS denies cross-origin requests unless `allowed_origins`
  lists them; the server runs on waitress unless `debug` is set, and the
  Werkzeug interactive debugger is never enabled.
- **Docker image** now includes the `lws_core` package and `sshpass`, which
  the API needs to run commands.

## 1.4.2 (9 September 2026)

- **The REST API refuses to start without a real API key**, and the example
  configuration binds it to `127.0.0.1`. An empty `api_key`, or one of the
  placeholders that shipped in the repository, stops the server at startup.
  Upgrading: set `api_key` to a random value of at least 32 characters, and
  set `api.host` explicitly if the API has to listen on another address.
- **Python 3.10 or later** is required, and CI tests every version from 3.10
  to 3.14. The Docker image is based on Python 3.14 and runs as an
  unprivileged `lws` user.
- **No third-party requests from the documentation site and web UI**: fonts
  and libraries are served from the repository.
- A debug message no longer includes file paths.

## 1.4.1 (8 November 2025)

- A pytest suite for the `lws_core` modules.
- The documentation site in `docs/`, published on GitHub Pages.

## 1.4.0 (8 November 2025)

- The shared code of `lws.py` moved into the `lws_core` package
  (configuration, SSH, Proxmox commands, logging, utilities).
- The REST API no longer includes exception details in the error it returns
  when it cannot start a command.

## 1.3.0 (13 September 2025)

- A `Dockerfile` for running the REST API in a container.
- Security and code quality fixes.

## 1.2.0 and 1.1.0 (5 May 2025)

Released without notes; the
[1.1.0](https://github.com/fabriziosalmi/lws/compare/v1.0.0...v1.1.0) and
[1.2.0](https://github.com/fabriziosalmi/lws/compare/v1.1.0...v1.2.0)
comparisons list the commits.

## 1.0.0 (1 April 2025)

The first tagged release.
