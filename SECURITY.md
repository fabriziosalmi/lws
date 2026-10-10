# Security Policy

LWS runs commands as root on Proxmox VE hosts, and its REST API turns an API
key into that same access. Security reports are welcome and are handled before
other work.

## Supported versions

Fixes go into the latest release and into `main`. Older releases do not
receive security updates: upgrade to the latest release.

| Version        | Supported |
| -------------- | --------- |
| Latest release | Yes       |
| Older releases | No        |

## Reporting a vulnerability

**Do not open a public issue for a vulnerability.** An issue is visible to
everyone, including people who could use it against hosts that are not yet
patched.

Report it privately instead:

1. On GitHub, open the repository's **Security** tab and choose **Report a
   vulnerability**. This creates a private advisory that only the maintainers
   can see.
2. If that option is not available to you, write to the maintainer at the
   address listed under "Enforcement" in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

Please include:

- the LWS version or commit, and whether the CLI, the REST API or the web UI
  is affected;
- the steps or the request that reproduce the problem;
- what an attacker gains, and what access they need first (network access to
  the API, a valid API key, a crafted Compose file, ...).

The maintainer aims to answer within a week. Once a fix is released, the
advisory is published with credit to the reporter, unless you prefer to stay
anonymous.

## Scope

In scope: command injection on the Proxmox host or in containers, ways around
the API key, disclosure of passwords or keys (in logs, responses or files),
and cross-site scripting in the web UI.

Out of scope: anything that needs the API key or `config.yaml` already, since
both grant root on the configured hosts by design; and weaknesses of Proxmox
VE itself, which should be reported to Proxmox.
