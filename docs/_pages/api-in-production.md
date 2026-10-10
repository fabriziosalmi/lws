---
title: Running the API in production
seo_title: "Run the LWS REST API in production: proxy, TLS, systemd"
description: "Deploy the LWS REST API behind nginx with TLS and basic auth, run it with systemd or Docker, and set the key, timeouts, CORS and logs."
---

# Running the REST API in production

The REST API (`api.py`) is a Flask application. For each request it starts
`lws.py` as a separate process, waits for it to end and returns the output
as JSON, so a request can do anything the CLI can do: whoever holds the API
key has root on every host under `regions` in `config.yaml`. This page shows
how to run it so that the key is not the only protection. The
[Security model](security-model.html) gives the wider picture.

## How the server runs

- With `api.debug: false` (the default), `api.py` serves the application with
  waitress, a production WSGI server. `api.debug: true` switches to Flask's
  development server, which is not meant for production.
- `api.py` reads the `config.yaml` next to it once, at startup. The `lws.py`
  processes read `config.yaml` from the current directory on every request:
  changes to `regions` apply at once, changes to `api_key` or `api` after a
  restart.
- The API has no TLS and no rate limiting of its own, and one key gives full
  access. A reverse proxy adds the rest.

You need a Linux machine that reaches the SSH port of every Proxmox host,
Python 3.10 or later with `sshpass` and the OpenSSH client (or Docker), a
working CLI setup, and a DNS name with a TLS certificate for the proxy.

## Set the API key

Generate a random key and write it into `config.yaml`:

```bash
KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
sed -i "s|^api_key:.*|api_key: \"$KEY\"|" config.yaml
echo "$KEY"   # give this to API clients
```

The API refuses to start when `api_key` is empty or one of the example values
from the repository, such as `changeme`, and logs a warning when the key is
shorter than 32 characters (the command above produces 43). Clients send it
in the `X-API-Key` header, compared in constant time. Every endpoint needs it
except `/api/v1/health`, the Swagger documentation and the web UI files.
There is one key for all clients: store it like a root password.

## Bind to loopback

`api.host` defaults to `127.0.0.1` and `api.port` to `8080`. Keep the API on
loopback and let a reverse proxy on the same machine be the only way in.
Change `api.host` only for the Docker image (see below) or for an address
that only an administration network or VPN can reach.

## Put a reverse proxy in front

The proxy terminates TLS, asks for a second credential, limits the request
rate and logs the real client addresses. This example uses nginx with basic
authentication. `htpasswd` comes from the `apache2-utils` package:

```bash
sudo htpasswd -c /etc/nginx/lws-api.htpasswd admin
sudo chown root:www-data /etc/nginx/lws-api.htpasswd
sudo chmod 640 /etc/nginx/lws-api.htpasswd
```

`/etc/nginx/conf.d/lws-api.conf` (files in `conf.d` are included in the
`http` context, where `limit_req_zone` belongs):

```nginx
limit_req_zone $binary_remote_addr zone=lws_api:10m rate=30r/m;

server {
    listen 443 ssl;
    server_name lws.example.net;

    ssl_certificate     /etc/letsencrypt/live/lws.example.net/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/lws.example.net/privkey.pem;

    auth_basic           "LWS API";
    auth_basic_user_file /etc/nginx/lws-api.htpasswd;

    limit_req        zone=lws_api burst=20 nodelay;
    limit_req_status 429;
    client_max_body_size 1m;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        # The API does not need the basic auth credentials.
        proxy_set_header Authorization "";
        # Requests wait for the lws command: api.command_timeout plus a margin.
        proxy_read_timeout 3700s;
    }
}
```

Load it with `sudo nginx -t && sudo systemctl reload nginx`. Clients then
send both credentials:

```bash
curl -u admin -H "X-API-Key: $LWS_API_KEY" https://lws.example.net/api/v1/lxc/instances
```

The example allows 30 requests per minute per client address, with bursts of
20, and answers `429` beyond that; adjust it to your clients. The API now
sees every request coming from `127.0.0.1`, including the
`Unauthorized access attempt` lines in `api.log`: the nginx access log has
the real addresses and the basic auth user. Another proxy, such as Caddy,
works as well if it adds TLS and authentication and waits at least
`api.command_timeout` for a response.

## Run it with systemd

Install LWS in its own folder, owned by an unprivileged account whose home is
that folder, so SSH keeps host keys in `/opt/lws/.ssh/known_hosts`:

```bash
sudo useradd --system --user-group --home-dir /opt/lws --shell /usr/sbin/nologin lws
sudo git clone https://github.com/fabriziosalmi/lws.git /opt/lws
sudo python3 -m venv /opt/lws/venv
sudo /opt/lws/venv/bin/pip install -r /opt/lws/requirements.txt
sudo cp /opt/lws/config.yaml.example /opt/lws/config.yaml
sudo chown -R lws:lws /opt/lws && sudo chmod 600 /opt/lws/config.yaml
```

Edit `/opt/lws/config.yaml`. Host keys are recorded per account, so connect
to each host once as `lws` (repeat with each `--region` and `--az`):

```bash
cd /opt/lws && sudo -u lws venv/bin/python lws.py px status --region eu-south-1 --az az1
```

Then create `/etc/systemd/system/lws-api.service`:

```ini
[Unit]
Description=LWS REST API
Wants=network-online.target
After=network-online.target

[Service]
User=lws
Group=lws
# Must hold config.yaml and lws.py: lws.py reads ./config.yaml,
# and api.log, lws.log and lws.json.log are written here.
WorkingDirectory=/opt/lws
ExecStart=/opt/lws/venv/bin/python /opt/lws/api.py
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/opt/lws
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now lws-api
journalctl -u lws-api -n 20   # why a start was refused, if it was
```

- The service needs no local root, since root work happens on the hosts
  over SSH. With `use_local_only: true` on a Proxmox host, `pct` runs locally
  and the service has to run as root.
- `ProtectSystem=strict` makes everything except `ReadWritePaths` read-only;
  a `known_hosts` file outside `/opt/lws` could not record new host keys.
  `PrivateTmp=true` gives LWS a writable `/tmp`.
- Do not add options that restrict networking, such as `PrivateNetwork=` or
  `IPAddressDeny=`: the service opens SSH connections to the hosts.

**Warning:** stopping or restarting the service also stops the `lws` commands
it is running, in the middle of the operation.

## Run it with Docker

The image is based on `python:3.14-slim` with `sshpass` and the OpenSSH
client. It copies `lws.py`, `api.py`, `ui.html`, `requirements.txt`,
`lws_core/`, `lws_commands/` and `vendor/` into `/app`, runs
`python3 api.py` as the unprivileged user `lws`, and exposes port 8080.
`config.yaml` is not part of it:

```bash
docker build -t lws-api .
LWS_UID=$(docker run --rm lws-api id -u)
sudo mkdir -p /srv/lws/ssh && sudo cp config.yaml /srv/lws/config.yaml
sudo chown -R "$LWS_UID" /srv/lws
sudo chmod 600 /srv/lws/config.yaml && sudo chmod 700 /srv/lws/ssh
```

Set `api.host: "0.0.0.0"` in `/srv/lws/config.yaml`, since a published port
cannot reach loopback inside the container. Publish the port on the host's
loopback only, behind the proxy:

```bash
docker run -d --name lws-api --restart unless-stopped \
  -v /srv/lws/config.yaml:/app/config.yaml:ro \
  -v /srv/lws/ssh:/home/lws/.ssh \
  -p 127.0.0.1:8080:8080 lws-api
```

`-p 8080:8080` without an address publishes the API on every interface, and
Docker's port rules bypass firewalls such as `ufw`. The `ssh` volume keeps
`known_hosts` when the container is replaced; without it, each new container
trusts host keys again on first contact. Logs are in `docker logs lws-api`.

## Timeouts and long operations

A request blocks until its `lws` command ends, and backups, migrations or
package installs take minutes.

- `api.command_timeout` (3600 seconds by default) is how long the API waits.
  Then it stops the `lws` process and answers `500` with
  `Command execution timed out after 3600 seconds.` A step already started
  on a host can keep running there.
- `ssh_command_timeout` (3600 by default) limits each remote command, and one
  `lws` command can run several: keep `api.command_timeout` at least as high.
- The proxy (`proxy_read_timeout`), any load balancer and the client (for
  example `curl --max-time`) must wait at least `api.command_timeout`. If one
  gives up first, the operation continues, and sending the request again can
  run it twice.
- waitress handles four requests at a time by default, and `api.py` keeps
  that. Further requests, health checks included, wait for a free slot.

## CORS

A browser page on another origin may call the API only when
`api.allowed_origins` lists that origin; without the list, none may. The web
UI at `/` is served by the API itself and needs no entry, and `curl`, scripts
and servers are not affected by CORS. List only your own `https://` origins.
Configuration files from earlier versions may contain `"null"`, the origin of
pages opened from a local file or a sandboxed frame: remove it.

## Logs

The API writes to `api.log` in its working directory and to standard output
(the journal, or `docker logs`). `api.log_level` is `DEBUG`, `INFO`,
`WARNING` or `ERROR`.

- At `INFO`, every command is logged before it runs. Values of options whose
  name contains `password`, `secret`, `token` or `key` are written as `***`,
  so `lxc run --password` does not reach the file in clear text.
- `exec` commands are logged as sent, and `DEBUG` adds the output of every
  command. Keep `INFO` in production.
- The `lws.py` processes write errors to `lws.log` and `lws.json.log`.

LWS does not rotate these files. With logrotate, use `copytruncate`, because
the API keeps `api.log` open.

## Rotate the key

Rotate it when someone who knew it leaves, when it shows up in a log, ticket
or shell history, and on a schedule. Write a new key into `config.yaml` as in
[Set the API key](#set-the-api-key) (in the systemd setup, run `sed` with
`sudo -u lws`), then run `sudo systemctl restart lws-api`, or
`docker restart lws-api` for the container. The old key stops working at the
restart, so update the clients at the same time.

## Health check and Swagger UI

`curl http://127.0.0.1:8080/api/v1/health` answers `{"status": "ok"}`
without a key. It shows that the process answers, not that hosts are
reachable; for that, call `GET /api/v1/px/hosts` with the key, which runs
`lws px list`.

The Swagger UI is at `/api/v1/docs` and the OpenAPI document at
`/api/v1/swagger.json`, both without a key; behind the proxy, basic auth
protects them. **Authorize** takes the API key. Through a TLS proxy,
"Try it out" may be blocked by the browser, because the document advertises
the plain HTTP address the API sees. Use `curl` instead.

## Pre-flight checklist

- `api_key` is random, at least 32 characters, known only to its clients.
- `config.yaml` is mode `0600`, owned by the account that runs the API.
- `api.debug` is `false`; `api.host` is `127.0.0.1` (or `0.0.0.0` in a
  container published on `127.0.0.1`), and `ss -ltn` shows port 8080 on
  `127.0.0.1` only.
- The proxy serves HTTPS only and asks for its own credentials.
- Proxy and client timeouts are at least `api.command_timeout`, which is at
  least `ssh_command_timeout`.
- `api.allowed_origins` is empty or lists only your origins, without `"null"`.
- `api.log_level` is `INFO`, and the logs are rotated.
- `known_hosts` survives restarts, and each host's key was checked once.
- The Proxmox hosts accept SSH only from this machine.
- Without the key a request returns `401`; with it, through the proxy, it
  succeeds.

## Related pages

- [Configuration](configuration.html#rest-api): every `api` key.
- [API reference](api-reference.html): the endpoints.
- [Security model](security-model.html): what the key gives access to.
- [Troubleshooting](troubleshooting.html#rest-api): startup and timeout
  errors.
