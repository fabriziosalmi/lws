---
title: Contributing
seo_title: "Contributing to LWS: setup, tests and pull requests"
description: "How to set up a development checkout of LWS, run the test suite, follow the project conventions for commits and code, and open a pull request."
---

# Contributing to LWS

Bug reports, fixes, documentation and new commands are all welcome. This page
covers what you need to know to get a change merged.

## Reporting a problem

Open an [issue](https://github.com/fabriziosalmi/lws/issues) with the command
you ran, its full output, your Proxmox VE version and whether you use
`use_local_only`. Remove passwords and API keys from anything you paste.

## Setting up a checkout

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR_USERNAME/lws.git
cd lws
git remote add upstream https://github.com/fabriziosalmi/lws.git

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt   # includes pytest, pytest-cov and pytest-mock
pip install ruff==0.15.6          # the version CI uses
```

LWS supports Python 3.10 to 3.14. The floor is declared once, in
`pyproject.toml`; `tests/test_python_support.py` fails if the CI matrix or the
Dockerfile disagree with it.

## Checks a pull request has to pass

CI runs on every pull request:

| Check | Command | Blocks the merge |
|---|---|---|
| Tests, Python 3.10 to 3.14 | `pytest` | Yes |
| Lint: real errors | `ruff check --select=E9,F63,F7,F82 .` | Yes |
| Lint: full rule set | `ruff check .` | No, advisory: `lws.py` and `api.py` carry older findings |
| Static analysis | slopless (`.github/workflows/slopless.yml`) | On errors |
| Documentation site | Jekyll build and link check, when `docs/` changes | Yes |

Run the first two before pushing:

```bash
ruff check --select=E9,F63,F7,F82 .
pytest
```

`pytest.ini` already adds coverage for `lws_core` and `api` and an HTML report
in `htmlcov/`. The suite is fully mocked: it needs no Proxmox host, SSH access
or Docker. Only the markers `unit`, `integration`, `slow`, `ssh` and `proxmox`
are allowed (`--strict-markers`).

## Writing code

### Commands

Every command lives in `lws.py`; `lws_commands/` is an empty placeholder. A
new command follows the pattern of the existing ones:

```python
@lxc.command('example')
@click.argument('instance_ids', nargs=-1, callback=_validate_pattern(_VMID_RE, "instance id"))
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
def example(instance_ids, region, az):
    """Short description shown in --help."""
    ...
```

- **Validate every value that reaches a remote command.** OpenSSH joins the
  arguments into one string for the host's shell, so a value that is safe as
  a local argument can still inject a command remotely. Use
  `_validate_pattern` with one of the patterns at the top of `lws.py`, or
  `_validate_ip_or_cidr`, as a click callback.
- **Run remote commands through `run_proxmox_command`** from `lws_core`, so
  `use_local_only` is honoured and the SSH options and password handling stay
  in one place.
- **Exit non-zero on failure** (`sys.exit(1)`). The REST API turns the exit
  code into the HTTP status, so a failure that exits 0 reaches API clients as
  a success.

### API endpoints

`api.py` runs `lws.py` as a subprocess:

```python
@app.route('/api/v1/lxc/instances/<instance_id>/example', methods=['POST'])
@require_api_key
def example_endpoint(instance_id):
    data = request.get_json(silent=True) or {}
    stdout, stderr, rc = run_lws_command(['lxc', 'example', instance_id], data)
    return format_response(stdout, stderr, rc)
```

`run_lws_command(command_parts, data=None, consumed_keys=None)` turns the
remaining keys of `data` into `--key value` options. Pass `consumed_keys` for
values you already placed in `command_parts`, so they are not sent twice.
Non-numeric `<instance_id>` path segments are rejected before the handler
runs.

### Tests

Tests live in `tests/` and mock `subprocess` and SSH. Do not depend on a
`config.yaml` in the working directory: the file is not tracked. Write one to
`tmp_path` and change into it, as `tests/test_config.py` does:

```python
def test_load_config_from_cwd(tmp_path, monkeypatch, sample_config):
    (tmp_path / "config.yaml").write_text(yaml.dump(sample_config))
    monkeypatch.chdir(tmp_path)
    assert load_config()["regions"]
```

## Documentation

The site in `docs/` is built by GitHub Pages with Jekyll; `docs/README.md`
explains its layout and how to preview it. When you change a command, update
`docs/_pages/cli-reference.md` and, for the API, `docs/_pages/api-reference.md`.

Two tests keep the documentation honest:

- `tests/test_docs_examples.py` parses every `lws` command in the
  documentation and the README with the real CLI. An example with a wrong
  option or size name fails the suite.
- `tests/test_docs_site.py` checks that every page is in
  `docs/_data/navigation.yml` and has a title and description, and that the
  version on the site matches `pyproject.toml`.

## Commits and pull requests

Commit titles follow a `type: summary` form, as in the history: `fix:`,
`docs:`, `ci:`, `build(deps):`, `chore:`, `release:`, with a scope where it
helps (`fix(api):`). Explain in the body why the change is needed.

```text
fix(api): refuse to start without a real API key

An empty api_key left every endpoint unauthenticated...
```

1. Branch from an up-to-date `main`:
   `git fetch upstream && git checkout -b fix/short-name upstream/main`.
2. Keep each pull request to one change, with tests for new behaviour.
3. Describe what changed and how you checked it. There is no pull request
   template.
4. Pull requests are squash-merged; the title becomes the commit title.

## Security issues

`SECURITY.md` describes how to report a vulnerability. Avoid posting working
exploit details in a public issue.

## Conduct

The project follows its [Code of Conduct](https://github.com/fabriziosalmi/lws/blob/main/CODE_OF_CONDUCT.md).

## License

Contributions are released under the [MIT License](https://github.com/fabriziosalmi/lws/blob/main/LICENSE),
like the rest of the project.
