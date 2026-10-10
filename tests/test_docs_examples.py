"""
Every `lws` command shown in the documentation has to parse against the real CLI.

The documentation site and the README showed `lws lxc run --size medium` in the
first code block a reader sees. config.yaml.example defines no `medium` size,
so click rejected the command before it reached Proxmox. Other examples passed
`-d` to `app run` and `-h` to `px exec` without a `--` separator: the first
failed with "No such option", the second printed the help page instead of
running `df -h`. Nothing compared the examples with the code, so they drifted.

These tests extract each command from the code blocks in docs/ and README.md
and hand it to click's own parser, with config.yaml.example as the
configuration. Parsing checks command names, option names, `click.Choice`
values such as `--size`, required arguments and options, and argument types. It
does not run anything: no SSH connection is made and nothing is executed.

Lines with a placeholder (`<instance-id>`, `...`, `$VAR`, `[OPTIONS]`) are
skipped, because they are not meant to be pasted as they are.
"""

import html
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS = REPO_ROOT / "docs"

# Prompt prefix, then either the `lws` alias or `python3 lws.py` (with an optional path).
_COMMAND_RE = re.compile(r"^(?:\$\s*)?(?:lws|python3?\s+(?:\S*/)?lws\.py)\s+(.*)$")
_PLACEHOLDER_RE = re.compile(r"<[^>]*>|\.\.\.|\$\{?[A-Za-z_]|\[[A-Z]")
_SHELL_OPERATORS = {"|", "||", "&&", "&", ";", ">", ">>", "<"}

# Runs in a child interpreter so that importing lws.py, which loads config.yaml
# from the working directory at import time, cannot leak into other tests.
_CHECKER = r"""
import contextlib, io, json, sys
import click
sys.path.insert(0, sys.argv[1])
import lws

HELP = {"-h", "--help"}
results = []
for args in json.load(sys.stdin):
    error = None
    root_ctx = click.Context(lws.lws, info_name="lws", **lws.lws.context_settings)
    ctx, cmd, rest = root_ctx, lws.lws, list(args)
    try:
        while isinstance(cmd, click.Group) and rest and not rest[0].startswith("-"):
            sub = cmd.get_command(ctx, rest[0])
            if sub is None:
                raise click.UsageError(f"no such command {rest[0]!r}")
            name = rest.pop(0)
            if isinstance(sub, click.Group):
                ctx = click.Context(sub, info_name=name, parent=ctx)
            cmd = sub
        if isinstance(cmd, click.Group) and not (HELP | {"--version"}) & set(rest):
            raise click.UsageError("the command stops at a group, no subcommand given")
        with contextlib.redirect_stdout(io.StringIO()):
            cmd.make_context(getattr(cmd, "name", "lws"), list(rest), parent=ctx)
    except click.exceptions.Exit:
        # --help and --version exit early. That is the point of a help example,
        # and a bug anywhere else: `px exec df -h` prints help instead of running df.
        if not (rest and rest[-1] in HELP | {"--version"} and len(rest) == 1):
            error = "prints the help page instead of running; put `--` before arguments that start with '-'"
    except click.ClickException as exc:
        error = exc.format_message()
    results.append(error)
json.dump(results, sys.stdout)
"""


def _code_blocks(path: Path):
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".html":
        for match in re.finditer(r"<code>(.*?)</code>", text, re.S):
            yield html.unescape(re.sub(r"<[^>]+>", "", match.group(1)))
    else:
        for match in re.finditer(r"^```[^\n]*\n(.*?)^```", text, re.S | re.M):
            yield match.group(1)


def _documented_commands():
    """(file, line as written, argv after `lws`) for every pasteable example."""
    sources = sorted(DOCS.glob("**/*.md")) + sorted(DOCS.glob("**/*.html")) + [REPO_ROOT / "README.md"]
    for path in sources:
        if "_site" in path.parts:
            continue
        for block in _code_blocks(path):
            for line in block.replace("\\\n", " ").splitlines():
                match = _COMMAND_RE.match(line.strip())
                if not match:
                    continue
                rest = match.group(1)
                if _PLACEHOLDER_RE.search(rest):
                    continue
                # $(date +%Y%m%d) is one word to the shell; keep it one word here.
                rest = re.sub(r"\$\([^)]*\)", "100", rest)
                lexer = shlex.shlex(rest, posix=True, punctuation_chars=True)
                lexer.whitespace_split = True
                lexer.commenters = "#"
                argv = []
                for token in lexer:
                    if token in _SHELL_OPERATORS:
                        break
                    argv.append(token)
                yield str(path.relative_to(REPO_ROOT)), " ".join(line.split()), argv


@pytest.fixture(scope="module")
def parse_errors(tmp_path_factory):
    examples = list(_documented_commands())
    workdir = tmp_path_factory.mktemp("docs-examples")
    shutil.copy(REPO_ROOT / "config.yaml.example", workdir / "config.yaml")
    proc = subprocess.run(
        [sys.executable, "-c", _CHECKER, str(REPO_ROOT)],
        input=json.dumps([argv for _, _, argv in examples]),
        capture_output=True, text=True, cwd=workdir, timeout=120,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    assert proc.returncode == 0, f"The checker itself failed:\n{proc.stderr}"
    results = json.loads(proc.stdout)
    return examples, results


def test_documentation_has_examples_to_check(parse_errors):
    """Guards the extractor: if it silently matched nothing, every test would pass."""
    examples, _ = parse_errors
    assert len(examples) >= 50, f"Only {len(examples)} examples found; has the extraction regex broken?"


def test_every_documented_command_parses(parse_errors):
    examples, results = parse_errors
    failures = [
        f"{source}: {line}\n    -> {error}"
        for (source, line, _), error in zip(examples, results)
        if error
    ]
    assert not failures, (
        "These documented commands are rejected by the CLI (checked against "
        "config.yaml.example):\n\n" + "\n".join(failures)
    )
