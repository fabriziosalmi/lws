"""
The supported Python versions have to agree across the three files that state them.

Before pyproject.toml existed, nothing declared what LWS supports and the three
places that implied it had drifted apart:

    README.md        "Python 3.6 or higher"      (untrue since 2021)
    ci.yml matrix    3.9 to 3.13
    Dockerfile       python:3.14-slim

The 3.9 entry blocked every dependency update that had moved past it, and 3.14,
the version actually shipped, was the one version nobody tested. Neither was
visible without opening three files and comparing them by hand.

These tests make that comparison automatic: `requires-python` in pyproject.toml
is the declaration, and the CI matrix and the Dockerfile have to stay inside it.
"""

import re
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = REPO_ROOT / "pyproject.toml"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
DOCKERFILE = REPO_ROOT / "Dockerfile"


def _version(text: str) -> tuple[int, int]:
    major, minor = text.split(".")[:2]
    return int(major), int(minor)


@pytest.fixture(scope="module")
def declared_floor() -> tuple[int, int]:
    """The (major, minor) floor from `requires-python` in pyproject.toml."""
    # Read with a regex rather than a TOML parser: tomllib is stdlib only from
    # 3.11, and the floor being checked here is 3.10.
    match = re.search(
        r'^requires-python\s*=\s*"(>=\s*\d+\.\d+)"',
        PYPROJECT.read_text(encoding="utf-8"), re.M,
    )
    assert match, "pyproject.toml declares no requires-python."
    spec = match.group(1)
    match = re.fullmatch(r">=\s*(\d+\.\d+)", spec.strip())
    assert match, (
        f"requires-python is {spec!r}. These tests understand a simple '>=X.Y' "
        "floor; if the policy has become more complex, teach them the new shape "
        "rather than deleting them."
    )
    return _version(match.group(1))


@pytest.fixture(scope="module")
def matrix_versions() -> list[tuple[int, int]]:
    """The python-version matrix from the CI workflow."""
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    matrix = workflow["jobs"]["test"]["strategy"]["matrix"]["python-version"]
    return [_version(str(v)) for v in matrix]


@pytest.fixture(scope="module")
def dockerfile_version() -> tuple[int, int]:
    """The Python version the shipped image is built from."""
    match = re.search(r"^FROM\s+python:(\d+\.\d+)", DOCKERFILE.read_text(encoding="utf-8"), re.M)
    assert match, "Dockerfile has no `FROM python:X.Y` line to check against."
    return _version(match.group(1))


def test_ci_matrix_starts_at_the_declared_floor(declared_floor, matrix_versions):
    """
    A matrix entry below the floor is not testing an old Python, it is blocking
    updates: the dependencies this project pins refuse to install there.
    """
    below = [v for v in matrix_versions if v < declared_floor]
    assert not below, (
        f"CI tests Python {['.'.join(map(str, v)) for v in below]}, below the "
        f"declared floor {'.'.join(map(str, declared_floor))}. Either raise the "
        "matrix or lower requires-python, but do not let them disagree."
    )
    assert min(matrix_versions) == declared_floor, (
        f"The lowest tested version is {'.'.join(map(str, min(matrix_versions)))} "
        f"but the floor is {'.'.join(map(str, declared_floor))}. The floor is "
        "supposed to be tested, otherwise it is a claim rather than a guarantee."
    )


def test_the_shipped_python_is_tested(matrix_versions, dockerfile_version):
    """
    The Dockerfile is how LWS actually runs. Its interpreter being absent from
    the matrix is how 3.14 went untested while the image was built on it.
    """
    assert dockerfile_version in matrix_versions, (
        f"The Dockerfile builds on Python {'.'.join(map(str, dockerfile_version))}, "
        f"which is not in the CI matrix {['.'.join(map(str, v)) for v in matrix_versions]}. "
        "The version shipped to users is the one that most needs a test run."
    )


def test_the_shipped_python_satisfies_the_floor(declared_floor, dockerfile_version):
    assert dockerfile_version >= declared_floor, (
        f"The Dockerfile builds on Python {'.'.join(map(str, dockerfile_version))}, "
        f"below the declared floor {'.'.join(map(str, declared_floor))}."
    )


def test_classifiers_match_the_matrix(matrix_versions):
    """
    The classifiers are what PyPI and tooling read. They are easy to forget when
    a version is added or dropped, and wrong metadata is worse than none.
    """
    declared = {
        _version(m)
        for m in re.findall(
            r'"Programming Language :: Python :: (\d+\.\d+)"',
            PYPROJECT.read_text(encoding="utf-8"),
        )
    }
    assert declared == set(matrix_versions), (
        f"Classifiers declare {sorted(declared)} but CI tests {sorted(set(matrix_versions))}."
    )


def test_the_interpreter_running_the_tests_satisfies_the_floor(declared_floor):
    """A sanity check on the floor itself: it cannot exceed what CI runs on."""
    assert sys.version_info[:2] >= declared_floor, (
        f"These tests are running on Python {sys.version_info.major}.{sys.version_info.minor}, "
        f"below the declared floor {'.'.join(map(str, declared_floor))}."
    )
