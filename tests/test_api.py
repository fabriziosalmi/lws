"""
Unit tests for api.py.

api.py loads config.yaml and validates the API key at *import* time (it
calls sys.exit(1) if the key is missing/a placeholder), so these tests
temporarily replace the real config.yaml with a valid one before the
first import and restore it afterward - see the `api_module` fixture.
"""

import os
import sys
import json
import importlib
import pytest
import yaml
from pathlib import Path
from unittest.mock import patch, Mock

PROJECT_ROOT = Path(__file__).parent.parent
CONFIG_PATH = PROJECT_ROOT / "config.yaml"

TEST_CONFIG = {
    "api_key": "test-api-key-" + "x" * 32,
    "api": {"allowed_origins": [], "debug": False, "host": "127.0.0.1", "port": 8080},
    "regions": {
        "eu-south-1": {
            "availability_zones": {
                "az1": {"host": "proxmox1.example.com", "user": "root", "ssh_password": "secret"}
            }
        }
    },
    "instance_sizes": {"micro": {"memory": 512, "cpulimit": 1, "storage": "8G"}},
}


@pytest.fixture(scope="module")
def api_module():
    """Import api.py with a known-valid config.yaml, then restore the original file."""
    original = CONFIG_PATH.read_text() if CONFIG_PATH.exists() else None
    CONFIG_PATH.write_text(yaml.safe_dump(TEST_CONFIG))
    sys.modules.pop("api", None)
    try:
        import api as api_mod
        yield api_mod
    finally:
        sys.modules.pop("api", None)
        if original is not None:
            CONFIG_PATH.write_text(original)
        else:
            CONFIG_PATH.unlink(missing_ok=True)


@pytest.fixture
def client(api_module):
    api_module.app.config["TESTING"] = True
    return api_module.app.test_client()


@pytest.fixture
def api_key(api_module):
    return api_module.API_KEY


class TestValidateInstanceId:
    @pytest.mark.unit
    def test_numeric_string_is_valid(self, api_module):
        assert api_module.validate_instance_id("101") is True

    @pytest.mark.unit
    def test_numeric_int_is_valid(self, api_module):
        assert api_module.validate_instance_id(101) is True

    @pytest.mark.unit
    @pytest.mark.parametrize("bad", ["101; rm -rf /", "abc", "", None, ["101"], "10.1"])
    def test_invalid_values_rejected(self, api_module, bad):
        assert api_module.validate_instance_id(bad) is False


class TestValidateInstanceIdsList:
    @pytest.mark.unit
    def test_all_numeric_is_valid(self, api_module):
        assert api_module.validate_instance_ids_list(["101", "102"]) is True

    @pytest.mark.unit
    def test_empty_list_is_invalid(self, api_module):
        assert api_module.validate_instance_ids_list([]) is False

    @pytest.mark.unit
    def test_not_a_list_is_invalid(self, api_module):
        assert api_module.validate_instance_ids_list("101") is False

    @pytest.mark.unit
    def test_one_bad_id_invalidates_whole_list(self, api_module):
        assert api_module.validate_instance_ids_list(["101", "102; touch /tmp/pwned"]) is False


class TestRunLwsCommandConsumedKeys:
    """run_lws_command must not re-send a value as both a positional cmd_parts
    entry and a --flag option - that's the bug behind api_remove and ~17
    other handlers (see run_lws_command's consumed_keys docstring)."""

    @pytest.mark.unit
    def test_consumed_key_not_duplicated_as_option(self, api_module):
        mock_process = Mock()
        mock_process.communicate.return_value = ("ok", "")
        mock_process.returncode = 0

        with api_module.app.test_request_context("/?unused=1"):
            with patch("subprocess.Popen", return_value=mock_process) as mock_popen:
                api_module.run_lws_command(
                    ["px", "backup-lxc", "101"],
                    {"vmid": "101", "storage": "local"},
                    consumed_keys=["vmid"],
                )
                full_cmd = mock_popen.call_args[0][0]
                assert full_cmd.count("--vmid") == 0
                assert "--storage" in full_cmd
                assert "local" in full_cmd

    @pytest.mark.unit
    def test_without_consumed_keys_value_is_duplicated(self, api_module):
        """Documents the bug this fixes: omitting consumed_keys re-sends the
        positional value as an option too."""
        mock_process = Mock()
        mock_process.communicate.return_value = ("ok", "")
        mock_process.returncode = 0

        with api_module.app.test_request_context("/"):
            with patch("subprocess.Popen", return_value=mock_process) as mock_popen:
                api_module.run_lws_command(
                    ["px", "backup-lxc", "101"],
                    {"vmid": "101", "storage": "local"},
                )
                full_cmd = mock_popen.call_args[0][0]
                assert full_cmd.count("--vmid") == 1


class TestBeforeRequestInstanceIdGuard:
    """The global before_request hook must reject a non-numeric <instance_id>
    path segment before any route handler runs."""

    @pytest.mark.unit
    def test_non_numeric_instance_id_rejected(self, client, api_key):
        resp = client.get(
            "/api/v1/lxc/instances/abc",
            headers={"X-API-Key": api_key},
        )
        assert resp.status_code == 400

    @pytest.mark.unit
    def test_injection_attempt_in_instance_id_rejected(self, client, api_key):
        # No "/" anywhere in the payload (encoded or not): a "/" instead
        # fails Flask's own routing (404) before reaching the guard, which
        # is a separate, also-safe outcome but not what this test is about.
        resp = client.get(
            "/api/v1/lxc/instances/101%3Bid",
            headers={"X-API-Key": api_key},
        )
        assert resp.status_code == 400

    @pytest.mark.unit
    def test_numeric_instance_id_passes_guard(self, client, api_key, api_module):
        mock_process = Mock()
        mock_process.communicate.return_value = ("{}", "")
        mock_process.returncode = 0
        with patch("subprocess.Popen", return_value=mock_process):
            resp = client.get(
                "/api/v1/lxc/instances/101",
                headers={"X-API-Key": api_key},
            )
        assert resp.status_code == 200


class TestAppRemoveRoute:
    """app_remove used to be declared as def app_remove(instance_ids) with a
    route carrying no <instance_ids> placeholder, so Flask called it with
    zero arguments and every request raised TypeError -> 500."""

    @pytest.mark.unit
    def test_app_remove_does_not_crash_with_type_error(self, client, api_key):
        mock_process = Mock()
        mock_process.communicate.return_value = ("removed", "")
        mock_process.returncode = 0
        with patch("subprocess.Popen", return_value=mock_process) as mock_popen:
            resp = client.post(
                "/api/v1/lxc/instances/app/remove",
                headers={"X-API-Key": api_key},
                json={"instance_ids": ["101", "102"]},
            )
        assert resp.status_code == 200
        full_cmd = mock_popen.call_args[0][0]
        assert "101" in full_cmd and "102" in full_cmd
        assert full_cmd.count("--instance-ids") == 0

    @pytest.mark.unit
    def test_app_remove_rejects_non_numeric_ids(self, client, api_key):
        resp = client.post(
            "/api/v1/lxc/instances/app/remove",
            headers={"X-API-Key": api_key},
            json={"instance_ids": ["101; rm -rf /"]},
        )
        assert resp.status_code == 400


class TestApiKeyAuthentication:
    @pytest.mark.unit
    def test_missing_api_key_is_rejected(self, client):
        resp = client.get("/api/v1/conf")
        assert resp.status_code == 401

    @pytest.mark.unit
    def test_wrong_api_key_is_rejected(self, client):
        resp = client.get("/api/v1/conf", headers={"X-API-Key": "wrong-key"})
        assert resp.status_code == 401

    @pytest.mark.unit
    def test_health_check_needs_no_key(self, client):
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
