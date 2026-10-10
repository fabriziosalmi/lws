"""
Behaviour of lws.py commands, with every command sent to Proxmox captured.

Nothing here runs pct or ssh: `run_argv`, `run_proxmox_command` and
`run_ssh_command` are replaced by fakes that record the argument lists and
return canned results. The tests check what LWS would run on a host, and how
it reports the outcome.
"""

import logging
import shlex
import subprocess
from unittest.mock import patch

import pytest
from click.testing import CliRunner

import lws

HOST = {"host": "pve1.example.net", "user": "root", "ssh_password": "pw"}
CONFIG = {
    "use_local_only": False,
    "start_vmid": 10000,
    "default_storage": "local-lvm",
    "default_network": "vmbr0",
    "regions": {
        "eu-south-1": {"availability_zones": {"az1": HOST, "az2": {**HOST, "host": "pve2.example.net"}}},
        "lab": {"availability_zones": {"pve-lab": {**HOST, "host": "pve-lab.local"}}},
    },
    "instance_sizes": {"small": {"memory": 1024, "cpulimit": 1, "storage": "local-lvm:8"}},
}


def ok(stdout="", stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout, stderr=stderr)


def fail(stderr="boom", returncode=1):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout="", stderr=stderr)


class Recorder:
    """Stands in for run_argv/run_proxmox_command; answers by matching argv prefixes."""

    def __init__(self, responses=None, default=None):
        self.calls = []
        self.inputs = {}  # index in calls -> text sent to the command's stdin
        self.responses = responses or []
        self.default = default if default is not None else ok()

    def respond(self, argv):
        joined = " ".join(argv)
        for prefix, result in self.responses:
            if joined.startswith(prefix):
                return result(argv) if callable(result) else result
        return self.default

    def argv(self, argv, use_local_only=False, host_details=None, input_text=None):
        argv = [str(a) for a in argv]
        if input_text is not None:
            self.inputs[len(self.calls)] = input_text
        self.calls.append(argv)
        return self.respond(argv)

    def proxmox(self, local_cmd, remote_cmd=None, use_local_only=False, host_details=None):
        if use_local_only:
            argv = [str(a) for a in local_cmd]
        else:
            # What the host's shell receives: OpenSSH joins the arguments with spaces.
            argv = shlex.split(" ".join(str(a) for a in remote_cmd))
        self.calls.append(argv)
        return self.respond(argv)

    def ssh(self, host, user, password, command, timeout=None):
        argv = shlex.split(command[0]) if len(command) == 1 else list(command)
        self.calls.append(argv)
        return self.respond(argv)

    def commands(self):
        return [" ".join(c) for c in self.calls]


@pytest.fixture(autouse=True)
def quiet_logging():
    """Silence logging while a command runs under CliRunner.

    With `log_cli = true` (pytest.ini), each log record makes pytest suspend
    and resume its own capture, which puts pytest's stream back in place of
    CliRunner's: everything the command prints afterwards is lost from
    `result.output`. These tests check output, not logs.
    """
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)


@pytest.fixture
def remote():
    """Patch every way lws.py reaches a host; yield the recorder."""
    def make(responses=None, default=None, local=False):
        rec = Recorder(responses, default)
        cfg = {**CONFIG, "use_local_only": local}
        patches = [
            patch.dict(lws.config, cfg, clear=True),
            patch.object(lws, "run_argv", side_effect=rec.argv),
            patch.object(lws, "run_proxmox_command", side_effect=rec.proxmox),
            patch.object(lws, "run_ssh_command", side_effect=rec.ssh),
            patch.object(lws, "load_config", return_value=cfg),
            patch("time.sleep"),
        ]
        for p in patches:
            p.start()
        make.patches.extend(patches)
        return rec
    make.patches = []
    yield make
    for p in reversed(make.patches):
        p.stop()


def run(*args, input=None):
    return CliRunner().invoke(lws.lws, list(args), input=input, catch_exceptions=False)


class TestLxcExec:
    def test_command_is_one_argv_for_the_container(self, remote):
        rec = remote()
        result = run("lxc", "exec", "100", "apt-get update && apt-get -y upgrade")
        assert result.exit_code == 0
        assert rec.calls == [["pct", "exec", "100", "--", "apt-get", "update", "&&", "apt-get", "-y", "upgrade"]]

    def test_goes_through_run_argv_so_the_host_shell_cannot_split_it(self, remote):
        """The real run_argv quotes `&&`; a regression to run_proxmox_command would not."""
        rec = remote()
        run("lxc", "exec", "100", "echo hi; reboot")
        assert lws.run_argv.called
        assert ["pct", "exec", "100", "--", "echo", "hi;", "reboot"] in rec.calls

    def test_accepts_the_argument_order_the_api_sends(self, remote):
        """api.py sends `lxc exec --region R -- <id> <command>`."""
        rec = remote()
        result = run("lxc", "exec", "--region", "eu-south-1", "--az", "az1", "--", "100", "df -h /")
        assert result.exit_code == 0, result.output
        assert rec.calls == [["pct", "exec", "100", "--", "df", "-h", "/"]]


class TestPxExec:
    def test_options_of_the_command_after_the_separator(self, remote):
        """api.py sends `px exec --region R -- <command>`; `-h` belongs to df."""
        rec = remote()
        result = run("px", "exec", "--region", "eu-south-1", "--", "df", "-h", "/var/lib/vz")
        assert result.exit_code == 0, result.output
        assert rec.calls == [["df", "-h", "/var/lib/vz"]]


class TestPxUpdate:
    def test_upgrades_every_configured_host_after_confirmation(self, remote):
        rec = remote()
        result = run("px", "update", input="y\n")
        assert result.exit_code == 0, result.output
        upgrades = [c for c in rec.calls if c[:2] == ["sh", "-c"]]
        assert len(upgrades) == 3
        assert "dist-upgrade" in upgrades[0][2]

    def test_limit_to_one_zone(self, remote):
        rec = remote()
        result = run("px", "update", "--region", "eu-south-1", "--az", "az2", "--yes")
        assert result.exit_code == 0, result.output
        assert len(rec.calls) == 1

    def test_declining_runs_nothing(self, remote):
        rec = remote()
        result = run("px", "update", input="n\n")
        assert result.exit_code == 1
        assert rec.calls == []

    def test_failure_on_one_host_exits_non_zero(self, remote):
        rec = remote(default=fail("E: dpkg was interrupted"))
        result = run("px", "update", "--region", "lab", "--yes")
        assert result.exit_code == 1
        assert "lab/pve-lab" in result.output
        assert len(rec.calls) == 1


class TestHealthCheck:
    def test_reads_cpu_from_top_output_without_a_remote_pipe(self, remote):
        top = "top - 10:00:00 up 1 day\n%Cpu(s):  2.0 us,  1.0 sy,  0.0 ni, 97.0 id,  0.0 wa\n"
        free = "              total        used\nMem:           1024         256        768\n"
        df = "Filesystem Size Used Avail Use% Mounted\n/dev/x 8G 2G 6G 25% /\n"
        rec = remote([
            ("pct status", ok("status: running")),
            ("pct exec 100 -- top", ok(top)),
            ("pct exec 100 -- free", ok(free)),
            ("pct exec 100 -- df", ok(df)),
        ], default=ok("Server: 1.1.1.1\nAddress: 1.1.1.1#53"))
        result = run("lxc", "health-check", "100")
        assert "CPU usage is normal: 3.0%" in result.output
        assert not any("|" in c for c in rec.calls)

    def test_fix_never_kills_processes(self, remote):
        top = "%Cpu(s): 95.0 us,  5.0 sy,  0.0 ni,  0.0 id\n"
        rec = remote([("pct status", ok("status: running")), ("pct exec 100 -- top", ok(top))])
        run("lxc", "health-check", "100", "--fix")
        assert not any("pkill" in c for c in rec.commands())


def pvesh_get(path, payload):
    """A canned answer for `pvesh get <path> --output-format json`."""
    import json
    return (f"pvesh get {path} --output-format json", ok(json.dumps(payload)))


class TestSecurityGroups:
    def test_rule_add_uses_the_proxmox_api(self, remote):
        rec = remote()
        result = run("px", "security-group-rule-add", "web", "--direction", "IN", "--destination-port", "443")
        assert result.exit_code == 0, result.output
        assert rec.calls == [["pvesh", "create", "/cluster/firewall/groups/web", "--enable", "1",
                              "--type", "in", "--action", "ACCEPT", "--proto", "tcp", "--dport", "443"]]

    def test_rule_rm_removes_only_the_exact_rule(self, remote):
        rules = [
            {"pos": 0, "type": "in", "action": "ACCEPT", "proto": "tcp", "dport": "443"},
            {"pos": 1, "type": "in", "action": "ACCEPT", "proto": "tcp", "dport": "4430"},
            {"pos": 2, "type": "in", "action": "ACCEPT", "proto": "tcp", "dport": "443", "source": "10.0.0.0/8"},
        ]
        rec = remote([pvesh_get("/cluster/firewall/groups/web", rules)])
        result = run("px", "security-group-rule-rm", "web", "--direction", "IN", "--destination-port", "443")
        assert result.exit_code == 0, result.output
        deletes = [c for c in rec.calls if c[1:2] == ["delete"]]
        assert deletes == [["pvesh", "delete", "/cluster/firewall/groups/web/0"]]

    def test_rule_rm_with_a_cidr(self, remote):
        rules = [{"pos": 3, "type": "in", "action": "ACCEPT", "proto": "tcp", "dport": "22", "source": "10.0.0.0/8"}]
        rec = remote([pvesh_get("/cluster/firewall/groups/web", rules)])
        result = run("px", "security-group-rule-rm", "web", "--direction", "IN",
                     "--source-ip", "10.0.0.0/8", "--destination-port", "22")
        assert result.exit_code == 0, result.output
        assert ["pvesh", "delete", "/cluster/firewall/groups/web/3"] in rec.calls

    def test_rule_rm_without_a_match_fails(self, remote):
        remote([pvesh_get("/cluster/firewall/groups/web", [])])
        result = run("px", "security-group-rule-rm", "web", "--direction", "OUT")
        assert result.exit_code == 1
        assert "No rule" in result.output

    def test_group_with_rules_is_kept_without_force(self, remote):
        rec = remote([pvesh_get("/cluster/firewall/groups/web", [{"pos": 0, "type": "in", "action": "ACCEPT"}])])
        result = run("px", "security-group-rm", "web")
        assert result.exit_code == 1
        assert not any(c[1:2] == ["delete"] for c in rec.calls)

    def test_force_deletes_rules_from_the_last_then_the_group(self, remote):
        rules = [{"pos": 0}, {"pos": 1}, {"pos": 2}]
        rec = remote([pvesh_get("/cluster/firewall/groups/web", rules)])
        result = run("px", "security-group-rm", "web", "--force")
        assert result.exit_code == 0, result.output
        deletes = [c[2] for c in rec.calls if c[1:2] == ["delete"]]
        assert deletes == ["/cluster/firewall/groups/web/2", "/cluster/firewall/groups/web/1",
                           "/cluster/firewall/groups/web/0", "/cluster/firewall/groups/web"]

    def test_attach_adds_an_enabled_group_reference(self, remote):
        rec = remote([
            ("hostname", ok("pve1\n")),
            pvesh_get("/cluster/firewall/groups", [{"group": "web"}]),
            pvesh_get("/nodes/pve1/lxc/100/firewall/rules", []),
            pvesh_get("/cluster/firewall/options", {"enable": 1}),
            pvesh_get("/nodes/pve1/lxc/100/firewall/options", {"enable": 1}),
        ])
        result = run("px", "security-group-attach", "web", "100")
        assert result.exit_code == 0, result.output
        assert ["pvesh", "create", "/nodes/pve1/lxc/100/firewall/rules",
                "--type", "group", "--action", "web", "--enable", "1"] in rec.calls
        assert "disabled" not in result.output

    def test_attach_turns_on_an_existing_disabled_reference(self, remote):
        """Earlier versions wrote `|GROUP web`, which Proxmox reads as disabled."""
        rec = remote([
            ("hostname", ok("pve1\n")),
            pvesh_get("/cluster/firewall/groups", [{"group": "web"}]),
            pvesh_get("/nodes/pve1/lxc/100/firewall/rules",
                      [{"pos": 0, "type": "group", "action": "web", "enable": 0}]),
            pvesh_get("/cluster/firewall/options", {"enable": 1}),
            pvesh_get("/nodes/pve1/lxc/100/firewall/options", {"enable": 1}),
        ])
        result = run("px", "security-group-attach", "web", "100")
        assert result.exit_code == 0, result.output
        assert ["pvesh", "set", "/nodes/pve1/lxc/100/firewall/rules/0", "--enable", "1"] in rec.calls
        assert not any(c[:2] == ["pvesh", "create"] for c in rec.calls)

    def test_attach_warns_when_the_firewall_is_off(self, remote):
        remote([
            ("hostname", ok("pve1\n")),
            pvesh_get("/cluster/firewall/groups", [{"group": "web"}]),
            pvesh_get("/nodes/pve1/lxc/100/firewall/rules", []),
            pvesh_get("/cluster/firewall/options", {}),
            pvesh_get("/nodes/pve1/lxc/100/firewall/options", {}),
        ])
        result = run("px", "security-group-attach", "web", "100")
        assert "datacenter firewall is disabled" in result.output
        assert "--enable-firewall" in result.output

    def test_enable_firewall_sets_options_and_nic_flag(self, remote):
        rec = remote([
            ("hostname", ok("pve1\n")),
            pvesh_get("/cluster/firewall/groups", [{"group": "web"}]),
            pvesh_get("/nodes/pve1/lxc/100/firewall/rules", []),
            pvesh_get("/nodes/pve1/lxc/100/config", {"net0": "name=eth0,bridge=vmbr0,ip=dhcp", "hostname": "web"}),
            pvesh_get("/cluster/firewall/options", {"enable": 1}),
            pvesh_get("/nodes/pve1/lxc/100/firewall/options", {"enable": 1}),
        ])
        result = run("px", "security-group-attach", "web", "100", "--enable-firewall")
        assert result.exit_code == 0, result.output
        assert ["pvesh", "set", "/nodes/pve1/lxc/100/firewall/options", "--enable", "1"] in rec.calls
        assert ["pct", "set", "100", "--net0", "name=eth0,bridge=vmbr0,ip=dhcp,firewall=1"] in rec.calls

    def test_attach_unknown_group_fails(self, remote):
        remote([("hostname", ok("pve1\n")), pvesh_get("/cluster/firewall/groups", [{"group": "db"}])])
        result = run("px", "security-group-attach", "web", "100")
        assert result.exit_code == 1
        assert "does not exist" in result.output

    def test_detach_removes_only_that_group(self, remote):
        rules = [{"pos": 0, "type": "group", "action": "webserver"}, {"pos": 1, "type": "group", "action": "web"}]
        rec = remote([("hostname", ok("pve1\n")), pvesh_get("/nodes/pve1/lxc/100/firewall/rules", rules)])
        result = run("px", "security-group-detach", "web", "100")
        assert result.exit_code == 0, result.output
        deletes = [c for c in rec.calls if c[1:2] == ["delete"]]
        assert deletes == [["pvesh", "delete", "/nodes/pve1/lxc/100/firewall/rules/1"]]


VZDUMP_LOG = ("INFO: starting new backup job: vzdump 100 --mode snapshot --compress zstd --dumpdir /var/lib/vz/dump\n"
              "INFO: creating vzdump archive '/var/lib/vz/dump/vzdump-lxc-100-2026_10_10-08_00_00.tar.zst'\n"
              "INFO: Finished Backup of VM 100 (00:00:42)\n")


class TestBackups:
    def test_backup_create_uses_valid_vzdump_options(self, remote):
        rec = remote([("vzdump", ok(stderr=VZDUMP_LOG))])
        result = run("lxc", "backup-create", "100")
        assert result.exit_code == 0, result.output
        vzdump = next(c for c in rec.calls if c[0] == "vzdump")
        assert vzdump == ["vzdump", "100", "--mode", "snapshot", "--compress", "zstd", "--dumpdir", "/var/lib/vz/dump"]
        assert "vzdump-lxc-100-2026_10_10-08_00_00.tar.zst" in result.output

    def test_backup_create_to_a_storage(self, remote):
        rec = remote([("vzdump", ok(VZDUMP_LOG))])
        run("lxc", "backup-create", "100", "--storage", "backups", "--mode", "stop", "--compress", "none")
        vzdump = next(c for c in rec.calls if c[0] == "vzdump")
        assert vzdump == ["vzdump", "100", "--mode", "stop", "--compress", "0", "--storage", "backups"]
        assert not any(c[0] == "mkdir" for c in rec.calls)

    def test_backup_create_failure_exits_non_zero(self, remote):
        remote([("vzdump", fail("ERROR: Backup of VM 100 failed"))])
        result = run("lxc", "backup-create", "100")
        assert result.exit_code == 1

    def test_deprecated_compress_level_is_ignored_with_a_warning(self, remote):
        rec = remote([("vzdump", ok(VZDUMP_LOG))])
        result = run("lxc", "backup-create", "100", "--compress-level", "6")
        assert "--compress-level is ignored" in result.output
        vzdump = next(c for c in rec.calls if c[0] == "vzdump")
        assert "6" not in vzdump

    def test_restore_over_an_existing_container_never_deletes_the_backup(self, remote):
        archive = "/var/lib/vz/dump/vzdump-lxc-100-2026_10_10-08_00_00.tar.zst"
        rec = remote([("pct status", ok("status: running"))])
        result = run("lxc", "backup-restore", "100", "--backup-file", archive, "--force")
        assert result.exit_code == 0, result.output
        assert ["pct", "stop", "100"] in rec.calls
        assert ["pct", "restore", "100", archive, "--storage", "local-lvm", "--force", "1"] in rec.calls
        assert not any(c[0] == "rm" for c in rec.calls)
        assert ["pct", "start", "100"] in rec.calls

    def test_restore_to_a_new_id_does_not_force(self, remote):
        archive = "local:backup/vzdump-lxc-100-2026_10_10-08_00_00.tar.zst"
        rec = remote([("pct status", fail("CT 200 does not exist"))])
        result = run("lxc", "backup-restore", "200", "--backup-file", archive, "--force", "--no-start")
        assert result.exit_code == 0, result.output
        assert ["pct", "restore", "200", archive, "--storage", "local-lvm"] in rec.calls
        assert not any(c[:2] == ["pct", "start"] for c in rec.calls)

    def test_restore_storage_option_overrides_default_storage(self, remote):
        archive = "local:backup/vzdump-lxc-100-2026_10_10-08_00_00.tar.zst"
        rec = remote([("pct status", fail("does not exist", 2))])
        run("lxc", "backup-restore", "200", "--backup-file", archive, "--storage", "local-zfs", "--force")
        assert ["pct", "restore", "200", archive, "--storage", "local-zfs"] in rec.calls

    def test_restore_without_any_storage_is_refused(self, remote):
        """pct restore would put the disk on 'local', which cannot hold container disks by default."""
        rec = remote()
        with patch.dict(lws.config, {"default_storage": None}):
            result = CliRunner().invoke(lws.lws, ["lxc", "backup-restore", "200", "--backup-file",
                                                  "/var/lib/vz/dump/x.tar.zst", "--force"])
        assert result.exit_code == 2
        assert "--storage" in result.output
        assert rec.calls == []

    def test_restore_asks_before_replacing(self, remote):
        rec = remote([("pct status", ok("status: stopped"))])
        result = run("lxc", "backup-restore", "100", "--backup-file", "/var/lib/vz/dump/x.tar.zst", input="n\n")
        assert result.exit_code == 1
        assert "destroyed" in result.output
        assert not any(c[:2] == ["pct", "restore"] for c in rec.calls)

    def test_restore_of_a_missing_file_fails(self, remote):
        remote([("pct status", fail()), ("test -f", fail())])
        result = run("lxc", "backup-restore", "100", "--backup-file", "/nope.tar.zst", "--force")
        assert result.exit_code == 1
        assert "not found" in result.output

    def test_uploaded_copy_is_removed_but_the_local_file_is_kept(self, remote, tmp_path):
        local = tmp_path / "vzdump-lxc-100-2026_10_10-08_00_00.tar.zst"
        local.write_bytes(b"x")
        rec = remote([("pct status", fail())])
        with patch.object(lws, "run_scp_command", return_value=ok()) as scp:
            result = run("lxc", "backup-restore", "100", "--backup-file", str(local), "--force")
        assert result.exit_code == 0, result.output
        remote_copy = scp.call_args.args[2].split(":", 1)[1]
        assert remote_copy.endswith(local.name)
        assert ["rm", "-f", remote_copy] in rec.calls
        assert local.exists()


PCT_CONFIG = """arch: amd64
cpulimit: 2
hostname: web
memory: 2048
net0: name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:00:01,ip=dhcp,type=veth
ostype: debian
rootfs: local-lvm:vm-100-disk-0,size=8G
swap: 512
"""


class TestHostAndConfigBackups:
    def test_px_backup_creates_the_directory_on_the_host(self, remote, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        rec = remote()
        result = run("px", "backup", "/root/pve-backups")
        assert result.exit_code == 0, result.output
        assert rec.calls == [["mkdir", "-p", "/root/pve-backups"],
                             ["tar", "-czf", "/root/pve-backups/proxmox-backup.tar.gz", "/etc/pve"]]
        assert not (tmp_path / "root").exists()

    def test_px_backup_failure_exits_non_zero(self, remote):
        remote([("tar", fail("tar: /root/x: Cannot open"))])
        assert run("px", "backup", "/root/pve-backups").exit_code == 1

    def test_conf_backup_copies_the_file_with_its_comments(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "config.yaml").write_text("# hosts\nregions: {}\n")
        result = run("conf", "backup", "copy.yaml")
        assert result.exit_code == 0, result.output
        assert (tmp_path / "copy.yaml").read_text() == "# hosts\nregions: {}\n"
        assert (tmp_path / "copy.yaml").stat().st_mode & 0o777 == 0o600

    def test_conf_backup_without_config_yaml_fails(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = run("conf", "backup", "copy.yaml")
        assert result.exit_code == 1
        assert not (tmp_path / "copy.yaml").exists()


class TestScaling:
    def test_scale_uses_pct_set_and_pct_resize(self, remote):
        rec = remote([("pct config", ok(PCT_CONFIG))])
        result = run("lxc", "scale", "100", "--memory", "4096", "--cpucores", "2", "--storage-size", "16G",
                     "--net-limit", "50")
        assert result.exit_code == 0, result.output
        assert ["pct", "set", "100", "--memory", "4096", "--cores", "2", "--net0",
                "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:00:01,ip=dhcp,type=veth,rate=50"] in rec.calls
        assert ["pct", "resize", "100", "rootfs", "16G"] in rec.calls
        assert not any("--rootfs" in c for c in rec.calls)

    def test_a_plain_number_is_gib(self, remote):
        rec = remote()
        run("lxc", "scale", "100", "--storage-size", "+8")
        assert ["pct", "resize", "100", "rootfs", "+8G"] in rec.calls

    def test_disk_bandwidth_options_are_refused(self, remote):
        result = CliRunner().invoke(lws.lws, ["lxc", "scale", "100", "--disk-read-limit", "50"])
        assert result.exit_code == 2
        assert "no disk bandwidth limits" in result.output

    def test_failure_exits_non_zero(self, remote):
        remote(default=fail("unable to parse"))
        result = run("lxc", "scale", "100", "--memory", "4096")
        assert result.exit_code == 1

    def test_scale_check_with_a_cpulimit_only_container(self, remote):
        lscpu = "Architecture: x86_64\nCPU(s): 16\nOn-line CPU(s) list: 0-15\n"
        free = "              total        used        free\nMem:          64000       10000       54000\n"
        cfg = {**CONFIG, "scaling": {"lxc_cpu": {"min_threshold": 30, "max_threshold": 80},
                                     "lxc_memory": {"min_threshold": 0.40, "max_threshold": 0.70}}}
        remote([("lscpu", ok(lscpu)), ("free", ok(free)), ("pct config", ok(PCT_CONFIG))])
        with patch.object(lws, "scale_check_load_config", return_value=cfg):
            result = run("lxc", "scale-check", "100")
        assert result.exit_code == 0, result.output
        assert "2 cores" in result.output and "8 GB storage" in result.output
        # 30 is read as 30%: 2 cores < 16 * 0.30, so one more step is suggested, not 20x more.
        assert "increasing CPU cores to 3 (current: 2)" in result.output

    def _scale_check(self, remote, pct_config, scaling=None):
        lscpu = "CPU(s): 16\n"
        free = "              total        used        free\nMem:          64000       10000       54000\n"
        cfg = {**CONFIG, "scaling": scaling or {}}
        remote([("lscpu", ok(lscpu)), ("free", ok(free)), ("pct config", ok(pct_config))])
        with patch.object(lws, "scale_check_load_config", return_value=cfg):
            return run("lxc", "scale-check", "100")

    def test_scale_check_hint_uses_the_option_that_limits_the_container(self, remote):
        """A cpulimit-only container is changed with --cpulimit; --cpucores alone would not raise its cap."""
        result = self._scale_check(remote, PCT_CONFIG)
        assert result.exit_code == 0, result.output
        assert "lws lxc scale 100 --cpulimit 3 --memory 2368 --storage-size 23G" in result.output

    def test_scale_check_hint_uses_cpucores_when_cores_is_set(self, remote):
        result = self._scale_check(remote, PCT_CONFIG.replace("cpulimit: 2", "cores: 2"))
        assert "lws lxc scale 100 --cpucores 3 " in result.output

    def test_scale_check_never_suggests_a_smaller_disk(self, remote):
        """Proxmox cannot shrink a container's disk, so lxc scale could not apply it."""
        result = self._scale_check(remote, PCT_CONFIG.replace("size=8G", "size=900G"))
        assert result.exit_code == 0, result.output
        assert "900 GB storage" in result.output
        assert "storage to" not in result.output and "--storage-size" not in result.output

    def test_scale_check_decrease_stays_within_the_limits(self, remote):
        """49152 MB is above 70% of the host and above max_memory_mb: suggest the maximum, not 48960."""
        result = self._scale_check(remote, PCT_CONFIG.replace("memory: 2048", "memory: 49152"),
                                   {"limits": {"max_memory_mb": 32768}})
        assert "decreasing memory to 32768 MB (current: 49152 MB)" in result.output

    def test_resources_describes_a_cpulimit_only_container(self, remote):
        remote([("pct status", ok("status: running")), ("pct config", ok(PCT_CONFIG))], default=fail())
        result = run("lxc", "resources", "100", "--count", "1")
        assert "CPU: limited to the time of 2 CPUs, Memory: 2048 MB" in result.output
        assert "None" not in result.output


class TestDocker:
    RUNNING = ("pct status", ok("status: running"))

    def test_setup_installs_from_apt_in_the_container(self, remote):
        rec = remote([
            self.RUNNING,
            ("pct config", ok("features: nesting=1\nhostname: web\n")),
            ("pct exec 100 -- docker --version", fail()),
        ])
        result = run("app", "setup", "100")
        assert result.exit_code == 0, result.output
        install = next(c for c in rec.calls if c[-3:-1] == ["sh", "-c"])
        assert install[:4] == ["pct", "exec", "100", "--"]
        assert "apt-get install -y docker.io" in install[-1]
        assert "docker-compose-v2" in install[-1]

    def test_setup_warns_without_nesting(self, remote):
        remote([self.RUNNING, ("pct config", ok("hostname: web\n")), ("pct exec 100 -- docker --version", fail())])
        result = run("app", "setup", "100")
        assert "--enable-nesting" in result.output

    def test_enable_nesting_on_an_unprivileged_container_adds_keyctl(self, remote):
        rec = remote([
            self.RUNNING,
            ("pct config", ok("unprivileged: 1\nfeatures: fuse=1\n")),
            ("pct exec 100 -- docker --version", fail()),
        ])
        result = run("app", "setup", "100", "--enable-nesting")
        assert result.exit_code == 0, result.output
        assert ["pct", "set", "100", "--features", "fuse=1,nesting=1,keyctl=1"] in rec.calls
        assert ["pct", "reboot", "100"] in rec.calls

    def test_setup_refuses_a_stopped_container(self, remote):
        remote([("pct status", ok("status: stopped"))])
        result = run("app", "setup", "100")
        assert result.exit_code == 1

    def test_run_passes_docker_arguments_one_by_one(self, remote):
        rec = remote([self.RUNNING])
        result = run("app", "run", "100", "--", "-d", "-p", "80:80", "nginx")
        assert result.exit_code == 0, result.output
        assert ["pct", "exec", "100", "--", "docker", "run", "-d", "-p", "80:80", "nginx"] in rec.calls

    def test_deploy_install_places_the_file_and_uses_a_project_name(self, remote, tmp_path):
        compose_file = tmp_path / "docker-compose.yml"
        compose_file.write_text("services:\n  wiki:\n    image: requarks/wiki:2\n")
        rec = remote([self.RUNNING])
        with patch.object(lws, "run_scp_command", return_value=ok()):
            result = run("app", "deploy", "install", "100", "--compose-file", str(compose_file))
        assert result.exit_code == 0, result.output
        push = next(c for c in rec.calls if c[:2] == ["pct", "push"])
        assert push[-1] == "/opt/lws/apps/wiki/docker-compose.yml"
        assert ["pct", "exec", "100", "--", "docker", "compose", "-p", "wiki", "-f",
                "/opt/lws/apps/wiki/docker-compose.yml", "up", "-d"] in rec.calls

    def test_deploy_falls_back_to_docker_compose_v1(self, remote, tmp_path):
        compose_file = tmp_path / "c.yml"
        compose_file.write_text("services:\n  web:\n    image: nginx\n")
        rec = remote([self.RUNNING, ("pct exec 100 -- docker compose version", fail())])
        with patch.object(lws, "run_scp_command", return_value=ok()):
            run("app", "deploy", "install", "100", "--compose-file", str(compose_file))
        assert any(c[4:5] == ["docker-compose"] and c[-2:] == ["up", "-d"] for c in rec.calls)

    def test_deploy_auto_start_installs_a_unit_inside_the_container(self, remote, tmp_path):
        compose_file = tmp_path / "c.yml"
        compose_file.write_text("services:\n  web:\n    image: nginx\n")
        rec = remote([self.RUNNING])
        with patch.object(lws, "run_scp_command", return_value=ok()):
            result = run("app", "deploy", "install", "100", "--compose-file", str(compose_file), "--auto-start")
        assert result.exit_code == 0, result.output
        assert any(c[:2] == ["pct", "push"] and c[-1] == "/etc/systemd/system/lws-web.service" for c in rec.calls)
        assert any(c[-1] == "systemctl daemon-reload && systemctl enable lws-web.service" for c in rec.calls)

    def test_remove_only_removes_installed_packages(self, remote):
        rec = remote()
        result = run("app", "remove", "100")
        assert result.exit_code == 0, result.output
        script = rec.calls[-1][-1]
        assert "dpkg -s" in script and "docker-compose-v2" in script

    def test_logs_do_not_follow_forever(self, remote):
        rec = remote()
        result = run("app", "logs", "100", "web", "--follow", "--tail", "50")
        assert result.exit_code == 0, result.output
        assert ["pct", "exec", "100", "--", "docker", "logs", "--tail", "50", "web"] in rec.calls


class TestLxcRunCloneMigrate:
    def test_run_with_features_and_a_single_net0(self, remote):
        pct_list = "VMID       Status     Lock         Name\n100        running                 web\n"
        rec = remote([("pct list", ok(pct_list))])
        # --size choices are read from config.yaml when lws.py is imported.
        size = next(p for p in lws.lws.commands["lxc"].commands["run"].params if p.name == "size")
        with patch.object(size.type, "choices", ["small"]), \
                patch.object(lws, "get_next_vmid", return_value=101), \
                patch.object(lws, "is_container_locked", return_value=False):
            result = run("lxc", "run", "--image-id", "local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst",
                         "--size", "small", "--features", "nesting=1", "--unprivileged", "--dhcp",
                         "--storage-size", "24G", "--dns", "1.1.1.1,9.9.9.9")
        assert result.exit_code == 0, result.output
        create = next(c for c in rec.calls if c[:2] == ["pct", "create"])
        assert create.count("--net0") == 1
        assert create[create.index("--net0") + 1] == "name=eth0,bridge=vmbr0,ip=dhcp"
        assert create[create.index("--rootfs") + 1] == "local-lvm:24"
        assert create[create.index("--features") + 1] == "nesting=1"
        assert create[create.index("--unprivileged") + 1] == "1"
        assert create[create.index("--nameserver") + 1] == "1.1.1.1 9.9.9.9"

    def _run_with_password(self, remote, password, pct_responses=()):
        pct_list = "VMID       Status     Lock         Name\n100        running                 web\n"
        rec = remote([("pct list", ok(pct_list)), *pct_responses])
        size = next(p for p in lws.lws.commands["lxc"].commands["run"].params if p.name == "size")
        with patch.object(size.type, "choices", ["small"]), \
                patch.object(lws, "get_next_vmid", return_value=101), \
                patch.object(lws, "is_container_locked", return_value=False):
            result = CliRunner().invoke(lws.lws, ["lxc", "run", "--image-id", "local:vztmpl/debian-12.tar.zst",
                                                  "--size", "small", "--password", password])
        return rec, result

    def test_run_sets_the_password_through_stdin_not_the_command_line(self, remote):
        """On pct create's command line the password showed in the host's process list and the logs."""
        rec, result = self._run_with_password(remote, "s3cret pass")
        assert result.exit_code == 0, result.output
        assert not any("s3cret" in part for call in rec.calls for part in call)
        chpasswd = rec.calls.index(["pct", "exec", "101", "--", "chpasswd"])
        assert rec.inputs[chpasswd] == "root:s3cret pass\n"
        assert chpasswd > rec.calls.index(["pct", "start", "101"])

    def test_run_reports_when_the_password_cannot_be_set(self, remote):
        rec, result = self._run_with_password(remote, "pw", [("pct start", fail("start failed"))])
        assert "root password was not set" in result.output
        assert ["pct", "exec", "101", "--", "chpasswd"] not in rec.calls

    def test_run_refuses_a_password_with_a_line_break(self, remote):
        rec, result = self._run_with_password(remote, "a\nroot2:x")
        assert result.exit_code == 2
        assert not any(c[:2] == ["pct", "create"] for c in rec.calls)

    def test_clone_removes_its_temporary_snapshot(self, remote):
        rec = remote()
        result = run("lxc", "clone", "100", "200", "--full", "--no-start")
        assert result.exit_code == 0, result.output
        snap = next(c for c in rec.calls if c[:2] == ["pct", "snapshot"])[3]
        assert ["pct", "delsnapshot", "100", snap] in rec.calls

    def test_clone_to_another_node_starts_it_there(self, remote):
        rec = remote()
        run("lxc", "clone", "100", "200", "--target-host", "pve2")
        assert ["pvesh", "create", "/nodes/pve2/lxc/200/status/start"] in rec.calls

    def test_migrate_restart(self, remote):
        rec = remote()
        result = run("lxc", "migrate", "100", "--target-host", "pve2", "--restart")
        assert result.exit_code == 0, result.output
        assert ["pct", "migrate", "100", "pve2", "--restart"] in rec.calls
