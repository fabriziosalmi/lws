"""
Unit tests for lws_core/proxmox.py

Tests cover:
- Local command execution
- Remote command execution via SSH
- Error handling for command execution
- Validation of command parameters
"""

import pytest
import subprocess
from unittest.mock import patch, Mock, MagicMock
from lws_core.proxmox import execute_command, run_proxmox_command


class TestExecuteCommand:
    """Tests for the execute_command function."""

    @pytest.mark.unit
    @pytest.mark.proxmox
    def test_execute_local_command_success(self):
        """Test successful local command execution."""
        cmd = ["pct", "list"]
        
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "VMID Status"
        mock_result.stderr = ""
        
        with patch('subprocess.run', return_value=mock_result) as mock_run:
            result = execute_command(cmd, use_local_only=True)
            
            assert result.returncode == 0
            assert "VMID" in result.stdout
            mock_run.assert_called_once()
            assert mock_run.call_args[0][0] == cmd

    @pytest.mark.unit
    @pytest.mark.proxmox
    def test_execute_local_command_failure(self):
        """Test local command execution failure."""
        cmd = ["pct", "destroy", "99999"]
        
        # Create a CalledProcessError
        error = subprocess.CalledProcessError(1, cmd, stderr="VM not found")
        
        with patch('subprocess.run', side_effect=error) as mock_run:
            result = execute_command(cmd, use_local_only=True)
            
            # Should return the error
            assert isinstance(result, subprocess.CalledProcessError)

    @pytest.mark.unit
    @pytest.mark.proxmox
    def test_execute_local_command_unexpected_error(self):
        """Test handling of unexpected errors during local execution."""
        cmd = ["pct", "list"]
        
        with patch('subprocess.run', side_effect=Exception("Unexpected error")):
            result = execute_command(cmd, use_local_only=True)
            
            assert result.returncode == 1
            assert "Unexpected error" in result.stderr

    @pytest.mark.unit
    @pytest.mark.proxmox
    def test_execute_remote_command_success(self, mock_ssh_host_details):
        """Test successful remote command execution."""
        cmd = ["pct", "list"]
        
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "VMID Status"
        mock_result.stderr = ""
        
        with patch('lws_core.proxmox.run_ssh_command', return_value=mock_result) as mock_ssh:
            result = execute_command(
                cmd,
                use_local_only=False,
                host_details=mock_ssh_host_details
            )
            
            assert result.returncode == 0
            assert "VMID" in result.stdout
            
            # Verify SSH was called with correct parameters
            mock_ssh.assert_called_once_with(
                mock_ssh_host_details['host'],
                mock_ssh_host_details['user'],
                mock_ssh_host_details['ssh_password'],
                cmd
            )

    @pytest.mark.unit
    @pytest.mark.proxmox
    def test_execute_remote_command_failure(self, mock_ssh_host_details):
        """Test remote command execution failure."""
        cmd = ["pct", "destroy", "99999"]
        
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "VM not found"
        
        with patch('lws_core.proxmox.run_ssh_command', return_value=mock_result):
            result = execute_command(
                cmd,
                use_local_only=False,
                host_details=mock_ssh_host_details
            )
            
            assert result.returncode == 1
            assert "not found" in result.stderr

    @pytest.mark.unit
    @pytest.mark.proxmox
    def test_execute_command_empty_command(self):
        """Test execution with empty command."""
        with pytest.raises(ValueError) as exc_info:
            execute_command([], use_local_only=True)
        
        assert "cannot be empty" in str(exc_info.value).lower()

    @pytest.mark.unit
    @pytest.mark.proxmox
    def test_execute_command_none_command(self):
        """Test execution with None command."""
        with pytest.raises(ValueError) as exc_info:
            execute_command(None, use_local_only=True)
        
        assert "cannot be empty" in str(exc_info.value).lower()

    @pytest.mark.unit
    @pytest.mark.proxmox
    def test_execute_remote_without_host_details(self):
        """Test remote execution without host details."""
        cmd = ["pct", "list"]
        
        with pytest.raises(ValueError) as exc_info:
            execute_command(cmd, use_local_only=False, host_details=None)
        
        assert "host details" in str(exc_info.value).lower()

    @pytest.mark.unit
    @pytest.mark.proxmox
    def test_execute_command_logs_local(self):
        """Test that local execution is logged."""
        cmd = ["pct", "list"]
        
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "VMID Status"
        mock_result.stderr = ""
        
        with patch('subprocess.run', return_value=mock_result):
            with patch('logging.debug') as mock_log:
                execute_command(cmd, use_local_only=True)
                
                # Should log the command
                assert mock_log.called
                log_messages = [str(call) for call in mock_log.call_args_list]
                assert any('local command' in msg.lower() for msg in log_messages)

    @pytest.mark.unit
    @pytest.mark.proxmox
    def test_execute_command_logs_remote(self, mock_ssh_host_details):
        """Test that remote execution is logged."""
        cmd = ["pct", "list"]
        
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "VMID Status"
        mock_result.stderr = ""
        
        with patch('lws_core.proxmox.run_ssh_command', return_value=mock_result):
            with patch('logging.debug') as mock_log:
                execute_command(
                    cmd,
                    use_local_only=False,
                    host_details=mock_ssh_host_details
                )
                
                # Should log the command
                assert mock_log.called
                log_messages = [str(call) for call in mock_log.call_args_list]
                assert any('remote command' in msg.lower() for msg in log_messages)


class TestRunProxmoxCommand:
    """Tests for the run_proxmox_command function."""

    @pytest.mark.unit
    @pytest.mark.proxmox
    def test_run_local_command(self):
        """Test running a local Proxmox command."""
        local_cmd = ["pct", "list"]
        
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "VMID Status"
        
        with patch('lws_core.proxmox.execute_command', return_value=mock_result) as mock_exec:
            result = run_proxmox_command(
                local_cmd=local_cmd,
                use_local_only=True
            )
            
            assert result.returncode == 0
            mock_exec.assert_called_once_with(local_cmd, True, None)

    @pytest.mark.unit
    @pytest.mark.proxmox
    def test_run_remote_command(self, mock_ssh_host_details):
        """Test running a remote Proxmox command."""
        local_cmd = ["pct", "list"]
        remote_cmd = ["pct", "list"]
        
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "VMID Status"
        
        with patch('lws_core.proxmox.execute_command', return_value=mock_result) as mock_exec:
            result = run_proxmox_command(
                local_cmd=local_cmd,
                remote_cmd=remote_cmd,
                use_local_only=False,
                host_details=mock_ssh_host_details
            )
            
            assert result.returncode == 0
            mock_exec.assert_called_once_with(remote_cmd, False, mock_ssh_host_details)

    @pytest.mark.unit
    @pytest.mark.proxmox
    def test_run_command_uses_local_when_local_only(self):
        """Test that local command is used when use_local_only is True."""
        local_cmd = ["pct", "list", "--local"]
        remote_cmd = ["pct", "list", "--remote"]
        
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "VMID Status"
        
        with patch('lws_core.proxmox.execute_command', return_value=mock_result) as mock_exec:
            run_proxmox_command(
                local_cmd=local_cmd,
                remote_cmd=remote_cmd,
                use_local_only=True
            )
            
            # Should use local_cmd
            assert mock_exec.call_args[0][0] == local_cmd

    @pytest.mark.unit
    @pytest.mark.proxmox
    def test_run_command_uses_remote_when_not_local_only(self, mock_ssh_host_details):
        """Test that remote command is used when use_local_only is False."""
        local_cmd = ["pct", "list", "--local"]
        remote_cmd = ["pct", "list", "--remote"]
        
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "VMID Status"
        
        with patch('lws_core.proxmox.execute_command', return_value=mock_result) as mock_exec:
            run_proxmox_command(
                local_cmd=local_cmd,
                remote_cmd=remote_cmd,
                use_local_only=False,
                host_details=mock_ssh_host_details
            )
            
            # Should use remote_cmd
            assert mock_exec.call_args[0][0] == remote_cmd

    @pytest.mark.unit
    @pytest.mark.proxmox
    def test_run_command_none_local_cmd(self):
        """Test error when local_cmd is None and use_local_only is True."""
        with pytest.raises(ValueError) as exc_info:
            run_proxmox_command(
                local_cmd=None,
                use_local_only=True
            )
        
        assert "cannot be none" in str(exc_info.value).lower()

    @pytest.mark.unit
    @pytest.mark.proxmox
    def test_run_command_none_remote_cmd(self, mock_ssh_host_details):
        """Test error when remote_cmd is None and use_local_only is False."""
        local_cmd = ["pct", "list"]
        
        with pytest.raises(ValueError) as exc_info:
            run_proxmox_command(
                local_cmd=local_cmd,
                remote_cmd=None,
                use_local_only=False,
                host_details=mock_ssh_host_details
            )
        
        assert "cannot be none" in str(exc_info.value).lower()

    @pytest.mark.unit
    @pytest.mark.proxmox
    def test_run_command_defaults_to_local_cmd(self):
        """Test that local_cmd is used when remote_cmd is not provided for local execution."""
        local_cmd = ["pct", "list"]
        
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "VMID Status"
        
        with patch('lws_core.proxmox.execute_command', return_value=mock_result) as mock_exec:
            run_proxmox_command(local_cmd=local_cmd, use_local_only=True)
            
            # Should use local_cmd
            assert mock_exec.call_args[0][0] == local_cmd

    @pytest.mark.unit
    @pytest.mark.proxmox
    def test_run_command_with_different_local_and_remote(self, mock_ssh_host_details):
        """Test with different local and remote commands."""
        local_cmd = ["pct", "list", "--node", "local"]
        remote_cmd = ["pct", "list", "--node", "remote"]
        
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "VMID Status"
        
        with patch('lws_core.proxmox.execute_command', return_value=mock_result) as mock_exec:
            # Test local execution
            run_proxmox_command(
                local_cmd=local_cmd,
                remote_cmd=remote_cmd,
                use_local_only=True
            )
            assert "--node" in mock_exec.call_args[0][0]
            assert "local" in mock_exec.call_args[0][0]
            
            # Test remote execution
            run_proxmox_command(
                local_cmd=local_cmd,
                remote_cmd=remote_cmd,
                use_local_only=False,
                host_details=mock_ssh_host_details
            )
            assert "--node" in mock_exec.call_args[0][0]
            assert "remote" in mock_exec.call_args[0][0]

    @pytest.mark.unit
    @pytest.mark.proxmox
    def test_run_command_returns_result(self):
        """Test that run_proxmox_command returns the command result."""
        local_cmd = ["pct", "list"]
        
        expected_result = Mock()
        expected_result.returncode = 0
        expected_result.stdout = "Test output"
        expected_result.stderr = ""
        
        with patch('lws_core.proxmox.execute_command', return_value=expected_result):
            result = run_proxmox_command(local_cmd=local_cmd, use_local_only=True)
            
            assert result == expected_result
            assert result.stdout == "Test output"

    @pytest.mark.unit
    @pytest.mark.proxmox
    def test_run_command_complex_command(self):
        """Test running a complex command with multiple arguments."""
        local_cmd = ["pct", "set", "10001", "--memory", "2048", "--cores", "4"]
        
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Configuration updated"
        
        with patch('lws_core.proxmox.execute_command', return_value=mock_result) as mock_exec:
            result = run_proxmox_command(local_cmd=local_cmd, use_local_only=True)
            
            assert result.returncode == 0
            # Verify all command parts were passed
            assert mock_exec.call_args[0][0] == local_cmd

    @pytest.mark.unit
    @pytest.mark.proxmox
    def test_run_command_propagates_errors(self):
        """Test that errors from execute_command are propagated."""
        local_cmd = ["pct", "list"]
        
        with patch('lws_core.proxmox.execute_command', side_effect=ValueError("Test error")):
            with pytest.raises(ValueError) as exc_info:
                run_proxmox_command(local_cmd=local_cmd, use_local_only=True)
            
            assert "Test error" in str(exc_info.value)

    @pytest.mark.unit
    @pytest.mark.proxmox
    def test_run_command_with_host_details_local(self, mock_ssh_host_details):
        """Test that host_details are passed through even for local execution."""
        local_cmd = ["pct", "list"]
        
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "VMID Status"
        
        with patch('lws_core.proxmox.execute_command', return_value=mock_result) as mock_exec:
            run_proxmox_command(
                local_cmd=local_cmd,
                use_local_only=True,
                host_details=mock_ssh_host_details
            )
            
            # Verify execute_command was called with use_local_only=True
            assert mock_exec.call_args[0][1] is True  # use_local_only parameter


class TestRunArgv:
    """run_argv gives the remote shell exactly the argument list, as subprocess does locally."""

    @pytest.mark.unit
    def test_remote_command_is_quoted_as_one_string(self):
        from lws_core.proxmox import run_argv
        host = {"host": "pve1", "user": "root", "ssh_password": "pw"}
        with patch('lws_core.proxmox.run_ssh_command') as mock_ssh:
            run_argv(["pct", "exec", "100", "--", "sh", "-c", "apt-get update && apt-get -y upgrade"], False, host)
        command = mock_ssh.call_args.args[3]
        assert command == ["pct exec 100 -- sh -c 'apt-get update && apt-get -y upgrade'"]

    @pytest.mark.unit
    def test_input_text_reaches_stdin_and_not_the_command(self):
        from lws_core.proxmox import run_argv
        host = {"host": "pve1", "user": "root", "ssh_password": "pw"}
        with patch('lws_core.proxmox.run_ssh_command') as mock_ssh:
            run_argv(["pct", "exec", "100", "--", "chpasswd"], False, host, input_text="root:s3cret\n")
        assert mock_ssh.call_args.kwargs == {"input_text": "root:s3cret\n"}
        assert "s3cret" not in mock_ssh.call_args.args[3][0]
        with patch('subprocess.run') as mock_run:
            run_argv(["chpasswd"], True, None, input_text="root:s3cret\n")
        assert mock_run.call_args.kwargs["input"] == "root:s3cret\n"

    @pytest.mark.unit
    def test_shell_operators_in_arguments_stay_arguments(self):
        """`&&` passed as an argument must not become a command separator on the host."""
        import shlex
        from lws_core.proxmox import run_argv
        host = {"host": "pve1", "user": "root", "ssh_password": "pw"}
        argv = ["pct", "exec", "100", "--", "echo", "a", "&&", "reboot"]
        with patch('lws_core.proxmox.run_ssh_command') as mock_ssh:
            run_argv(argv, False, host)
        remote = mock_ssh.call_args.args[3][0]
        assert shlex.split(remote) == argv
        assert "'&&'" in remote

    @pytest.mark.unit
    def test_local_command_is_the_plain_list(self):
        from lws_core.proxmox import run_argv
        with patch('lws_core.proxmox.subprocess.run') as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
            run_argv(["pct", "list"], True, None)
        assert mock_run.call_args.args[0] == ["pct", "list"]
