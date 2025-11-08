"""
Unit tests for lws_core/ssh.py

Tests cover:
- SSH command execution with password authentication
- Retry logic for failed connections
- Timeout handling
- Password sanitization in logs
- Error handling for missing sshpass
"""

import pytest
import subprocess
import time
from unittest.mock import patch, Mock, MagicMock, call
from lws_core.ssh import run_ssh_command


class TestRunSSHCommand:
    """Tests for the run_ssh_command function."""

    @pytest.mark.unit
    @pytest.mark.ssh
    def test_successful_ssh_command(self, mock_sshpass_installed):
        """Test successful SSH command execution."""
        host = "proxmox1.example.com"
        user = "root"
        password = "test_password"
        command = ["pct", "list"]
        
        # Mock successful subprocess.run
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "VMID Status\n10001 running"
        mock_result.stderr = ""
        
        with patch('subprocess.run', return_value=mock_result) as mock_run:
            result = run_ssh_command(host, user, password, command)
            
            # Verify result
            assert result.returncode == 0
            assert "10001" in result.stdout
            
            # Verify subprocess.run was called with correct arguments
            assert mock_run.called
            call_args = mock_run.call_args[0][0]
            assert "sshpass" in call_args
            assert "-p" in call_args
            assert password in call_args
            assert f"{user}@{host}" in call_args
            assert "pct" in call_args
            assert "list" in call_args

    @pytest.mark.unit
    @pytest.mark.ssh
    def test_ssh_command_failure(self, mock_sshpass_installed):
        """Test SSH command that fails."""
        host = "proxmox1.example.com"
        user = "root"
        password = "test_password"
        command = ["pct", "destroy", "99999"]
        
        # Mock failed subprocess.run
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "VM 99999 does not exist"
        
        with patch('subprocess.run', return_value=mock_result):
            result = run_ssh_command(host, user, password, command)
            
            # Verify error result
            assert result.returncode != 0
            assert "does not exist" in result.stderr

    @pytest.mark.unit
    @pytest.mark.ssh
    def test_sshpass_not_installed(self, mock_sshpass_not_installed):
        """Test error when sshpass is not installed."""
        host = "proxmox1.example.com"
        user = "root"
        password = "test_password"
        command = ["pct", "list"]
        
        with pytest.raises(RuntimeError) as exc_info:
            run_ssh_command(host, user, password, command)
        
        assert "sshpass" in str(exc_info.value).lower()

    @pytest.mark.unit
    @pytest.mark.ssh
    def test_connection_timeout(self, mock_sshpass_installed):
        """Test SSH command timeout handling."""
        host = "proxmox1.example.com"
        user = "root"
        password = "test_password"
        command = ["pct", "list"]
        
        with patch('subprocess.run', side_effect=subprocess.TimeoutExpired(cmd=[], timeout=60)):
            result = run_ssh_command(host, user, password, command)
            
            # Verify timeout result
            assert result.returncode == 124  # Timeout exit code
            assert "timed out" in result.stderr.lower()

    @pytest.mark.unit
    @pytest.mark.ssh
    def test_connection_refused_retry(self, mock_sshpass_installed):
        """Test retry logic when connection is refused."""
        host = "proxmox1.example.com"
        user = "root"
        password = "test_password"
        command = ["pct", "list"]
        
        # First two attempts fail with connection refused, third succeeds
        mock_fail = Mock()
        mock_fail.returncode = 255
        mock_fail.stdout = ""
        mock_fail.stderr = "Connection refused"
        
        mock_success = Mock()
        mock_success.returncode = 0
        mock_success.stdout = "VMID Status"
        mock_success.stderr = ""
        
        with patch('subprocess.run', side_effect=[mock_fail, mock_fail, mock_success]) as mock_run:
            with patch('time.sleep'):  # Speed up the test by mocking sleep
                result = run_ssh_command(host, user, password, command)
                
                # Should succeed after retries
                assert result.returncode == 0
                # Should have been called 3 times
                assert mock_run.call_count == 3

    @pytest.mark.unit
    @pytest.mark.ssh
    def test_connection_timeout_retry(self, mock_sshpass_installed):
        """Test retry logic when connection times out."""
        host = "proxmox1.example.com"
        user = "root"
        password = "test_password"
        command = ["pct", "list"]
        
        # First attempt times out, second succeeds
        mock_fail = Mock()
        mock_fail.returncode = 255
        mock_fail.stdout = ""
        mock_fail.stderr = "Connection timed out"
        
        mock_success = Mock()
        mock_success.returncode = 0
        mock_success.stdout = "VMID Status"
        mock_success.stderr = ""
        
        with patch('subprocess.run', side_effect=[mock_fail, mock_success]) as mock_run:
            with patch('time.sleep'):
                result = run_ssh_command(host, user, password, command)
                
                # Should succeed after retry
                assert result.returncode == 0
                # Should have been called 2 times
                assert mock_run.call_count == 2

    @pytest.mark.unit
    @pytest.mark.ssh
    def test_max_retries_exceeded(self, mock_sshpass_installed):
        """Test that retries stop after max attempts."""
        host = "proxmox1.example.com"
        user = "root"
        password = "test_password"
        command = ["pct", "list"]
        
        # Always fail with connection refused
        mock_fail = Mock()
        mock_fail.returncode = 255
        mock_fail.stdout = ""
        mock_fail.stderr = "Connection refused"
        
        with patch('subprocess.run', return_value=mock_fail) as mock_run:
            with patch('time.sleep'):
                result = run_ssh_command(host, user, password, command)
                
                # Should fail after max retries
                assert result.returncode == 255
                # Should have been called 3 times (initial + 2 retries)
                assert mock_run.call_count == 3

    @pytest.mark.unit
    @pytest.mark.ssh
    def test_non_retryable_error(self, mock_sshpass_installed):
        """Test that non-connection errors don't trigger retry."""
        host = "proxmox1.example.com"
        user = "root"
        password = "test_password"
        command = ["pct", "destroy", "99999"]
        
        # Fail with non-connection error
        mock_fail = Mock()
        mock_fail.returncode = 1
        mock_fail.stdout = ""
        mock_fail.stderr = "VM does not exist"
        
        with patch('subprocess.run', return_value=mock_fail) as mock_run:
            result = run_ssh_command(host, user, password, command)
            
            # Should fail immediately without retry
            assert result.returncode == 1
            # Should have been called only once
            assert mock_run.call_count == 1

    @pytest.mark.unit
    @pytest.mark.ssh
    def test_password_sanitized_in_command(self, mock_sshpass_installed):
        """Test that password is sanitized when logging commands."""
        host = "proxmox1.example.com"
        user = "root"
        password = "super_secret_password_123"
        command = ["pct", "list"]
        
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "VMID Status"
        mock_result.stderr = ""
        
        with patch('subprocess.run', return_value=mock_result):
            with patch('logging.debug') as mock_log:
                run_ssh_command(host, user, password, command)
                
                # Check that logging was called
                assert mock_log.called
                
                # Verify password is not in any log message
                for call_args in mock_log.call_args_list:
                    log_message = str(call_args)
                    assert password not in log_message
                    # Should contain asterisks instead
                    if 'sshpass' in log_message:
                        assert '****' in log_message

    @pytest.mark.unit
    @pytest.mark.ssh
    def test_timeout_with_retry(self, mock_sshpass_installed):
        """Test timeout error triggers retry and eventually fails."""
        host = "proxmox1.example.com"
        user = "root"
        password = "test_password"
        command = ["pct", "list"]
        
        with patch('subprocess.run', side_effect=subprocess.TimeoutExpired(cmd=[], timeout=60)):
            with patch('time.sleep'):
                result = run_ssh_command(host, user, password, command)
                
                # Should return timeout error after all retries
                assert result.returncode == 124
                assert "timed out" in result.stderr.lower()

    @pytest.mark.unit
    @pytest.mark.ssh
    def test_unexpected_exception(self, mock_sshpass_installed):
        """Test handling of unexpected exceptions."""
        host = "proxmox1.example.com"
        user = "root"
        password = "test_password"
        command = ["pct", "list"]
        
        with patch('subprocess.run', side_effect=Exception("Unexpected error")):
            result = run_ssh_command(host, user, password, command)
            
            # Should return error result
            assert result.returncode == 1
            assert "Unexpected error" in result.stderr

    @pytest.mark.unit
    @pytest.mark.ssh
    def test_ssh_connection_options(self, mock_sshpass_installed):
        """Test that SSH is called with correct connection options."""
        host = "proxmox1.example.com"
        user = "root"
        password = "test_password"
        command = ["pct", "list"]
        
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "VMID Status"
        mock_result.stderr = ""
        
        with patch('subprocess.run', return_value=mock_result) as mock_run:
            run_ssh_command(host, user, password, command)
            
            # Verify SSH options
            call_args = mock_run.call_args[0][0]
            assert "StrictHostKeyChecking=no" in ' '.join(call_args)
            assert "ConnectTimeout=15" in ' '.join(call_args)
            assert "ServerAliveInterval=5" in ' '.join(call_args)

    @pytest.mark.unit
    @pytest.mark.ssh
    def test_command_with_multiple_arguments(self, mock_sshpass_installed):
        """Test SSH command with multiple arguments."""
        host = "proxmox1.example.com"
        user = "root"
        password = "test_password"
        command = ["pct", "set", "10001", "--memory", "2048"]
        
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Configuration updated"
        mock_result.stderr = ""
        
        with patch('subprocess.run', return_value=mock_result) as mock_run:
            result = run_ssh_command(host, user, password, command)
            
            # Verify all command parts are included
            call_args = mock_run.call_args[0][0]
            assert "pct" in call_args
            assert "set" in call_args
            assert "10001" in call_args
            assert "--memory" in call_args
            assert "2048" in call_args
            assert result.returncode == 0

    @pytest.mark.unit
    @pytest.mark.ssh
    def test_stdout_and_stderr_captured(self, mock_sshpass_installed):
        """Test that both stdout and stderr are captured."""
        host = "proxmox1.example.com"
        user = "root"
        password = "test_password"
        command = ["pct", "list"]
        
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Standard output"
        mock_result.stderr = "Warning message"
        
        with patch('subprocess.run', return_value=mock_result):
            result = run_ssh_command(host, user, password, command)
            
            assert result.stdout == "Standard output"
            assert result.stderr == "Warning message"
