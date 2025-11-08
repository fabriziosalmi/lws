"""
Unit tests for lws_core/utils.py

Tests cover:
- Service status checking
- Command aliases
- Instance command processing
- Resize command building
- VMID generation
- Container lock checking
"""

import pytest
import subprocess
from unittest.mock import patch, Mock, MagicMock, call
from click.testing import CliRunner

from lws_core.utils import (
    is_service_active,
    command_alias,
    process_instance_command,
    build_resize_command,
    get_next_vmid,
    is_container_locked
)


class TestIsServiceActive:
    """Tests for the is_service_active function."""

    @pytest.mark.unit
    def test_service_is_active(self):
        """Test checking an active service."""
        mock_result = Mock()
        mock_result.stdout = "active\n"
        mock_result.returncode = 0
        
        with patch('subprocess.run', return_value=mock_result):
            result = is_service_active("nginx")
            
            assert result is True

    @pytest.mark.unit
    def test_service_is_inactive(self):
        """Test checking an inactive service."""
        mock_result = Mock()
        mock_result.stdout = "inactive\n"
        mock_result.returncode = 3
        
        with patch('subprocess.run', return_value=mock_result):
            result = is_service_active("nginx")
            
            assert result is False

    @pytest.mark.unit
    def test_service_not_found(self):
        """Test checking a non-existent service."""
        mock_result = Mock()
        mock_result.stdout = "failed\n"
        mock_result.returncode = 4
        
        with patch('subprocess.run', return_value=mock_result):
            result = is_service_active("nonexistent")
            
            assert result is False

    @pytest.mark.unit
    def test_service_check_exception(self):
        """Test exception handling during service check."""
        with patch('subprocess.run', side_effect=Exception("System error")):
            result = is_service_active("nginx")
            
            assert result is False

    @pytest.mark.unit
    def test_service_check_strips_whitespace(self):
        """Test that whitespace is stripped from output."""
        mock_result = Mock()
        mock_result.stdout = "  active  \n"
        mock_result.returncode = 0
        
        with patch('subprocess.run', return_value=mock_result):
            result = is_service_active("nginx")
            
            assert result is True


class TestCommandAlias:
    """Tests for the command_alias decorator."""

    @pytest.mark.unit
    def test_command_alias_decorator(self):
        """Test that command_alias decorator can be applied."""
        @command_alias('test', 'alias')
        def test_function():
            return "test"
        
        # Decorator should return the function unchanged
        assert test_function() == "test"

    @pytest.mark.unit
    def test_command_alias_with_multiple_aliases(self):
        """Test command_alias with multiple aliases."""
        @command_alias('alias1', 'alias2', 'alias3')
        def test_function():
            return 42
        
        assert test_function() == 42


class TestBuildResizeCommand:
    """Tests for the build_resize_command function."""

    @pytest.mark.unit
    def test_resize_memory_only(self):
        """Test building resize command with memory only."""
        with patch('lws_core.utils.config', {'default_storage': 'local-lvm'}):
            local_cmd, remote_cmd = build_resize_command("10001", memory=2048)
            
            assert local_cmd == remote_cmd
            assert "pct" in local_cmd
            assert "set" in local_cmd
            assert "10001" in local_cmd
            assert "--memory" in local_cmd
            assert "2048" in local_cmd

    @pytest.mark.unit
    def test_resize_cpulimit_only(self):
        """Test building resize command with CPU limit only."""
        with patch('lws_core.utils.config', {'default_storage': 'local-lvm'}):
            local_cmd, remote_cmd = build_resize_command("10001", cpulimit=4)
            
            assert "--cpulimit" in local_cmd
            assert "4" in local_cmd

    @pytest.mark.unit
    def test_resize_storage_only(self):
        """Test building resize command with storage only."""
        with patch('lws_core.utils.config', {'default_storage': 'local-lvm'}):
            local_cmd, remote_cmd = build_resize_command("10001", storage_size="32G")
            
            assert "--rootfs" in local_cmd
            assert "local-lvm:32G" in local_cmd

    @pytest.mark.unit
    def test_resize_all_parameters(self):
        """Test building resize command with all parameters."""
        with patch('lws_core.utils.config', {'default_storage': 'local-lvm'}):
            local_cmd, remote_cmd = build_resize_command(
                "10001",
                memory=4096,
                cpulimit=8,
                storage_size="64G"
            )
            
            assert "--memory" in local_cmd
            assert "4096" in local_cmd
            assert "--cpulimit" in local_cmd
            assert "8" in local_cmd
            assert "--rootfs" in local_cmd
            assert "local-lvm:64G" in local_cmd

    @pytest.mark.unit
    def test_resize_no_parameters(self):
        """Test building resize command with no parameters."""
        with patch('lws_core.utils.config', {'default_storage': 'local-lvm'}):
            local_cmd, remote_cmd = build_resize_command("10001")
            
            # Should still have basic pct set command
            assert "pct" in local_cmd
            assert "set" in local_cmd
            assert "10001" in local_cmd


class TestGetNextVMID:
    """Tests for the get_next_vmid function."""

    @pytest.mark.unit
    def test_get_next_vmid_with_existing_containers(self, mock_pct_list_output):
        """Test getting next VMID when containers exist."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = mock_pct_list_output
        
        with patch('lws_core.utils.run_proxmox_command', return_value=mock_result):
            next_vmid = get_next_vmid(start_vmid=10000, use_local_only=True)
            
            # Should return max existing VMID + 1
            assert next_vmid == 10006  # max is 10005, so next is 10006

    @pytest.mark.unit
    def test_get_next_vmid_no_existing_containers(self):
        """Test getting next VMID when no containers exist."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "VMID       Status     Lock         Name"
        
        with patch('lws_core.utils.run_proxmox_command', return_value=mock_result):
            next_vmid = get_next_vmid(start_vmid=10000, use_local_only=True)
            
            # Should return start_vmid
            assert next_vmid == 10000

    @pytest.mark.unit
    def test_get_next_vmid_command_failure(self):
        """Test getting next VMID when command fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Error"
        
        with patch('lws_core.utils.run_proxmox_command', return_value=mock_result):
            next_vmid = get_next_vmid(start_vmid=10000, use_local_only=True)
            
            # Should return start_vmid on failure
            assert next_vmid == 10000

    @pytest.mark.unit
    def test_get_next_vmid_custom_start(self, mock_pct_list_output):
        """Test getting next VMID with custom start VMID."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "VMID       Status     Lock         Name"
        
        with patch('lws_core.utils.run_proxmox_command', return_value=mock_result):
            next_vmid = get_next_vmid(start_vmid=20000, use_local_only=True)
            
            assert next_vmid == 20000

    @pytest.mark.unit
    def test_get_next_vmid_remote_execution(self):
        """Test getting next VMID with remote execution."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "VMID       Status     Lock         Name\n10001      running"
        
        host_details = {
            'host': 'proxmox.example.com',
            'user': 'root',
            'ssh_password': 'password'
        }
        
        with patch('lws_core.utils.run_proxmox_command', return_value=mock_result) as mock_run:
            next_vmid = get_next_vmid(
                start_vmid=10000,
                use_local_only=False,
                host_details=host_details
            )
            
            assert next_vmid == 10002
            # Verify remote execution was requested
            assert mock_run.called


class TestIsContainerLocked:
    """Tests for the is_container_locked function."""

    @pytest.mark.unit
    def test_container_is_locked(self, mock_pct_config_locked_output):
        """Test checking a locked container."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = mock_pct_config_locked_output
        
        host_details = {'host': 'proxmox.example.com', 'user': 'root', 'ssh_password': 'password'}
        
        with patch('lws_core.utils.config', {'use_local_only': False}):
            with patch('lws_core.utils.run_proxmox_command', return_value=mock_result):
                result = is_container_locked("10001", host_details)
                
                assert result is True

    @pytest.mark.unit
    def test_container_is_not_locked(self, mock_pct_config_output):
        """Test checking a non-locked container."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = mock_pct_config_output
        
        host_details = {'host': 'proxmox.example.com', 'user': 'root', 'ssh_password': 'password'}
        
        with patch('lws_core.utils.config', {'use_local_only': False}):
            with patch('lws_core.utils.run_proxmox_command', return_value=mock_result):
                result = is_container_locked("10001", host_details)
                
                assert result is False

    @pytest.mark.unit
    def test_container_lock_check_failure(self):
        """Test lock check when command fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Container not found"
        
        host_details = {'host': 'proxmox.example.com', 'user': 'root', 'ssh_password': 'password'}
        
        with patch('lws_core.utils.config', {'use_local_only': False}):
            with patch('lws_core.utils.run_proxmox_command', return_value=mock_result):
                result = is_container_locked("99999", host_details)
                
                # Should return False on failure to avoid indefinite retries
                assert result is False


class TestProcessInstanceCommand:
    """Tests for the process_instance_command function."""

    @pytest.mark.unit
    def test_process_stop_command(self, sample_config):
        """Test processing stop command."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Stopped"
        mock_result.stderr = ""
        
        with patch('lws_core.utils.config', sample_config):
            with patch('lws_core.utils.run_proxmox_command', return_value=mock_result):
                with patch('click.secho') as mock_echo:
                    process_instance_command(
                        instance_ids=['10001'],
                        command_type='stop',
                        region='eu-south-1',
                        az='az1'
                    )
                    
                    # Should show success message
                    assert any('success' in str(call).lower() for call in mock_echo.call_args_list)

    @pytest.mark.unit
    def test_process_start_command(self, sample_config):
        """Test processing start command."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Started"
        
        with patch('lws_core.utils.config', sample_config):
            with patch('lws_core.utils.run_proxmox_command', return_value=mock_result):
                with patch('click.secho') as mock_echo:
                    process_instance_command(
                        instance_ids=['10001'],
                        command_type='start',
                        region='eu-south-1',
                        az='az1'
                    )
                    
                    assert any('success' in str(call).lower() for call in mock_echo.call_args_list)

    @pytest.mark.unit
    def test_process_describe_command(self, sample_config, mock_pct_config_output):
        """Test processing describe command."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = mock_pct_config_output
        
        with patch('lws_core.utils.config', sample_config):
            with patch('lws_core.utils.run_proxmox_command', return_value=mock_result):
                with patch('click.secho') as mock_echo:
                    process_instance_command(
                        instance_ids=['10001'],
                        command_type='describe',
                        region='eu-south-1',
                        az='az1'
                    )
                    
                    # Should display config
                    assert any('configuration' in str(call).lower() for call in mock_echo.call_args_list)

    @pytest.mark.unit
    def test_process_terminate_command(self, sample_config):
        """Test processing terminate command."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Destroyed"
        
        with patch('lws_core.utils.config', sample_config):
            with patch('lws_core.utils.run_proxmox_command', return_value=mock_result):
                with patch('click.secho') as mock_echo:
                    process_instance_command(
                        instance_ids=['10001'],
                        command_type='terminate',
                        region='eu-south-1',
                        az='az1'
                    )
                    
                    assert any('success' in str(call).lower() for call in mock_echo.call_args_list)

    @pytest.mark.unit
    def test_process_resize_command(self, sample_config):
        """Test processing resize command."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Resized"
        
        with patch('lws_core.utils.config', sample_config):
            with patch('lws_core.utils.run_proxmox_command', return_value=mock_result):
                with patch('click.secho') as mock_echo:
                    process_instance_command(
                        instance_ids=['10001'],
                        command_type='resize',
                        region='eu-south-1',
                        az='az1',
                        memory=2048,
                        cpulimit=4
                    )
                    
                    assert any('success' in str(call).lower() for call in mock_echo.call_args_list)

    @pytest.mark.unit
    def test_process_snapshot_create_command(self, sample_config):
        """Test processing snapshot create command."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Snapshot created"
        
        with patch('lws_core.utils.config', sample_config):
            with patch('lws_core.utils.run_proxmox_command', return_value=mock_result):
                with patch('click.secho') as mock_echo:
                    process_instance_command(
                        instance_ids=['10001'],
                        command_type='snapshot_create',
                        region='eu-south-1',
                        az='az1',
                        snapshot_name='test-snap'
                    )
                    
                    assert any('success' in str(call).lower() for call in mock_echo.call_args_list)

    @pytest.mark.unit
    def test_process_snapshot_delete_command(self, sample_config):
        """Test processing snapshot delete command."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Snapshot deleted"
        
        with patch('lws_core.utils.config', sample_config):
            with patch('lws_core.utils.run_proxmox_command', return_value=mock_result):
                with patch('click.secho') as mock_echo:
                    process_instance_command(
                        instance_ids=['10001'],
                        command_type='snapshot_delete',
                        region='eu-south-1',
                        az='az1',
                        snapshot_name='test-snap'
                    )
                    
                    assert any('success' in str(call).lower() for call in mock_echo.call_args_list)

    @pytest.mark.unit
    def test_process_command_no_instances(self, sample_config):
        """Test processing command with no instance IDs."""
        with patch('lws_core.utils.config', sample_config):
            with patch('click.secho') as mock_echo:
                process_instance_command(
                    instance_ids=[],
                    command_type='stop',
                    region='eu-south-1',
                    az='az1'
                )
                
                # Should show error
                assert any('no instance' in str(call).lower() for call in mock_echo.call_args_list)

    @pytest.mark.unit
    def test_process_command_invalid_region(self, sample_config):
        """Test processing command with invalid region."""
        with patch('lws_core.utils.config', sample_config):
            with patch('click.secho') as mock_echo:
                process_instance_command(
                    instance_ids=['10001'],
                    command_type='stop',
                    region='invalid-region',
                    az='az1'
                )
                
                # Should show error
                assert any('invalid' in str(call).lower() for call in mock_echo.call_args_list)

    @pytest.mark.unit
    def test_process_command_invalid_az(self, sample_config):
        """Test processing command with invalid availability zone."""
        with patch('lws_core.utils.config', sample_config):
            with patch('click.secho') as mock_echo:
                process_instance_command(
                    instance_ids=['10001'],
                    command_type='stop',
                    region='eu-south-1',
                    az='invalid-az'
                )
                
                # Should show error
                assert any('invalid' in str(call).lower() for call in mock_echo.call_args_list)

    @pytest.mark.unit
    def test_process_command_unknown_type(self, sample_config):
        """Test processing unknown command type."""
        with patch('lws_core.utils.config', sample_config):
            with patch('click.secho') as mock_echo:
                process_instance_command(
                    instance_ids=['10001'],
                    command_type='unknown_command',
                    region='eu-south-1',
                    az='az1'
                )
                
                # Should show error
                assert any('unknown' in str(call).lower() for call in mock_echo.call_args_list)

    @pytest.mark.unit
    def test_process_command_failure(self, sample_config):
        """Test processing command that fails."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Command failed"
        
        with patch('lws_core.utils.config', sample_config):
            with patch('lws_core.utils.run_proxmox_command', return_value=mock_result):
                with patch('click.secho') as mock_echo:
                    process_instance_command(
                        instance_ids=['10001'],
                        command_type='stop',
                        region='eu-south-1',
                        az='az1'
                    )
                    
                    # Should show failure
                    assert any('failed' in str(call).lower() for call in mock_echo.call_args_list)

    @pytest.mark.unit
    def test_process_multiple_instances(self, sample_config):
        """Test processing command for multiple instances."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Success"
        
        with patch('lws_core.utils.config', sample_config):
            with patch('lws_core.utils.run_proxmox_command', return_value=mock_result) as mock_run:
                with patch('click.secho'):
                    process_instance_command(
                        instance_ids=['10001', '10002', '10003'],
                        command_type='stop',
                        region='eu-south-1',
                        az='az1'
                    )
                    
                    # Should be called 3 times
                    assert mock_run.call_count == 3
