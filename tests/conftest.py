"""
Pytest configuration and fixtures for LWS tests
"""

import os
import sys
import pytest
import tempfile
import yaml
from unittest.mock import Mock, MagicMock
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


@pytest.fixture
def sample_config():
    """Fixture providing a valid sample configuration."""
    return {
        'use_local_only': False,
        'start_vmid': 10000,
        'default_storage': 'local-lvm',
        'default_network': 'vmbr0',
        'minimum_resources': {
            'cores': 1,
            'memory_mb': 512
        },
        'api_key': 'test-api-key',
        'regions': {
            'eu-south-1': {
                'availability_zones': {
                    'az1': {
                        'host': 'proxmox1.example.com',
                        'user': 'root',
                        'ssh_password': 'password123'
                    },
                    'az2': {
                        'host': '172.23.0.2',
                        'user': 'root',
                        'ssh_password': 'password456'
                    }
                }
            },
            'eu-central-1': {
                'availability_zones': {
                    'pve-rhine': {
                        'host': 'pve-rhine.example.com',
                        'user': 'root',
                        'ssh_password': 'password789'
                    }
                }
            }
        },
        'instance_sizes': {
            'micro': {
                'memory': 512,
                'cpulimit': 1,
                'storage': '8G'
            },
            'small': {
                'memory': 1024,
                'cpulimit': 2,
                'storage': '16G'
            },
            'medium': {
                'memory': 2048,
                'cpulimit': 4,
                'storage': '32G'
            }
        }
    }


@pytest.fixture
def config_file(tmp_path, sample_config):
    """Fixture that creates a temporary config.yaml file."""
    config_path = tmp_path / "config.yaml"
    with open(config_path, 'w') as f:
        yaml.dump(sample_config, f)
    return config_path


@pytest.fixture
def mock_subprocess_result():
    """Fixture providing a mock subprocess.CompletedProcess object."""
    def _create_result(returncode=0, stdout="", stderr=""):
        result = Mock()
        result.returncode = returncode
        result.stdout = stdout
        result.stderr = stderr
        result.args = []
        return result
    return _create_result


@pytest.fixture
def mock_ssh_host_details():
    """Fixture providing mock SSH host details."""
    return {
        'host': 'proxmox1.example.com',
        'user': 'root',
        'ssh_password': 'test_password'
    }


@pytest.fixture
def mock_pct_list_output():
    """Fixture providing sample pct list output."""
    return """VMID       Status     Lock         Name                
10001      running                 test-container-1
10002      stopped                 test-container-2
10005      running                 test-container-3"""


@pytest.fixture
def mock_pct_config_output():
    """Fixture providing sample pct config output."""
    return """arch: amd64
cores: 2
hostname: test-container
memory: 2048
net0: name=eth0,bridge=vmbr0,ip=dhcp
ostype: ubuntu
rootfs: local-lvm:vm-10001-disk-0,size=8G
swap: 512"""


@pytest.fixture
def mock_pct_config_locked_output():
    """Fixture providing sample pct config output with lock."""
    return """arch: amd64
cores: 2
hostname: test-container
lock: backup
memory: 2048
net0: name=eth0,bridge=vmbr0,ip=dhcp
ostype: ubuntu
rootfs: local-lvm:vm-10001-disk-0,size=8G
swap: 512"""


@pytest.fixture
def mock_pct_snapshot_output():
    """Fixture providing sample pct snapshot output."""
    return """NAME                     TIME                 DESCRIPTION
snap1                    2024-01-15 10:30:00  Before update
snap2                    2024-01-20 14:45:00  After testing"""


@pytest.fixture(autouse=True)
def reset_config_module():
    """Reset the config module between tests."""
    # This fixture runs automatically before each test
    import lws_core.config as config_module
    # Store original config
    original_config = config_module.config.copy() if hasattr(config_module, 'config') else None
    
    yield
    
    # Restore or reset config after test
    if original_config is not None:
        config_module.config = original_config


@pytest.fixture
def change_test_dir(tmp_path, monkeypatch):
    """Change working directory to tmp_path for the test."""
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture
def mock_sshpass_installed(monkeypatch):
    """Mock shutil.which to simulate sshpass being installed."""
    def mock_which(cmd):
        if cmd == 'sshpass':
            return '/usr/bin/sshpass'
        return None
    
    import shutil
    monkeypatch.setattr(shutil, 'which', mock_which)


@pytest.fixture
def mock_sshpass_not_installed(monkeypatch):
    """Mock shutil.which to simulate sshpass not being installed."""
    def mock_which(cmd):
        return None
    
    import shutil
    monkeypatch.setattr(shutil, 'which', mock_which)
