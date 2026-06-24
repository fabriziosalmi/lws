"""
LWS Core Module

This module contains core utilities for the LWS (Linux Web Services) CLI tool.
It provides configuration management, logging, SSH execution, and Proxmox command utilities.
"""

__version__ = '1.4.1'

# Import logging first (no dependencies)
from .logging_setup import setup_logging, JsonFormatter

# Import SSH (only depends on standard libs)
from .ssh import run_ssh_command

# Import config (depends on nothing from lws_core)
from .config import config, load_config, validate_config, mask_sensitive_info, _ensure_config_loaded

# Import proxmox (depends on ssh)
from .proxmox import execute_command, run_proxmox_command

# Import utils last (depends on config and proxmox)
from .utils import (
    is_service_active,
    command_alias,
    process_instance_command,
    build_resize_command,
    get_next_vmid,
    is_container_locked
)

# Ensure config is loaded after all imports
_ensure_config_loaded()

__all__ = [
    '__version__',
    'config',
    'load_config',
    'validate_config',
    'mask_sensitive_info',
    'setup_logging',
    'JsonFormatter',
    'run_ssh_command',
    'execute_command',
    'run_proxmox_command',
    'is_service_active',
    'command_alias',
    'process_instance_command',
    'build_resize_command',
    'get_next_vmid',
    'is_container_locked',
]
