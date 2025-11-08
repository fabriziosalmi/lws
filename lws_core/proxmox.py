"""
Proxmox Module

This module provides utilities for executing Proxmox commands either locally
or remotely via SSH.
"""

import logging
import subprocess
from .ssh import run_ssh_command


def execute_command(cmd, use_local_only, host_details=None):
    """
    Executes a command locally or via SSH based on the configuration.

    Parameters:
    - cmd: Command list to execute
    - use_local_only: Whether to execute locally only
    - host_details: SSH connection details for remote execution

    Returns:
    - subprocess.CompletedProcess object with command output
    """
    if not cmd:
        raise ValueError("Command cannot be empty")

    if use_local_only:
        logging.debug(f"🔎 Executing local command: {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            result.check_returncode()
            logging.debug(f"🔎 Local command output: {result.stdout}")
            return result
        except subprocess.CalledProcessError as e:
            logging.error(f"❌ Local command failed: {e}")
            return e
        except Exception as e:
            logging.error(f"❌ Unexpected error executing local command: {str(e)}")
            error_result = subprocess.CompletedProcess(
                args=cmd,
                returncode=1,
                stdout="",
                stderr=f"Error: {str(e)}"
            )
            return error_result
    else:
        if not host_details:
            raise ValueError("Host details are required for remote command execution")
        logging.debug(f"🔎 Executing remote command: {' '.join(cmd)} on {host_details['host']}")
        return run_ssh_command(host_details['host'], host_details['user'], host_details['ssh_password'], cmd)


def run_proxmox_command(local_cmd, remote_cmd=None, use_local_only=False, host_details=None):
    """
    Executes a Proxmox command either locally or remotely.

    Parameters:
    - local_cmd: Command to execute locally
    - remote_cmd: Command to execute remotely (if use_local_only is False)
    - use_local_only: Whether to execute locally only
    - host_details: SSH connection details for remote execution

    Returns:
    - subprocess.CompletedProcess object with command output
    """
    cmd = local_cmd if use_local_only else remote_cmd
    if cmd is None:
        raise ValueError("Command cannot be None.")
    return execute_command(cmd, use_local_only, host_details)
