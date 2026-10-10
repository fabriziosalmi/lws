"""
Proxmox Module

This module provides utilities for executing Proxmox commands either locally
or remotely via SSH.
"""

import logging
import shlex
import subprocess
from .ssh import run_ssh_command


def execute_command(cmd, use_local_only, host_details=None, input_text=None):
    """
    Executes a command locally or via SSH based on the configuration.

    Parameters:
    - cmd: Command list to execute
    - use_local_only: Whether to execute locally only
    - host_details: SSH connection details for remote execution
    - input_text: Text for the command's standard input. Secrets go here,
      not in `cmd`: arguments show in process lists and in the debug logs.

    Returns:
    - subprocess.CompletedProcess object with command output
    """
    if not cmd:
        raise ValueError("Command cannot be empty")

    if use_local_only:
        logging.debug(f"🔎 Executing local command: {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, input=input_text, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
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
        extra = {} if input_text is None else {'input_text': input_text}
        return run_ssh_command(host_details['host'], host_details['user'], host_details['ssh_password'], cmd, **extra)


def run_proxmox_command(local_cmd, remote_cmd=None, use_local_only=False, host_details=None, input_text=None):
    """
    Executes a Proxmox command either locally or remotely.

    Parameters:
    - local_cmd: Command to execute locally
    - remote_cmd: Command to execute remotely (if use_local_only is False)
    - use_local_only: Whether to execute locally only
    - host_details: SSH connection details for remote execution
    - input_text: Text for the command's standard input (see execute_command)

    Returns:
    - subprocess.CompletedProcess object with command output
    """
    cmd = local_cmd if use_local_only else remote_cmd
    if cmd is None:
        raise ValueError("Command cannot be None.")
    if input_text is None:
        return execute_command(cmd, use_local_only, host_details)
    return execute_command(cmd, use_local_only, host_details, input_text=input_text)


def run_argv(argv, use_local_only=False, host_details=None, input_text=None):
    """
    Runs one command, given as an argument list, with the same arguments
    locally and over SSH.

    OpenSSH joins the arguments that follow user@host into a single string,
    which the remote shell parses again. An argument list that is safe for
    subprocess is therefore not safe remotely: `pct exec 100 -- ls && reboot`
    would run `reboot` on the host. Quoting every argument with shlex.join
    makes the remote shell see exactly `argv`, as subprocess does locally.

    For a pipeline or `&&` inside a container, pass it explicitly to a shell
    in the container: ["pct", "exec", id, "--", "sh", "-c", "a && b"].

    `input_text` is sent to the command's standard input, over SSH too: the
    way to hand a secret to a command without putting it on a command line.
    """
    argv = [str(a) for a in argv]
    if input_text is None:
        return run_proxmox_command(argv, [shlex.join(argv)], use_local_only, host_details)
    return run_proxmox_command(argv, [shlex.join(argv)], use_local_only, host_details, input_text=input_text)
