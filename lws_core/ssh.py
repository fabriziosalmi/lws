"""
SSH Module

This module provides SSH command execution utilities with retry logic,
timeout handling, and password sanitization for secure logging.
"""

import os
import time
import logging
import subprocess
import shutil

# How long one remote command may run, in seconds. Backups, package installs
# and migrations legitimately take minutes, so this is a safety net for a
# command that hangs, not a limit for normal work. A dead connection is
# detected sooner by ServerAliveInterval (5 s x the default 3 probes).
# `ssh_command_timeout` in config.yaml overrides it; 0 or null disables it.
DEFAULT_COMMAND_TIMEOUT = 3600

_USE_CONFIG = object()


def configured_command_timeout():
    """The per-command SSH timeout from config.yaml, or the default."""
    try:
        from .config import config
        value = config.get('ssh_command_timeout', DEFAULT_COMMAND_TIMEOUT)
    except Exception:
        return DEFAULT_COMMAND_TIMEOUT
    if value in (None, 0, "0"):
        return None
    try:
        value = float(value)
    except (TypeError, ValueError):
        logging.error(f"❌ Invalid ssh_command_timeout {value!r}; using {DEFAULT_COMMAND_TIMEOUT} seconds.")
        return DEFAULT_COMMAND_TIMEOUT
    return value if value > 0 else None


def _is_connection_failure(result):
    """True when ssh itself could not connect, so the command never started.

    ssh exits with 255 for its own errors. Retrying anything else could run a
    remote command twice: a command's own output may well mention a refused
    connection.
    """
    return result.returncode == 255 and (
        "Connection refused" in result.stderr or "Connection timed out" in result.stderr
    )


def run_ssh_command(host, user, ssh_password, command, timeout=_USE_CONFIG, input_text=None):
    """
    Runs an SSH command on a remote host, with error handling and logging.

    Parameters:
    - host: Remote host to connect to
    - user: SSH username
    - ssh_password: SSH password
    - command: List containing the command and its arguments
    - timeout: Seconds the command may run; None for no limit. Defaults to
      `ssh_command_timeout` from config.yaml, or DEFAULT_COMMAND_TIMEOUT.
    - input_text: Text sent to the remote command's standard input, for
      secrets that must not appear on the command line or in the logs.

    A failed connection is retried up to twice. A command that started and
    then timed out is not retried: it may have changed state on the host, and
    running it again (a second vzdump, a second apt-get) is not safe.

    Returns:
    - subprocess.CompletedProcess object with stdout and stderr
    """
    if not shutil.which('sshpass'):
        error_msg = "sshpass command not found. Please install it with 'apt install sshpass' or equivalent."
        logging.error(f"❌ {error_msg}")
        raise RuntimeError(error_msg)

    # Add connection timeout and retry mechanism
    connection_timeout = "15"  # 15 seconds timeout
    max_retries = 2
    retry_count = 0

    # The password goes through the SSHPASS env var (sshpass -e), not -p, so
    # it never shows up in `ps`/`/proc/<pid>/cmdline` to other local users.
    ssh_env = {**os.environ, "SSHPASS": ssh_password}

    # StrictHostKeyChecking=accept-new trusts a host's key on first contact
    # (needed since these hosts are rarely pre-seeded into known_hosts) but,
    # unlike the previous "no", still rejects a KNOWN host whose key changes
    # later, which is the actual MITM case this setting exists to catch.
    ssh_cmd = [
        "sshpass", "-e", "ssh",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", f"ConnectTimeout={connection_timeout}",
        "-o", "ServerAliveInterval=5",
        f"{user}@{host}"
    ] + command

    # Construct a sanitized command for logging (hides the password)
    sanitized_ssh_cmd = [
        "sshpass", "-e", "ssh",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", f"ConnectTimeout={connection_timeout}",
        "-o", "ServerAliveInterval=5",
        f"{user}@{host}"
    ] + command

    if timeout is _USE_CONFIG:
        timeout = configured_command_timeout()

    while retry_count <= max_retries:
        try:
            # Log the sanitized command instead of the real command with the password
            if retry_count > 0:
                logging.debug(f"🔁 Retry {retry_count}/{max_retries}: Executing SSH command: {' '.join(sanitized_ssh_cmd)}")
            else:
                logging.debug(f"🔎 Executing SSH command: {' '.join(sanitized_ssh_cmd)}")

            # Execute the command
            result = subprocess.run(ssh_cmd, input=input_text, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, timeout=timeout, env=ssh_env)

            # Check if the command succeeded
            if result.returncode == 0:
                logging.debug(f"🔎 SSH command executed successfully: {' '.join(sanitized_ssh_cmd)}")
                logging.debug(f"🔎 Command output: {result.stdout}")
                return result

            # If we reached here, there was an error
            logging.debug(f"❌ SSH command failed with return code {result.returncode}: {' '.join(sanitized_ssh_cmd)}")
            logging.debug(f"❌ Error output: {result.stderr}")

            # Retry only when ssh could not connect, so the command never ran
            if _is_connection_failure(result):
                retry_count += 1
                if retry_count <= max_retries:
                    logging.debug(f"🔄 Retrying SSH connection to {host} after connection issue ({retry_count}/{max_retries})")
                    time.sleep(2)  # Wait 2 seconds before retry
                    continue

            # For other errors, don't retry - just return the error
            return result

        except subprocess.TimeoutExpired:
            # Not retried: the command was running and may have changed state.
            logging.error(f"❌ SSH command timed out after {timeout:g} seconds: {' '.join(sanitized_ssh_cmd)}")
            return subprocess.CompletedProcess(
                args=sanitized_ssh_cmd,
                returncode=124,  # Common timeout exit code
                stdout="",
                stderr=f"Error: SSH command timed out after {timeout:g} seconds"
            )
        except Exception as e:
            logging.error(f"❌ An unexpected error occurred while running SSH command: {str(e)}")
            # Create a dummy result with the error info
            error_result = subprocess.CompletedProcess(
                args=sanitized_ssh_cmd,
                returncode=1,
                stdout="",
                stderr=f"Error: {str(e)}"
            )
            return error_result


def run_scp_command(ssh_password, *scp_args, timeout=None):
    """
    Runs `scp` with the given arguments, with the password passed via the
    SSHPASS environment variable and host-key verification enabled - the
    same security properties as run_ssh_command, but without its command
    timeout or retry-on-connection-refused logic: a file transfer can
    legitimately take far longer than a status command, and blindly
    retrying a partially-completed transfer is not safe in general.

    Parameters:
    - ssh_password: SSH password for the target host
    - scp_args: positional scp arguments in scp's own order, e.g.
      ("/local/file", "user@host:/remote/path") for an upload, or the
      reverse for a download. Callers build the user@host:path spec
      themselves since scp's source/destination syntax differs from the
      "command after host" form run_ssh_command uses.
    - timeout: optional subprocess timeout in seconds. None (the default)
      waits indefinitely, appropriate for transfers of unknown size.

    Returns:
    - subprocess.CompletedProcess object with stdout and stderr
    """
    if not shutil.which('sshpass'):
        error_msg = "sshpass command not found. Please install it with 'apt install sshpass' or equivalent."
        logging.error(f"❌ {error_msg}")
        raise RuntimeError(error_msg)

    scp_env = {**os.environ, "SSHPASS": ssh_password}
    scp_cmd = [
        "sshpass", "-e", "scp",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=15",
    ] + list(scp_args)

    logging.debug(f"🔎 Executing scp command: {' '.join(scp_cmd)}")

    try:
        result = subprocess.run(scp_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout, env=scp_env)
        if result.returncode != 0:
            logging.debug(f"❌ scp command failed with return code {result.returncode}: {result.stderr}")
        return result
    except subprocess.TimeoutExpired:
        logging.error(f"❌ scp command timed out after {timeout} seconds: {' '.join(scp_cmd)}")
        return subprocess.CompletedProcess(
            args=scp_cmd,
            returncode=124,
            stdout="",
            stderr=f"Error: scp command timed out after {timeout} seconds"
        )
    except Exception as e:
        logging.error(f"❌ An unexpected error occurred while running scp: {str(e)}")
        return subprocess.CompletedProcess(
            args=scp_cmd,
            returncode=1,
            stdout="",
            stderr=f"Error: {str(e)}"
        )
