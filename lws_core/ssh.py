"""
SSH Module

This module provides SSH command execution utilities with retry logic,
timeout handling, and password sanitization for secure logging.
"""

import time
import logging
import subprocess
import shutil


def run_ssh_command(host, user, ssh_password, command):
    """
    Runs an SSH command on a remote host, with error handling and logging.

    Parameters:
    - host: Remote host to connect to
    - user: SSH username
    - ssh_password: SSH password
    - command: List containing the command and its arguments

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

    ssh_cmd = [
        "sshpass", "-p", ssh_password, "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", f"ConnectTimeout={connection_timeout}",
        "-o", "ServerAliveInterval=5",
        f"{user}@{host}"
    ] + command

    # Construct a sanitized command for logging (hides the password)
    sanitized_ssh_cmd = [
        "sshpass", "-p", "****", "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", f"ConnectTimeout={connection_timeout}",
        "-o", "ServerAliveInterval=5",
        f"{user}@{host}"
    ] + command

    while retry_count <= max_retries:
        try:
            # Log the sanitized command instead of the real command with the password
            if retry_count > 0:
                logging.debug(f"🔁 Retry {retry_count}/{max_retries}: Executing SSH command: {' '.join(sanitized_ssh_cmd)}")
            else:
                logging.debug(f"🔎 Executing SSH command: {' '.join(sanitized_ssh_cmd)}")

            # Execute the command
            result = subprocess.run(ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)

            # Check if the command succeeded
            if result.returncode == 0:
                logging.debug(f"🔎 SSH command executed successfully: {' '.join(sanitized_ssh_cmd)}")
                logging.debug(f"🔎 Command output: {result.stdout}")
                return result

            # If we reached here, there was an error
            logging.debug(f"❌ SSH command failed with return code {result.returncode}: {' '.join(sanitized_ssh_cmd)}")
            logging.debug(f"❌ Error output: {result.stderr}")

            # Check for specific SSH errors that would benefit from retry
            if "Connection refused" in result.stderr or "Connection timed out" in result.stderr:
                retry_count += 1
                if retry_count <= max_retries:
                    logging.debug(f"🔄 Retrying SSH connection to {host} after connection issue ({retry_count}/{max_retries})")
                    time.sleep(2)  # Wait 2 seconds before retry
                    continue

            # For other errors, don't retry - just return the error
            return result

        except subprocess.TimeoutExpired as te:
            logging.error(f"❌ SSH command timed out after 60 seconds: {' '.join(sanitized_ssh_cmd)}")
            retry_count += 1
            if retry_count <= max_retries:
                logging.debug(f"🔄 Retrying SSH command after timeout ({retry_count}/{max_retries})")
                time.sleep(2)
                continue
            # Create a dummy result for the timeout
            error_result = subprocess.CompletedProcess(
                args=sanitized_ssh_cmd,
                returncode=124,  # Common timeout exit code
                stdout="",
                stderr=f"Error: SSH command timed out after 60 seconds"
            )
            return error_result
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
