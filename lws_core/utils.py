"""
Utilities Module

This module contains utility functions used throughout the LWS tool,
including service checks, VMID generation, and instance command processing.
"""

import logging
import subprocess
import click
from .config import config
from .proxmox import run_proxmox_command


def is_service_active(service_name):
    """
    Check if a service is active using systemctl.

    Parameters:
    - service_name: Name of the service to check

    Returns:
    - Boolean indicating if the service is active
    """
    try:
        result = subprocess.run(
            ["systemctl", "is-active", service_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result.stdout.strip() == "active"
    except Exception as e:
        logging.error(f"Error checking if service {service_name} is active: {str(e)}")
        return False


def command_alias(*aliases):
    """
    Decorator that creates command aliases for Click commands.

    Parameters:
    - aliases: List of command name aliases

    Returns:
    - Decorator function

    Note: This decorator needs to be used in the context where the main CLI
    group is available. Import this in your command files and use with the
    appropriate CLI group.
    """
    def decorator(f):
        # This will be used in the command modules where the CLI group is defined
        return f
    return decorator


def process_instance_command(instance_ids, command_type, region, az, **kwargs):
    """
    Process commands for LXC instances.

    Parameters:
    - instance_ids: List of instance IDs to process
    - command_type: Type of command to execute
    - region: Region where instances exist
    - az: Availability zone where instances exist
    - kwargs: Additional command arguments
    """
    if not instance_ids:
        click.secho("❌ No instance IDs provided.", fg='red')
        return

    try:
        host_details = config['regions'][region]['availability_zones'][az]
    except KeyError:
        click.secho(f"❌ Invalid region '{region}' or availability zone '{az}'", fg='red')
        return

    command_map = {
        'stop': lambda instance_id: (["pct", "shutdown", instance_id], ["pct", "shutdown", instance_id]),
        'terminate': lambda instance_id: (["pct", "destroy", instance_id, "--purge"], ["pct", "destroy", instance_id, "--purge"]),
        'describe': lambda instance_id: (["pct", "config", instance_id], ["pct", "config", instance_id]),
        'resize': lambda instance_id: build_resize_command(instance_id, **kwargs),
        'start': lambda instance_id: (["pct", "start", instance_id], ["pct", "start", instance_id]),
        'reboot': lambda instance_id: (["pct", "reboot", instance_id], ["pct", "reboot", instance_id]),
        'snapshot_create': lambda instance_id, snapshot_name: (
            ["pct", "snapshot", instance_id, snapshot_name],
            ["pct", "snapshot", instance_id, snapshot_name]
        ),
        'snapshot_delete': lambda instance_id, snapshot_name: (
            ["pct", "delsnapshot", instance_id, snapshot_name],
            ["pct", "delsnapshot", instance_id, snapshot_name]
        ),
        '_snapshots': lambda instance_id: (["pct", "snapshot", instance_id], ["pct", "snapshot", instance_id]),
    }

    if command_type not in command_map:
        click.secho(f"❌ Unknown command type: {command_type}", fg='red')
        return

    with click.progressbar(instance_ids, label=f"Processing {command_type} command") as instance_ids_bar:
        for instance_id in instance_ids_bar:
            try:
                if command_type in ['snapshot_create', 'snapshot_delete']:
                    snapshot_name = kwargs.get('snapshot_name')
                    if not snapshot_name:
                        click.secho(f"❌ Snapshot name is required for {command_type}", fg='red')
                        continue
                    local_cmd, remote_cmd = command_map[command_type](instance_id, snapshot_name)
                else:
                    local_cmd, remote_cmd = command_map[command_type](instance_id)

                result = run_proxmox_command(local_cmd, remote_cmd, config.get('use_local_only', False), host_details)

                if result.returncode == 0:
                    if command_type == 'describe':
                        click.secho(f"🔧 Instance {instance_id} configuration:\n{result.stdout}", fg='cyan')
                    elif command_type == '_snapshots':
                        click.secho(f"📜 Snapshots for instance {instance_id}:\n{result.stdout}", fg='cyan')
                    else:
                        click.secho(f"✅ Instance {instance_id} {command_type} executed successfully.", fg='green')
                else:
                    click.secho(f"❌ Failed to {command_type} instance {instance_id}: {result.stderr}", fg='red')
            except Exception as e:
                click.secho(f"❌ Error processing instance {instance_id}: {str(e)}", fg='red')
                logging.error(f"Error processing instance {instance_id} with {command_type}: {str(e)}")


def build_resize_command(instance_id, memory=None, cpulimit=None, storage_size=None, **kwargs):
    """
    Build command for resizing an LXC container.

    Parameters:
    - instance_id: ID of the instance to resize
    - memory: New memory size in MB
    - cpulimit: New CPU limit
    - storage_size: New storage size

    Returns:
    - Tuple of local and remote commands
    """
    resize_cmd = ["pct", "set", instance_id]
    if memory:
        resize_cmd.extend(["--memory", str(memory)])
    if cpulimit:
        resize_cmd.extend(["--cpulimit", str(cpulimit)])
    if storage_size:
        resize_cmd.extend(["--rootfs", f"{config.get('default_storage', 'local')}:{storage_size}"])
    return (resize_cmd, resize_cmd)


def get_next_vmid(start_vmid=10000, use_local_only=False, host_details=None):
    """
    Generate the next available VMID by finding the highest existing VMID and incrementing it.

    Parameters:
    - start_vmid: The starting VMID to use if no containers exist.
    - use_local_only: Boolean to determine if the command should be run locally or remotely.
    - host_details: Dictionary containing the host, user, and ssh_password for remote execution.

    Returns:
    - The next available VMID as an integer.
    """
    # Command to list the existing containers and their VMIDs
    list_cmd = ["pct", "list"]

    # Execute the command either locally or remotely
    result = run_proxmox_command(list_cmd, list_cmd, use_local_only, host_details)

    if result and result.returncode == 0:
        existing_vmids = []
        lines = result.stdout.splitlines()
        for line in lines:
            # Skip the header line and extract VMID from each line
            if line.startswith("VMID"):
                continue
            vmid = int(line.split()[0])
            existing_vmids.append(vmid)

        # Find the next available VMID
        if existing_vmids:
            next_vmid = max(existing_vmids) + 1
        else:
            next_vmid = start_vmid

        return next_vmid
    else:
        logging.error("❌ Failed to retrieve existing VMIDs. Defaulting to start_vmid.")
        return start_vmid


def is_container_locked(instance_id, host_details):
    """
    Checks if the container is locked by using the pct config command.

    Parameters:
    - instance_id: ID of the instance to check
    - host_details: SSH connection details

    Returns:
    - Boolean indicating if the container is locked
    """
    check_lock_cmd = ["pct", "config", str(instance_id)]
    result = run_proxmox_command(check_lock_cmd, check_lock_cmd, config['use_local_only'], host_details)

    if result.returncode == 0:
        return 'lock' in result.stdout
    else:
        logging.error(f"❌ Failed to check lock status for instance {instance_id}: {result.stderr}")
        return False  # Assume it's not locked if the command fails to avoid indefinite retries
