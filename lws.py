#!/usr/bin/env python3

# to create lws alias:
# chmod +x lws.py && alias lws='python3 lws.py'
# then u can just run..
# lws

import os
import math
import time
import subprocess
import shutil
import logging
import logging.config
import json
import requests
import gzip
import yaml
import click
import socket
import tempfile
import re
import ipaddress
import shlex
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
from tqdm import tqdm

# Import from lws_core modules
from lws_core import (
    __version__,
    config,
    load_config,
    validate_config,
    run_ssh_command,
    run_scp_command,
    run_proxmox_command,
    run_argv,
    execute_command,
    process_instance_command,
    build_resize_command,
    get_next_vmid,
    is_container_locked,
    mask_sensitive_info
)


# Configuration and logging are now handled by lws_core modules


# lws
@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version=__version__)
def lws():
    """🐧 Linux (Containers) Web Services - A CLI tool for managing LXC containers on Proxmox."""
    pass


# Command alias decorator (kept local as it depends on the CLI group)
def command_alias(*aliases):
    """Decorator that creates command aliases for Click commands."""
    def decorator(f):
        for alias in aliases:
            lws.command(alias)(f)
        return f
    return decorator


# SSH and command execution functions are now in lws_core.ssh and lws_core.proxmox


# --- Input validators ---
# Several commands below interpolate user-supplied values into shell strings
# (sed/grep/echo) that are executed on the remote Proxmox host or inside an
# LXC container via SSH. Passing those values through `shlex.quote` is not
# enough on its own because the strings also embed sed/grep pattern syntax
# (not just shell syntax), so a quoted-but-still-regex-special value could
# still break the intended command. Validating against a strict allow-list
# before the value is ever interpolated removes the injection vector instead
# of trying to escape it across two nested languages.
#
# This also covers a second, more structural injection vector: OpenSSH
# itself re-joins every argument given after `user@host` into a single
# string and hands it to the remote shell, even when this codebase builds a
# "safe" argv list like ["pct", "shutdown", instance_id] for run_ssh_command.
# So a value containing shell metacharacters is exploitable remotely even
# though subprocess.run(..., shell=False) makes it safe locally. instance_id
# is by far the most common untrusted value flowing into these commands
# (Proxmox container IDs are always numeric), so validating it here at every
# Click argument closes that vector for the large majority of call sites.
_SAFE_NAME_RE = re.compile(r'^[A-Za-z0-9_-]{1,64}$')
_VMID_RE = re.compile(r'^[0-9]{1,10}$')
_TEMPLATE_NAME_RE = re.compile(r'^[A-Za-z0-9_.-]{1,255}$')
_PROTOCOL_RE = re.compile(r'^[A-Za-z0-9]{1,16}$')
_PORT_RE = re.compile(r'^[0-9]{1,5}(:[0-9]{1,5})?$')
_HOSTNAME_RE = re.compile(r'^[A-Za-z0-9.-]{1,253}$')
_SAFE_PATH_RE = re.compile(r'^[A-Za-z0-9_./-]{1,512}$')
_SERVICE_NAME_RE = re.compile(r'^[A-Za-z0-9_@.:-]{1,128}$')
_SAFE_FREETEXT_RE = re.compile(r'^[A-Za-z0-9 ._,:/-]{0,255}$')


def _validate_pattern(pattern, label):
    def callback(ctx, param, value):
        if value is None:
            return value
        values = value if isinstance(value, (tuple, list)) else (value,)
        for v in values:
            if not pattern.match(str(v)):
                raise click.BadParameter(f"invalid {label}: {v!r}")
        return value
    return callback


def _validate_ip_or_cidr(ctx, param, value):
    if value is None:
        return value
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise click.BadParameter(f"invalid IP/CIDR: {value!r}")
    return value


# Utility functions are now in lws_core.utils


@lws.group()
@command_alias('conf')
def conf():
    """🛠️ Manage client configuration."""
    pass


@conf.command('show')
def show_conf():
    """📄 Show current configuration."""
    try:
        config = load_config()
        masked_config = mask_sensitive_info(config)
        click.secho(yaml.dump(masked_config, default_flow_style=False), fg='cyan')
    except Exception as e:
        click.secho(f"❌ Error loading configuration: {str(e)}", fg='red')
        sys.exit(1)


@conf.command('validate')
def validate_configuration_command():
    """📄 Validate the current configuration."""
    logging.info("Validating configuration")
    try:
        validate_config(config)  # Using the existing validate_config function
        click.secho(f"✅ Configuration is valid.", fg='green')
        logging.info("✅ Configuration validation succeeded")
    except ValueError as e:
        click.secho(f"❌ Configuration validation failed: {str(e)}", fg='red')
        logging.error(f"❌ Configuration validation failed: {str(e)}")
        sys.exit(1)


def _open_private(path, mode):
    """Open a new file readable and writable by its owner only (0600)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.chmod(path, 0o600)  # also when the file already existed
    return os.fdopen(fd, mode)


@conf.command('backup')
@click.argument('destination_path', callback=_validate_pattern(_SAFE_PATH_RE, "destination path"))
@click.option('--timestamp', is_flag=True, help="Add a timestamp to the file name, before its extension.")
@click.option('--compress', is_flag=True, help="Compress the backup file with gzip.")
def backup_config(destination_path, timestamp, compress):
    """💾 Backup the current configuration to a file.

    The copy includes SSH passwords and the API key in clear text, so it is
    written with 0600 permissions.
    """
    # The file as it is, comments included. The in-memory configuration is not
    # used: without a config.yaml it is an empty fallback, not worth a backup.
    try:
        with open('config.yaml', 'rb') as source:
            content = source.read()
    except OSError as e:
        click.secho(f"❌ Cannot read config.yaml in {os.getcwd()}: {e.strerror}", fg='red')
        sys.exit(1)

    if timestamp:
        stem, ext = os.path.splitext(destination_path)
        destination_path = f"{stem}_{time.strftime('%Y%m%d%H%M%S')}{ext}"

    logging.info(f"Backing up configuration to {destination_path}")

    try:
        if compress:
            destination_path = f"{destination_path}.gz"
            with _open_private(destination_path, 'wb') as raw, gzip.GzipFile(fileobj=raw, mode='wb') as backup_file:
                backup_file.write(content)
        else:
            with _open_private(destination_path, 'wb') as backup_file:
                backup_file.write(content)

        click.secho(f"✅ Configuration backed up to {destination_path}.", fg='green')
        click.secho("⚠️ The file contains passwords and the API key in clear text.", fg='yellow')
        logging.info(f"✅ Configuration backed up to {destination_path}")
    except Exception as e:
        click.secho(f"❌ Error backing up configuration: {str(e)}", fg='red')
        logging.error(f"❌ Error backing up configuration: {str(e)}")
        sys.exit(1)


@lws.group()
@command_alias('lxc')
def lxc():
    """⚙️ Manage LXC containers."""
    pass


@lws.group()
@command_alias('px')
def px():
    """🌐 Manage Proxmox hosts."""
    pass


@px.command('list')
@click.option('--region', default=None, help='Filter hosts by region.')
def list_hosts(region):
    """🌐 List all available Proxmox hosts."""

    def resolve_host(host, timeout=0.2):
        """Resolve host with a timeout."""
        try:
            return socket.gethostbyname(host)
        except socket.gaierror:
            return None

    def check_tcp_port(host, port, timeout=0.2):
        """Check if a TCP port is open."""
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    def check_host_reachability(host):
        """Check host reachability with DNS timeout, TCP probe, and fallback ping."""
        resolved_ip = resolve_host(host)
        if not resolved_ip:
            return host, "🔴"  # DNS resolution failed

        if check_tcp_port(resolved_ip, 22):
            return host, "🟢"  # TCP port 22 is open
        else:
            # Fall back to ping
            try:
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '0.2', resolved_ip],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                if result.returncode == 0:
                    return host, "🟡"  # Host is reachable via ping, but port 22 is closed
                else:
                    return host, "🔴"  # Host is not reachable
            except subprocess.CalledProcessError:
                return host, "🔴"  # Host is not reachable

    def process_host(region, az, az_details):
        host = az_details['host']
        status_symbol = check_host_reachability(host)
        return f"{status_symbol[1]} -> Region: {region} - AZ: {az} - Host: {status_symbol[0]}"

    if not config.get('regions'):
        click.secho("❌ No regions found in configuration.", fg='red')
        return

    # Collect tasks for parallel execution
    tasks = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        for reg, details in config['regions'].items():
            if region and reg != region:
                continue
            for az, az_details in details.get('availability_zones', {}).items():
                tasks.append(executor.submit(process_host, reg, az, az_details))

        # Process results as they complete
        click.secho("Checking host availability...", fg='yellow')
        for future in tqdm(as_completed(tasks), total=len(tasks), desc="Checking hosts"):
            try:
                result = future.result()
                click.secho(result, fg='cyan')
            except Exception as e:
                click.secho(f"Error checking host: {e}", fg='red')

@px.command('reboot')
#@command_alias('proxmox-reboot')
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
@click.option('--confirm', is_flag=True, help="Confirm that you want to reboot the Proxmox host.")
def reboot_proxmox(region, az, confirm):
    """🔄 Reboot the Proxmox host.

    This command will reboot the entire Proxmox host. Use with caution.
    """

    if not confirm:
        click.secho("❗ Rebooting the Proxmox host is a critical action. Use the --confirm flag to proceed.", fg='red')
        return

    # Retrieve the host details from the configuration
    host_details = config['regions'][region]['availability_zones'][az]
    host = host_details['host']
    user = host_details['user']
    ssh_password = host_details['ssh_password']

    try:
        # Execute the SSH command to reboot the Proxmox host
        result = run_ssh_command(host, user, ssh_password, ["reboot"])

        if result.returncode == 0:
            click.secho(f"✅ Proxmox host {host} rebooted successfully.", fg='green')
        else:
            click.secho(f"❌ Failed to reboot Proxmox host {host}: {result.stderr}", fg='red')
            sys.exit(1)

    except Exception as e:
        click.secho(f"❌ An error occurred: {str(e)}", fg='red')
        sys.exit(1)



@px.command('upload')
#@command_alias('upload-template')
@click.argument('local_path')
@click.argument('remote_template_name', required=False, callback=_validate_pattern(_TEMPLATE_NAME_RE, "remote template name"))
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
@click.option('--storage-path', default='/var/lib/vz/template/cache', callback=_validate_pattern(_SAFE_PATH_RE, "storage path"), help="Remote path to upload the template. Defaults to Proxmox template directory.")
def upload_template(local_path, remote_template_name, region, az, storage_path):
    """💽 Upload template to Proxmox host.
    
    LOCAL_PATH: The path to the template file on your local machine.
    REMOTE_TEMPLATE_NAME: (Optional) The name under which the template will be stored on the Proxmox server. Defaults to the name of the local file.
    """

    # Use the local filename if remote_template_name is not provided
    if not remote_template_name:
        remote_template_name = os.path.basename(local_path)

    # Retrieve the host details from the configuration
    host_details = config['regions'][region]['availability_zones'][az]
    host = host_details['host']
    user = host_details['user']
    ssh_password = host_details['ssh_password']

    try:
        # Execute the SCP command to upload the template. No timeout: template
        # files can be multiple GB, and a fixed timeout meant for short remote
        # commands would abort a slow but otherwise healthy transfer.
        result = run_scp_command(ssh_password, local_path, f"{user}@{host}:{storage_path}/{remote_template_name}")

        if result.returncode == 0:
            click.secho(f"✅ Template '{remote_template_name}' uploaded successfully to {storage_path} on {host}.", fg='green')
        else:
            click.secho(f"❌ Failed to upload template: {result.stderr}", fg='red')
            sys.exit(1)

    except Exception as e:
        click.secho(f"❌ An error occurred: {str(e)}", fg='red')
        sys.exit(1)


@px.command('status')
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
def px_status(region, az):
    """📊 Monitor resource usage of a Proxmox host."""
    # click.secho(f"🔍 Debug: Loading configuration for region '{region}' and availability zone '{az}'", fg='yellow')
    
    config = load_config()
    host_details = config['regions'][region]['availability_zones'][az]
    
    # click.secho(f"🔍 Debug: Retrieved host details: {host_details}", fg='yellow')
    
    host = host_details['host']
    user = host_details['user']
    ssh_password = host_details['ssh_password']
    
    commands = {
        "Load Avg": ["cat", "/proc/loadavg"],
        "Memory Usage": ["cat", "/proc/meminfo"],
        "Disk Space": ["df", "-h", "/"],
        "Swap Space": ["cat", "/proc/swaps"]
    }
    
    for metric_name, command in commands.items():
        result = run_ssh_command(host, user, ssh_password, command)
        
        if result and result.returncode == 0:
            output = result.stdout.strip()
            
            if metric_name == "Load Avg":
                loadavg = output.split()[0:3]
                click.secho(f"📊 Proxmox {host} - {metric_name}: {' '.join(loadavg)}", fg='cyan')
            
            elif metric_name == "Memory Usage":
                meminfo_lines = output.splitlines()
                meminfo_dict = {line.split(":")[0]: line.split(":")[1].strip() for line in meminfo_lines if line}
                mem_total = meminfo_dict["MemTotal"].split()[0]
                mem_free = meminfo_dict["MemFree"].split()[0]
                mem_used = int(mem_total) - int(mem_free)
                click.secho(f"📊 Proxmox {host} - {metric_name}: Used {mem_used} kB / {mem_total} kB", fg='cyan')

            elif metric_name == "Disk Space":
                disk_info = output.splitlines()[1]  # Assuming the first line is headers
                click.secho(f"📊 Proxmox {host} - {metric_name}: {disk_info}", fg='cyan')

            elif metric_name == "Swap Space":
                swap_info_lines = output.splitlines()[1:]  # First line is header
                for swap_info in swap_info_lines:
                    swap_details = swap_info.split()
                    swap_name = swap_details[0]
                    swap_size = swap_details[2]
                    swap_used = swap_details[3]
                    click.secho(f"📊 Proxmox {host} - {metric_name}: {swap_used} kB used / {swap_size} kB total ({swap_name})", fg='cyan')

        else:
            click.secho(f"❌ Failed to retrieve {metric_name} on host {host}: {result.stderr if result else 'Unknown error'}", fg='red')

@px.command('clusters')
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
def px_list_clusters(region, az):
    """🔍 List all clusters in the Proxmox environment."""
    
    # Load configuration
    config = load_config()
    host_details = config['regions'][region]['availability_zones'][az]
    
    host = host_details['host']
    user = host_details['user']
    ssh_password = host_details['ssh_password']

    # Command to list cluster status using pvecm
    command = ["pvecm", "status"]

    # Execute the command on the Proxmox host using SSH
    result = run_ssh_command(host, user, ssh_password, command)

    # Output the result of the command
    if result.returncode == 0:
        click.secho(f"📋 Clusters:\n{result.stdout}", fg='cyan')
    else:
        click.secho(f"❌ Failed to list clusters: {result.stderr.strip()}", fg='red')
        sys.exit(1)


# Proxmox VE is upgraded with dist-upgrade (full-upgrade): plain `upgrade`
# never installs new dependencies, such as the next kernel package, and can
# leave a host half-updated. Existing configuration files are kept.
PX_UPGRADE_SCRIPT = (
    "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y "
    "-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold dist-upgrade"
)


@px.command('update')
@click.option('--region', '--location', default=None, help="Only hosts in this region. Default: every configured host.")
@click.option('--az', '--node', default=None, help="Only this availability zone (requires --region).")
@click.option('--yes', is_flag=True, help="Do not ask for confirmation.")
def px_update_hosts(region, az, yes):
    """🔄 Update the packages of Proxmox hosts (apt-get dist-upgrade)."""
    if az and not region:
        raise click.UsageError("--az requires --region.")
    targets = []
    for region_name, region_config in config.get('regions', {}).items():
        if region and region_name != region:
            continue
        for az_name, host_details in region_config.get('availability_zones', {}).items():
            if az and az_name != az:
                continue
            targets.append((region_name, az_name, host_details))
    if not targets:
        click.secho("❌ No matching hosts in config.yaml.", fg='red')
        sys.exit(1)
    if config.get('use_local_only'):
        # Local mode manages the host LWS runs on, once.
        targets = targets[:1]

    names = ", ".join(f"{r}/{a} ({h['host']})" for r, a, h in targets)
    if not yes:
        click.confirm(f"⚠️ Run apt-get dist-upgrade on: {names}?", abort=True)

    failed = []
    for region_name, az_name, host_details in targets:
        click.secho(f"🔄 Updating {region_name}/{az_name} ({host_details['host']})...", fg='cyan')
        result = run_argv(["sh", "-c", PX_UPGRADE_SCRIPT], config.get('use_local_only', False), host_details)
        if result.returncode == 0:
            click.secho(f"✅ {region_name}/{az_name} updated.", fg='green')
        else:
            click.secho(f"❌ Failed to update {region_name}/{az_name}: {result.stderr.strip()}", fg='red')
            failed.append(f"{region_name}/{az_name}")

    if failed:
        click.secho(f"❌ Update failed on: {', '.join(failed)}", fg='red')
        sys.exit(1)
    click.secho("✅ All selected hosts updated. A new kernel takes effect after a reboot.", fg='green')

@px.command('cluster-start')
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
def px_start_cluster_services(region, az):
    """🚀 Start all cluster services on Proxmox hosts."""

    # Load configuration
    config = load_config()
    host_details = config['regions'][region]['availability_zones'][az]
    
    host = host_details['host']
    user = host_details['user']
    ssh_password = host_details['ssh_password']

    # Command to start cluster services
    command = ["systemctl", "start", "pve-cluster", "corosync"]

    # Execute the command on the Proxmox host using SSH
    result = run_ssh_command(host, user, ssh_password, command)

    # Output the result of the command
    if result.returncode == 0:
        click.secho("✅ Cluster services started successfully.", fg='green')
    else:
        click.secho(f"❌ Failed to start cluster services on host {host}: {result.stderr.strip()}", fg='red')
        sys.exit(1)

@px.command('cluster-stop')
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
def px_stop_cluster_services(region, az):
    """🛑 Stop all cluster services on Proxmox hosts."""

    # Load configuration
    config = load_config()
    host_details = config['regions'][region]['availability_zones'][az]
    
    host = host_details['host']
    user = host_details['user']
    ssh_password = host_details['ssh_password']

    # Command to stop cluster services
    command = ["systemctl", "stop", "pve-cluster", "corosync"]

    # Execute the command on the Proxmox host using SSH
    result = run_ssh_command(host, user, ssh_password, command)

    # Output the result of the command
    if result.returncode == 0:
        click.secho("✅ Cluster services stopped successfully.", fg='green')
    else:
        click.secho(f"❌ Failed to stop cluster services on host {host}: {result.stderr.strip()}", fg='red')
        sys.exit(1)

@px.command('cluster-restart')
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
def px_restart_cluster_services(region, az):
    """🔄 Restart all cluster services on Proxmox hosts."""

    # Load configuration
    config = load_config()
    host_details = config['regions'][region]['availability_zones'][az]
    
    host = host_details['host']
    user = host_details['user']
    ssh_password = host_details['ssh_password']

    # Command to restart cluster services
    command = ["systemctl", "restart", "pve-cluster", "corosync"]

    # Execute the command on the Proxmox host using SSH
    result = run_ssh_command(host, user, ssh_password, command)

    # Output the result of the command
    if result.returncode == 0:
        click.secho("✅ Cluster services restarted successfully.", fg='green')
    else:
        click.secho(f"❌ Failed to restart cluster services on host {host}: {result.stderr.strip()}", fg='red')
        sys.exit(1)



@px.command('backup-lxc')
@click.argument('vmid', callback=_validate_pattern(_VMID_RE, "vmid"))
@click.option('--storage', required=True, callback=_validate_pattern(_SAFE_NAME_RE, "storage"), help="The storage target where the backup will be stored.")
@click.option('--mode', default='snapshot', type=click.Choice(['snapshot', 'suspend', 'stop']), help="Backup mode: snapshot, suspend, or stop.")
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
def px_create_backup(vmid, storage, mode, region, az):
    """💾 Create a backup of a specific LXC container."""
    
    # Load configuration
    config = load_config()
    host_details = config['regions'][region]['availability_zones'][az]
    host = host_details['host']
    user = host_details['user']
    ssh_password = host_details['ssh_password']

    # Command to create the backup
    backup_cmd = ["vzdump", vmid, "--storage", storage, "--mode", mode]

    # Execute the backup command on the Proxmox host
    result = run_ssh_command(host, user, ssh_password, backup_cmd)

    # Output the result of the command
    if result.returncode == 0:
        click.secho(f"✅ Backup of instance {vmid} successfully created and stored on {storage}.", fg='green')
    else:
        click.secho(f"❌ Failed to create backup of instance {vmid}: {result.stderr.strip()}", fg='red')
        sys.exit(1)


# lxc

# Command to run LXC instances

@lxc.command('run')
@click.option('--image-id', required=True, help="ID of the container image template.")
@click.option('--count', default=1, help="Number of instances to run.")
@click.option('--size', default='small', type=click.Choice(list(config['instance_sizes'].keys())), help="Instance size.")
@click.option('--hostname', default=None, help="Hostname for the container.")
@click.option('--net0', default=f"name=eth0,bridge={config.get('default_network', 'vmbr0')}", help="Network settings for the container.")
@click.option('--storage-size', default=None, callback=_validate_pattern(re.compile(r'^\d+(\.\d+)?G?$'), "storage size"), help="Root disk size in GiB, replacing the size's own (e.g., 16). Uses default_storage.")
@click.option('--features', default=None, callback=_validate_pattern(re.compile(r'^[a-z]+=[0-9a-z;]+(,[a-z]+=[0-9a-z;]+)*$'), "features"), help="LXC features, e.g. nesting=1 (needed for Docker) or nesting=1,keyctl=1.")
@click.option('--unprivileged', is_flag=True, help="Create an unprivileged container (recommended by Proxmox).")
@click.option('--onboot', default=config.get('default_onboot', True), help="Start the container on boot.")
@click.option('--lock', default=None, help="Set lock for the container. By default, no lock is set.")
@click.option('--init', default=False, is_flag=True, help="Run initialization script after container creation.")
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1.")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1.")
@click.option('--max-retries', default=5, help="Maximum number of retries to start the container.")
@click.option('--retry-delay', default=5, help="Delay in seconds between retries.")
@click.option('--password', default=None, help="Set the root password for the container.")
@click.option('--ip', default=None, help="Set a fixed IP address for the container (e.g., 192.168.1.100).")
@click.option('--netmask', default='24', help="Set the netmask for the fixed IP address. Default is 24.")
@click.option('--gateway', default=None, help="Set the gateway for the container's network.")
@click.option('--dns', default=None, help="Set DNS servers for the container (comma-separated).")
@click.option('--dhcp', is_flag=True, default=False, help="Enable DHCP for the container.")
def run_instances(image_id, count, size, hostname, net0, storage_size, features, unprivileged, onboot, lock, init, region, az, max_retries, retry_delay, password, ip, netmask, gateway, dns, dhcp):
    """🛠️ Create and start LXC containers with optional network configuration, root password, gateway, and DNS settings."""
    start_vmid = config.get('start_vmid', 10000)
    instance_config = config['instance_sizes'][size]
    storage = instance_config['storage']

    if storage_size:
        # Proxmox reads STORAGE:SIZE as a size in GiB, without a unit.
        storage = f"{config['default_storage']}:{storage_size.rstrip('G')}"

    # One net0 value: --dhcp and --ip add to the base definition.
    if dhcp:
        net0 = f"{net0},ip=dhcp"
    elif ip:
        net0 = f"{net0},ip={ip}/{netmask}" + (f",gw={gateway}" if gateway else "")

    host_details = config['regions'][region]['availability_zones'][az]

    for i in range(count):
        instance_id = get_next_vmid(start_vmid=start_vmid, use_local_only=config['use_local_only'], host_details=host_details)
        create_cmd = [
            "pct", "create", str(instance_id),
            image_id,
            "--memory", str(instance_config['memory']),
            "--cpulimit", str(instance_config['cpulimit']),
            "--net0", net0,
            "--rootfs", storage,
            "--onboot", str(int(onboot))
        ]

        if lock:
            create_cmd.extend(["--lock", lock])

        if hostname:
            create_cmd.extend(["--hostname", f"{hostname}-{instance_id}"])

        if password:
            create_cmd.extend(["--password", password])

        if features:
            create_cmd.extend(["--features", features])

        if unprivileged:
            create_cmd.extend(["--unprivileged", "1"])

        # Add DNS settings if provided (pct takes a space-separated list)
        if dns:
            create_cmd.extend(["--nameserver", dns.replace(",", " ")])

        # create_cmd runs unmodified when local (no shell involved - quoting
        # would corrupt the values, not protect them). When remote, OpenSSH
        # joins every argv element after user@host into one string for the
        # remote shell, so free-text values here (hostname, password, dns,
        # net0, ...) are a command-injection vector despite never passing
        # through a local shell themselves - shlex.quote on this remote-only
        # copy closes that without constraining what a valid value can
        # contain (it's a no-op for any value that doesn't need quoting).
        remote_create_cmd = [shlex.quote(str(part)) for part in create_cmd]
        create_result = run_proxmox_command(create_cmd, remote_create_cmd, config['use_local_only'], host_details)

        if create_result.returncode == 0:
            click.secho(f"✅ Instance {instance_id} created successfully.", fg='green')
            
            # Retry logic for starting the container
            for attempt in range(max_retries):
                if is_container_locked(instance_id, host_details):
                    click.secho(f"🔄 Instance {instance_id} is locked. Retrying in {retry_delay} seconds... (Attempt {attempt + 1}/{max_retries})", fg='yellow')
                    time.sleep(retry_delay)
                else:
                    start_result = run_proxmox_command(
                        ["pct", "start", str(instance_id)],
                        ["pct", "start", str(instance_id)],
                        config['use_local_only'],
                        host_details
                    )
                    if start_result.returncode == 0:
                        click.secho(f"🚀 Instance {instance_id} started.", fg='green')
                        
                        # Run an initialization script if the --init flag is set
                        if init:
                            init_cmd = ["pct", "exec", str(instance_id), "--", "/path/to/init-script.sh"]
                            init_result = run_proxmox_command(init_cmd, init_cmd, config['use_local_only'], host_details)
                            if init_result.returncode == 0:
                                click.secho(f"🔧 Initialization script executed successfully on {instance_id}.", fg='green')
                            else:
                                click.secho(f"❌ Failed to execute initialization script on {instance_id}: {init_result.stderr}", fg='red')

                        break
                    else:
                        click.secho(f"❌ Failed to start instance {instance_id}: {start_result.stderr}", fg='red')
                        break
            else:
                click.secho(f"❌ Failed to start instance {instance_id} after {max_retries} attempts.", fg='red')
        else:
            click.secho(f"❌ Failed to create instance {instance_id}: {create_result.stderr}", fg='red')



@lxc.command('stop')
@click.argument('instance_ids', nargs=-1, callback=_validate_pattern(_VMID_RE, "instance id"))
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
def stop_instances(instance_ids, region, az):
    """🛑 Stop running LXC containers."""
    process_instance_command(instance_ids, 'stop', region, az)

@lxc.command('terminate')
@click.argument('instance_ids', nargs=-1, callback=_validate_pattern(_VMID_RE, "instance id"))
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
def terminate_instances(instance_ids, region, az):
    """💥 Terminate (destroy) LXC containers."""
    process_instance_command(instance_ids, 'terminate', region, az)

@lxc.command('show')
@click.argument('instance_ids', nargs=-1, required=False, callback=_validate_pattern(_VMID_RE, "instance id"))
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
def describe_instances(instance_ids, region, az):
    """🔍 Describe LXC containers."""
    if instance_ids:
        process_instance_command(instance_ids, 'describe', region, az)
    else:
        host_details = config['regions'][region]['availability_zones'][az]
        list_result = run_proxmox_command(["pct", "list"], ["pct", "list"], config['use_local_only'], host_details)
        
        if list_result.returncode == 0:
            click.secho(f"📋 Instances:\n{list_result.stdout}", fg='cyan')
        else:
            click.secho(f"❌ Failed to list instances: {list_result.stderr}", fg='red')
            sys.exit(1)

_DISK_SIZE_RE = re.compile(r'^\+?\d+(\.\d+)?[KMGT]?$')


@lxc.command('scale')
@click.argument('instance_ids', nargs=-1, required=True, callback=_validate_pattern(_VMID_RE, "instance id"))
@click.option('--memory', type=click.IntRange(min=16), default=None, help="Memory in MB.")
@click.option('--cpulimit', type=click.FloatRange(min=0, max=8192), default=None, help="CPU time limit, in CPUs (0 removes the limit).")
@click.option('--cpucores', type=click.IntRange(min=1, max=8192), default=None, help="Number of CPU cores the container sees.")
@click.option('--storage-size', default=None, callback=_validate_pattern(_DISK_SIZE_RE, "storage size"),
              help="New root disk size, such as 32G, or +8G to add 8 GiB. Disks can only grow.")
@click.option('--net-limit', type=click.FloatRange(min=0), default=None, help="Rate limit of net0, in MB/s (0 removes the limit).")
@click.option('--disk-read-limit', default=None, hidden=True)
@click.option('--disk-write-limit', default=None, hidden=True)
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
def scale_instances(instance_ids, memory, cpulimit, cpucores, storage_size, net_limit, disk_read_limit, disk_write_limit, region, az):
    """📏 Change the CPU, memory, disk and network limits of LXC containers."""
    if disk_read_limit or disk_write_limit:
        raise click.UsageError("--disk-read-limit and --disk-write-limit were removed: Proxmox has no "
                               "disk bandwidth limits for containers.")
    if all(v is None for v in (memory, cpulimit, cpucores, storage_size, net_limit)):
        raise click.UsageError("Nothing to change: pass at least one of --memory, --cpulimit, --cpucores, "
                               "--storage-size, --net-limit.")

    host_details = _host_details(region, az)
    use_local = config['use_local_only']
    failed = []

    for instance_id in instance_ids:
        set_cmd = ["pct", "set", instance_id]
        if memory is not None:
            set_cmd += ["--memory", str(memory)]
        if cpulimit is not None:
            set_cmd += ["--cpulimit", f"{cpulimit:g}"]
        if cpucores is not None:
            set_cmd += ["--cores", str(cpucores)]
        if net_limit is not None:
            # net0 is replaced as a whole, so the rate goes into the current definition.
            current = run_argv(["pct", "config", instance_id], use_local, host_details)
            net0 = next((line.split(":", 1)[1].strip() for line in current.stdout.splitlines()
                         if line.startswith("net0:")), None) if current.returncode == 0 else None
            if not net0:
                click.secho(f"❌ Container {instance_id} has no net0 to limit.", fg='red')
                failed.append(instance_id)
                continue
            options = [o for o in net0.split(",") if o and not o.startswith("rate=")]
            if net_limit > 0:
                options.append(f"rate={net_limit:g}")
            set_cmd += ["--net0", ",".join(options)]

        if len(set_cmd) > 3:
            result = run_argv(set_cmd, use_local, host_details)
            if result.returncode != 0:
                click.secho(f"❌ Failed to scale instance '{instance_id}': {result.stderr.strip()}", fg='red')
                failed.append(instance_id)
                continue

        if storage_size:
            size = storage_size if storage_size[-1] in "KMGT" else f"{storage_size}G"
            result = run_argv(["pct", "resize", instance_id, "rootfs", size], use_local, host_details)
            if result.returncode != 0:
                click.secho(f"❌ Failed to resize the disk of '{instance_id}': {result.stderr.strip()}", fg='red')
                failed.append(instance_id)
                continue

        click.secho(f"✅ Instance '{instance_id}' successfully scaled.", fg='green')

    if failed:
        sys.exit(1)


@lxc.command('snapshot-add')
@click.argument('instance_id', callback=_validate_pattern(_VMID_RE, "instance id"))
@click.argument('snapshot_name')
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
def create_snapshot(instance_id, snapshot_name, region, az):
    """📸 Create a snapshot of an LXC container."""
    process_instance_command([instance_id], 'snapshot_create', region, az, snapshot_name=snapshot_name)

@lxc.command('snapshot-rm')
@click.argument('instance_id', callback=_validate_pattern(_VMID_RE, "instance id"))
@click.argument('snapshot_name')
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
def delete_snapshot(instance_id, snapshot_name, region, az):
    """🗑️ Delete a snapshot of an LXC container."""
    process_instance_command([instance_id], 'snapshot_delete', region, az, snapshot_name=snapshot_name)

@lxc.command('snapshots')
@click.argument('instance_id', callback=_validate_pattern(_VMID_RE, "instance id"))
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Defaults to eu-south-1.")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Defaults to az1.")
@click.option('--use-local-only', is_flag=False, help="Execute the command locally instead of via SSH.")
def snapshots(instance_id, region, az, use_local_only):
    """🗃️ List all snapshots of an LXC container."""
    # Get the host details from the configuration
    host_details = config['regions'][region]['availability_zones'][az]

    # Command to list snapshots locally on the Proxmox node
    local_cmd = ["pct", "listsnapshot", instance_id]
    
    # Command to list snapshots remotely via SSH
    remote_cmd = ["pct", "listsnapshot", instance_id]

    # Execute the command using the run_proxmox_command utility
    result = run_proxmox_command(local_cmd, remote_cmd, use_local_only, host_details)

    if result is not None and result.returncode == 0:
        click.echo(result.stdout)
    else:
        click.echo(f"Failed to list snapshots for LXC container {instance_id}.")

@lxc.command('start')
@click.argument('instance_ids', nargs=-1, callback=_validate_pattern(_VMID_RE, "instance id"))
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
def start_instances(instance_ids, region, az):
    """🚀 Start stopped LXC containers."""
    process_instance_command(instance_ids, 'start', region, az)

@lxc.command('reboot')
@click.argument('instance_ids', nargs=-1, callback=_validate_pattern(_VMID_RE, "instance id"))
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
def reboot_instances(instance_ids, region, az):
    """🔄 Reboot running LXC containers."""
    process_instance_command(instance_ids, 'reboot', region, az)

@px.command('image-add')
@click.argument('instance_id', callback=_validate_pattern(_VMID_RE, "instance id"))
@click.argument('template_name')
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
def create_image(instance_id, template_name, region, az):
    """📦 Create a template image from an LXC container."""
    host_details = config['regions'][region]['availability_zones'][az]

    # Stop the instance before converting to a template
    stop_result = run_proxmox_command(["pct", "shutdown", instance_id], ["pct", "shutdown", instance_id], config['use_local_only'], host_details)

    if stop_result.returncode == 0:
        click.secho(f"🛑 Instance {instance_id} stopped for templating.", fg='green')

        # Corrected command to create a template
        create_template_result = run_proxmox_command(
            ["pct", "template", instance_id],
            ["pct", "template", instance_id],
            config['use_local_only'], host_details
        )

        if create_template_result.returncode == 0:
            click.secho(f"✅ Template '{template_name}' created successfully from instance {instance_id}.", fg='green')
        else:
            click.secho(f"❌ Failed to create template: {create_template_result.stderr}", fg='red')
            sys.exit(1)
    else:
        click.secho(f"❌ Failed to stop instance {instance_id}: {stop_result.stderr}", fg='red')
        sys.exit(1)

@px.command('image-rm')
@click.argument('template_name', callback=_validate_pattern(_TEMPLATE_NAME_RE, "template name"))
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
def delete_image(template_name, region, az):
    """🗑️ Delete a template image from Proxmox host."""
    host_details = config['regions'][region]['availability_zones'][az]

    # Command to delete the template
    delete_cmd = f"rm /var/lib/vz/template/cache/{template_name}.tar.gz"

    # Execute the delete command on the Proxmox host using SSH
    result = run_ssh_command(host_details['host'], host_details['user'], host_details['ssh_password'], [delete_cmd])

    # Output the result of the command
    if result.returncode == 0:
        click.secho(f"✅ Template '{template_name}' successfully deleted from host {host_details['host']}.", fg='green')
    else:
        click.secho(f"❌ Failed to delete template '{template_name}' on host {host_details['host']}: {result.stderr.strip()}", fg='red')
        sys.exit(1)


@lxc.command('volume-attach')
@click.argument('instance_id', callback=_validate_pattern(_VMID_RE, "instance id"))
@click.argument('volume_name')
@click.argument('volume_size')
@click.option('--mount-point', default=None, help="The mount point for the volume inside the container (e.g., /mnt/data).")
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
def attach_volume(instance_id, volume_name, volume_size, mount_point, region, az):
    """🔗 Attach a storage volume to an LXC container."""
    
    if not mount_point:
        click.secho("❌ Mount point is required to attach the volume.", fg='red')
        return
    
    # Build the command to attach the volume
    attach_cmd = ["pct", "set", instance_id, f"--mp0={volume_name}:{volume_size},mp={mount_point}"]
    
    # Retrieve the host details from the configuration
    host_details = config['regions'][region]['availability_zones'][az]
    host = host_details['host']
    user = host_details['user']
    ssh_password = host_details['ssh_password']
    
    # Execute the attach volume command on the Proxmox host using SSH
    result = run_proxmox_command(attach_cmd, attach_cmd, config['use_local_only'], host_details)
    
    # Output the result of the command
    if result.returncode == 0:
        click.secho(f"✅ Volume '{volume_name}' of size '{volume_size}' successfully attached to instance '{instance_id}' at mount point '{mount_point}'.", fg='green')
    else:
        click.secho(f"❌ Failed to attach volume '{volume_name}' to instance '{instance_id}': {result.stderr.strip()}", fg='red')
        sys.exit(1)

@lxc.command('volume-detach')
@click.argument('instance_id', callback=_validate_pattern(_VMID_RE, "instance id"))
@click.argument('volume_name')
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
def detach_volume(instance_id, volume_name, region, az):
    """🔓 Detach a storage volume from an LXC container."""
    
    # Build the command to detach the volume
    detach_cmd = ["pct", "set", instance_id, f"--delete=mp0"]
    
    # Retrieve the host details from the configuration
    host_details = config['regions'][region]['availability_zones'][az]
    host = host_details['host']
    user = host_details['user']
    ssh_password = host_details['ssh_password']
    
    # Execute the detach volume command on the Proxmox host using SSH
    result = run_proxmox_command(detach_cmd, detach_cmd, config['use_local_only'], host_details)
    
    # Output the result of the command
    if result.returncode == 0:
        click.secho(f"✅ Volume '{volume_name}' successfully detached from instance '{instance_id}'.", fg='green')
    else:
        click.secho(f"❌ Failed to detach volume '{volume_name}' from instance '{instance_id}': {result.stderr.strip()}", fg='red')
        sys.exit(1)

@lxc.command('status')
@click.argument('instance_ids', nargs=-1, callback=_validate_pattern(_VMID_RE, "instance id"))
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
def monitor_instances(instance_ids, region, az):
    """📊 Monitor resources of LXC containers."""
    host_details = config['regions'][region]['availability_zones'][az]

    for instance_id in instance_ids:
        # Commands to get various system metrics
        loadavg_cmd = ["pct", "exec", instance_id, "--", "cat", "/proc/loadavg"]
        meminfo_cmd = ["pct", "exec", instance_id, "--", "cat", "/proc/meminfo"]
        disk_cmd = ["pct", "exec", instance_id, "--", "df", "-h", "/"]  # For free disk space on root
        swap_cmd = ["pct", "exec", instance_id, "--", "cat", "/proc/swaps"]  # For swap space

        # Execute all commands
        loadavg_result = run_proxmox_command(loadavg_cmd, loadavg_cmd, config['use_local_only'], host_details)
        meminfo_result = run_proxmox_command(meminfo_cmd, meminfo_cmd, config['use_local_only'], host_details)
        disk_result = run_proxmox_command(disk_cmd, disk_cmd, config['use_local_only'], host_details)
        swap_result = run_proxmox_command(swap_cmd, swap_cmd, config['use_local_only'], host_details)

        if all(result.returncode == 0 for result in [loadavg_result, meminfo_result, disk_result, swap_result]):
            # Load average
            loadavg = loadavg_result.stdout.strip().split()[0:3]
            click.secho(f"📊 Instance {instance_id} - Load Avg: {' '.join(loadavg)}", fg='cyan')

            # Memory usage
            meminfo_lines = meminfo_result.stdout.strip().splitlines()
            meminfo_dict = {line.split(":")[0]: line.split(":")[1].strip() for line in meminfo_lines if line}
            memory_used = int(meminfo_dict["MemTotal"].split()[0]) - int(meminfo_dict["MemFree"].split()[0])
            memory_total = int(meminfo_dict["MemTotal"].split()[0])
            click.secho(f"📊 Instance {instance_id} - Memory Usage: {memory_used} kB / {memory_total} kB", fg='cyan')

            # Free disk space
            disk_info = disk_result.stdout.strip().splitlines()[1]  # Assuming the first line is headers
            click.secho(f"📊 Instance {instance_id} - Disk Space: {disk_info}", fg='cyan')

            # Swap space usage
            swap_info_lines = swap_result.stdout.strip().splitlines()[1:]  # First line is header
            for swap_info in swap_info_lines:
                swap_details = swap_info.split()
                swap_name = swap_details[0]
                swap_size = swap_details[2]
                swap_used = swap_details[3]
                click.secho(f"📊 Instance {instance_id} - Swap Space ({swap_name}): Used {swap_used} / {swap_size}", fg='cyan')

        else:
            click.secho(f"❌ Failed to monitor instance {instance_id}:", fg='red')
            if loadavg_result.returncode != 0:
                click.secho(f"  Load Avg Error: {loadavg_result.stderr.strip()}", fg='red')
            if meminfo_result.returncode != 0:
                click.secho(f"  Mem Info Error: {meminfo_result.stderr.strip()}", fg='red')
            if disk_result.returncode != 0:
                click.secho(f"  Disk Space Error: {disk_result.stderr.strip()}", fg='red')
            if swap_result.returncode != 0:
                click.secho(f"  Swap Space Error: {swap_result.stderr.strip()}", fg='red')


@lxc.command('service')
@click.argument('action', type=click.Choice(['status', 'start', 'stop', 'restart', 'reload', 'enable']))
@click.argument('service_name', callback=_validate_pattern(_SERVICE_NAME_RE, "service name"))
@click.argument('instance_ids', nargs=-1, callback=_validate_pattern(_VMID_RE, "instance id"))
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
def service(action, service_name, instance_ids, region, az):
    """🔧 Manage a service of LXC containers."""
    host_details = config['regions'][region]['availability_zones'][az]

    for instance_id in instance_ids:
        # Construct the command based on the action
        service_cmd = ["pct", "exec", instance_id, "--", "systemctl", action, service_name]

        # Execute the command
        result = run_proxmox_command(service_cmd, service_cmd, config['use_local_only'], host_details)

        # Handle the output based on the action
        if result.returncode == 0:
            if action == 'status':
                click.secho(f"📊 Instance {instance_id} - Service '{service_name}' status:\n{result.stdout}", fg='cyan')
            else:
                click.secho(f"✅ Instance {instance_id} - '{service_name}' {action} successfully executed.", fg='green')
        else:
            click.secho(f"❌ Instance {instance_id} - Failed to {action} service '{service_name}': {result.stderr.strip()}", fg='red')


@lxc.command('migrate')
@click.argument('instance_id', callback=_validate_pattern(_VMID_RE, "instance id"))
@click.option('--target-host', required=True, callback=_validate_pattern(_HOSTNAME_RE, "target host"), help="Name of the Proxmox node, in the same cluster, to move the container to.")
@click.option('--restart', is_flag=True, help="Migrate a running container: stop it, move it, start it on the target (pct migrate --restart).")
@click.option('--target-storage', default=None, callback=_validate_pattern(_SAFE_NAME_RE, "target storage"), help="Storage on the target node for the container's disks.")
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
def lxc_migrate(instance_id, target_host, restart, target_storage, region, az):
    """🔄 Migrate an LXC container to another node of the same Proxmox cluster."""
    host_details = _host_details(region, az)

    migrate_cmd = ["pct", "migrate", instance_id, target_host]
    if restart:
        migrate_cmd.append("--restart")
    if target_storage:
        migrate_cmd += ["--target-storage", target_storage]

    # Runs on the source node; Proxmox moves the data between nodes itself.
    result = run_argv(migrate_cmd, config['use_local_only'], host_details)

    # Output the result of the command
    if result.returncode == 0:
        click.secho(f"✅ Instance {instance_id} successfully migrated to {target_host}.", fg='green')
    else:
        click.secho(f"❌ Failed to migrate instance {instance_id} to {target_host}: {result.stderr.strip()}", fg='red')
        sys.exit(1)


# --- Firewall security groups -------------------------------------------------
# These commands go through pvesh, the command-line client of the Proxmox VE
# API that every host has. The API validates rules, numbers them, writes
# /etc/pve/firewall/*.fw atomically and refuses to delete a group that still
# has rules. Editing those files with sed, as earlier versions did, could
# delete neighbouring groups and wrote group references in the disabled form.

_REGION_OPTION = click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
_AZ_OPTION = click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
_RULE_FIELDS = ('type', 'action', 'proto', 'sport', 'dport', 'source', 'dest')


def _host_details(region, az):
    try:
        return config['regions'][region]['availability_zones'][az]
    except KeyError:
        click.secho(f"❌ Invalid region '{region}' or availability zone '{az}'.", fg='red')
        sys.exit(1)


def pvesh(verb, path, host_details, **params):
    """Run `pvesh <verb> <path> --key value ...`; None values are left out."""
    argv = ["pvesh", verb, path]
    for key, value in params.items():
        if value is not None:
            argv += [f"--{key}", str(value)]
    return run_argv(argv, config['use_local_only'], host_details)


def pvesh_json(path, host_details):
    """`pvesh get <path>` parsed as JSON; exits with a message if it fails."""
    result = run_argv(["pvesh", "get", path, "--output-format", "json"], config['use_local_only'], host_details)
    if result.returncode != 0:
        click.secho(f"❌ pvesh get {path} failed: {result.stderr.strip()}", fg='red')
        sys.exit(1)
    try:
        return json.loads(result.stdout or "null")
    except ValueError:
        click.secho(f"❌ Unexpected output from pvesh get {path}.", fg='red')
        sys.exit(1)


def proxmox_node_name(host_details):
    """The node name Proxmox uses for this host (its short hostname)."""
    result = run_argv(["hostname"], config['use_local_only'], host_details)
    name = result.stdout.strip().split('.')[0] if result.returncode == 0 else ""
    if not name:
        click.secho(f"❌ Could not read the host name: {result.stderr.strip()}", fg='red')
        sys.exit(1)
    return name


def _rule_fields(direction, action, protocol, source_ip, source_port, destination_ip, destination_port):
    return {
        'type': direction.lower(), 'action': action, 'proto': protocol,
        'sport': source_port, 'dport': destination_port,
        'source': source_ip, 'dest': destination_ip,
    }


def _describe_rule(fields):
    """A rule as one line, in the order Proxmox shows it in its .fw files."""
    parts = [str(fields.get('type', '')).upper(), str(fields.get('action', ''))]
    labels = (('macro', '-macro'), ('proto', '-p'), ('source', '--source'), ('sport', '--sport'),
              ('dest', '--dest'), ('dport', '--dport'))
    parts += [f"{flag} {fields[key]}" for key, flag in labels if fields.get(key)]
    return " ".join(p for p in parts if p)


def _rule_options(func):
    for decorator in reversed([
        click.option('--direction', type=click.Choice(['IN', 'OUT'], case_sensitive=False), required=True, help="Direction of the rule (IN or OUT)."),
        click.option('--action', type=click.Choice(['ACCEPT', 'DROP', 'REJECT'], case_sensitive=False), default='ACCEPT', help="Action of the rule. Default: ACCEPT."),
        click.option('--protocol', default='tcp', callback=_validate_pattern(_PROTOCOL_RE, "protocol"), help="Protocol (e.g., tcp, udp, icmp). Default: tcp."),
        click.option('--source-ip', default=None, callback=_validate_ip_or_cidr, help="Source IP or CIDR."),
        click.option('--source-port', default=None, callback=_validate_pattern(_PORT_RE, "source port"), help="Source port or range (e.g., 22, 80:443)."),
        click.option('--destination-ip', default=None, callback=_validate_ip_or_cidr, help="Destination IP or CIDR."),
        click.option('--destination-port', default=None, callback=_validate_pattern(_PORT_RE, "destination port"), help="Destination port or range (e.g., 22, 80:443)."),
    ]):
        func = decorator(func)
    return func


@px.command('security-group-add')
@click.argument('group_name', callback=_validate_pattern(_SAFE_NAME_RE, "group name"))
@click.option('--description', default=None, callback=_validate_pattern(_SAFE_FREETEXT_RE, "description"), help="Description of the security group.")
@_REGION_OPTION
@_AZ_OPTION
def create_security_group(group_name, description, region, az):
    """🔐 Create a security group in the cluster firewall."""
    host_details = _host_details(region, az)
    result = pvesh("create", "/cluster/firewall/groups", host_details, group=group_name, comment=description or None)
    if result.returncode == 0:
        click.secho(f"✅ Security group '{group_name}' created.", fg='green')
    else:
        click.secho(f"❌ Failed to create security group '{group_name}': {result.stderr.strip()}", fg='red')
        sys.exit(1)


@px.command('security-group-rm')
@click.argument('group_name', callback=_validate_pattern(_SAFE_NAME_RE, "group name"))
@click.option('--force', is_flag=True, help="Also delete the group's rules. Without it, a group that has rules is not deleted.")
@_REGION_OPTION
@_AZ_OPTION
def delete_security_group(group_name, force, region, az):
    """🗑️ Delete a security group from the cluster firewall."""
    host_details = _host_details(region, az)
    rules = pvesh_json(f"/cluster/firewall/groups/{group_name}", host_details) or []
    if rules and not force:
        click.secho(f"❌ Security group '{group_name}' has {len(rules)} rule(s). Remove them first, or pass --force.", fg='red')
        sys.exit(1)
    # Highest position first, so the remaining positions do not shift.
    for rule in sorted(rules, key=lambda r: int(r['pos']), reverse=True):
        result = pvesh("delete", f"/cluster/firewall/groups/{group_name}/{int(rule['pos'])}", host_details)
        if result.returncode != 0:
            click.secho(f"❌ Failed to delete rule {rule['pos']} of '{group_name}': {result.stderr.strip()}", fg='red')
            sys.exit(1)
    result = pvesh("delete", f"/cluster/firewall/groups/{group_name}", host_details)
    if result.returncode == 0:
        click.secho(f"✅ Security group '{group_name}' deleted.", fg='green')
    else:
        click.secho(f"❌ Failed to delete security group '{group_name}': {result.stderr.strip()}", fg='red')
        sys.exit(1)


@px.command('security-group-rule-add')
@click.argument('group_name', callback=_validate_pattern(_SAFE_NAME_RE, "group name"))
@_rule_options
@_REGION_OPTION
@_AZ_OPTION
def add_security_group_rule(group_name, direction, action, protocol, source_ip, source_port, destination_ip, destination_port, region, az):
    """➕ Add a rule to an existing security group."""
    host_details = _host_details(region, az)
    fields = _rule_fields(direction, action.upper(), protocol, source_ip, source_port, destination_ip, destination_port)
    result = pvesh("create", f"/cluster/firewall/groups/{group_name}", host_details, enable=1, **fields)
    if result.returncode == 0:
        click.secho(f"✅ Rule '{_describe_rule(fields)}' added to security group '{group_name}'.", fg='green')
    else:
        click.secho(f"❌ Failed to add the rule to '{group_name}': {result.stderr.strip()}", fg='red')
        sys.exit(1)


@px.command('security-group-rule-rm')
@click.argument('group_name', callback=_validate_pattern(_SAFE_NAME_RE, "group name"))
@_rule_options
@_REGION_OPTION
@_AZ_OPTION
def remove_security_group_rule(group_name, direction, action, protocol, source_ip, source_port, destination_ip, destination_port, region, az):
    """➖ Remove a rule from a security group.

    Removes the rules whose direction, action, protocol, addresses and ports
    are exactly the ones given; options left out must be absent from the rule.
    """
    host_details = _host_details(region, az)
    wanted = _rule_fields(direction, action.upper(), protocol, source_ip, source_port, destination_ip, destination_port)
    rules = pvesh_json(f"/cluster/firewall/groups/{group_name}", host_details) or []
    matches = [r for r in rules if all(str(r.get(k) or '') == str(wanted[k] or '') for k in _RULE_FIELDS)]
    if not matches:
        click.secho(f"❌ No rule '{_describe_rule(wanted)}' in security group '{group_name}'.", fg='red')
        sys.exit(1)
    for rule in sorted(matches, key=lambda r: int(r['pos']), reverse=True):
        result = pvesh("delete", f"/cluster/firewall/groups/{group_name}/{int(rule['pos'])}", host_details)
        if result.returncode != 0:
            click.secho(f"❌ Failed to remove the rule from '{group_name}': {result.stderr.strip()}", fg='red')
            sys.exit(1)
    click.secho(f"✅ Removed {len(matches)} rule(s) '{_describe_rule(wanted)}' from '{group_name}'.", fg='green')


def _enable_container_firewall(vmid, node, host_details):
    """Turn on the container's firewall and the firewall flag of each of its NICs."""
    result = pvesh("set", f"/nodes/{node}/lxc/{vmid}/firewall/options", host_details, enable=1)
    if result.returncode != 0:
        click.secho(f"❌ Failed to enable the firewall of container {vmid}: {result.stderr.strip()}", fg='red')
        sys.exit(1)
    ct_config = pvesh_json(f"/nodes/{node}/lxc/{vmid}/config", host_details) or {}
    for key in sorted(k for k in ct_config if re.fullmatch(r'net\d+', k)):
        current = [o for o in str(ct_config[key]).split(',') if o]
        if 'firewall=1' in current:
            continue
        updated = [o for o in current if not o.startswith('firewall=')] + ['firewall=1']
        result = run_argv(["pct", "set", vmid, f"--{key}", ",".join(updated)],
                          config['use_local_only'], host_details)
        if result.returncode != 0:
            click.secho(f"❌ Failed to set firewall=1 on {key} of container {vmid}: {result.stderr.strip()}", fg='red')
            sys.exit(1)
    click.secho(f"✅ Firewall enabled for container {vmid} and its network interfaces.", fg='green')


def _warn_if_firewall_inactive(vmid, node, host_details):
    """Say which switch is still off, since Proxmox applies none of the rules then."""
    datacenter = pvesh_json("/cluster/firewall/options", host_details) or {}
    if str(datacenter.get('enable', 0)) != '1':
        click.secho("⚠️ The datacenter firewall is disabled, so no firewall rule is applied yet. LWS does not "
                    "turn it on: without rules that allow SSH (22) and the web interface (8006), enabling it "
                    "can lock you out. Enable it under Datacenter > Firewall > Options when ready.", fg='yellow')
    container = pvesh_json(f"/nodes/{node}/lxc/{vmid}/firewall/options", host_details) or {}
    if str(container.get('enable', 0)) != '1':
        click.secho(f"⚠️ The firewall of container {vmid} is off. Run the command again with --enable-firewall, "
                    "or enable it under the container's Firewall > Options.", fg='yellow')


@px.command('security-group-attach')
@click.argument('group_name', callback=_validate_pattern(_SAFE_NAME_RE, "group name"))
@click.argument('vmid', callback=_validate_pattern(_VMID_RE, "vmid"))
@click.option('--enable-firewall', is_flag=True, help="Also enable the container's firewall and set firewall=1 on its network interfaces.")
@_REGION_OPTION
@_AZ_OPTION
def attach_security_group_to_lxc(group_name, vmid, enable_firewall, region, az):
    """🔗 Attach a security group to an LXC container."""
    host_details = _host_details(region, az)
    node = proxmox_node_name(host_details)
    groups = pvesh_json("/cluster/firewall/groups", host_details) or []
    if group_name not in {g.get('group') for g in groups}:
        click.secho(f"❌ Security group '{group_name}' does not exist. Create it with: lws px security-group-add {group_name}", fg='red')
        sys.exit(1)

    rules_path = f"/nodes/{node}/lxc/{vmid}/firewall/rules"
    existing = [r for r in (pvesh_json(rules_path, host_details) or [])
                if r.get('type') == 'group' and r.get('action') == group_name]
    if existing:
        for rule in existing:
            if str(rule.get('enable', 1)) != '1':
                result = pvesh("set", f"{rules_path}/{int(rule['pos'])}", host_details, enable=1)
                if result.returncode != 0:
                    click.secho(f"❌ Failed to enable the reference to '{group_name}': {result.stderr.strip()}", fg='red')
                    sys.exit(1)
        click.secho(f"✅ Security group '{group_name}' is attached to container {vmid}.", fg='green')
    else:
        result = pvesh("create", rules_path, host_details, type='group', action=group_name, enable=1)
        if result.returncode != 0:
            click.secho(f"❌ Failed to attach '{group_name}' to container {vmid}: {result.stderr.strip()}", fg='red')
            sys.exit(1)
        click.secho(f"✅ Security group '{group_name}' attached to container {vmid}.", fg='green')

    if enable_firewall:
        _enable_container_firewall(vmid, node, host_details)
    _warn_if_firewall_inactive(vmid, node, host_details)


@px.command('security-group-detach')
@click.argument('group_name', callback=_validate_pattern(_SAFE_NAME_RE, "group name"))
@click.argument('vmid', callback=_validate_pattern(_VMID_RE, "vmid"))
@_REGION_OPTION
@_AZ_OPTION
def detach_security_group_from_lxc(group_name, vmid, region, az):
    """🔓 Detach a security group from an LXC container."""
    host_details = _host_details(region, az)
    node = proxmox_node_name(host_details)
    rules_path = f"/nodes/{node}/lxc/{vmid}/firewall/rules"
    references = [r for r in (pvesh_json(rules_path, host_details) or [])
                  if r.get('type') == 'group' and r.get('action') == group_name]
    if not references:
        click.secho(f"❌ Security group '{group_name}' is not attached to container {vmid}.", fg='red')
        sys.exit(1)
    for rule in sorted(references, key=lambda r: int(r['pos']), reverse=True):
        result = pvesh("delete", f"{rules_path}/{int(rule['pos'])}", host_details)
        if result.returncode != 0:
            click.secho(f"❌ Failed to detach '{group_name}' from container {vmid}: {result.stderr.strip()}", fg='red')
            sys.exit(1)
    click.secho(f"✅ Security group '{group_name}' detached from container {vmid}.", fg='green')

@lxc.command('show-storage')
@click.argument('instance_id', callback=_validate_pattern(_VMID_RE, "instance id"))
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
def lxc_list_storage(instance_id, region, az):
    """🔍 List storage details for LXC container."""
    
    # Load configuration
    config = load_config()
    host_details = config['regions'][region]['availability_zones'][az]
    host = host_details['host']
    user = host_details['user']
    ssh_password = host_details['ssh_password']

    # Command to list storage for the LXC container using df -h
    list_storage_cmd = ["pct", "exec", instance_id, "--", "df", "-h"]

    # Execute the command on the Proxmox host
    result = run_ssh_command(host, user, ssh_password, list_storage_cmd)

    # Output the result of the command
    if result.returncode == 0:
        storage_lines = result.stdout.strip().splitlines()
        if storage_lines:
            click.secho(f"📊 Storage details for instance {instance_id}:", fg='cyan')
            for line in storage_lines:
                click.secho(f"  {line}", fg='cyan')
        else:
            click.secho(f"❌ No storage information found for instance {instance_id}.", fg='red')
            sys.exit(1)
    else:
        click.secho(f"❌ Failed to retrieve storage details for instance {instance_id}: {result.stderr.strip()}", fg='red')
        sys.exit(1)



import click
import logging

def get_host_details(region, az):
    """Retrieves the host details from the configuration for a given region and availability zone."""
    config = load_config()
    try:
        return config['regions'][region]['availability_zones'][az]
    except KeyError as e:
        logging.error(f"❌ Invalid region or availability zone: {e}")
        return None

def get_host_free_resources(host_details):
    """Retrieve free CPU and memory resources on the host."""
    cpu_command = ["lscpu"]
    mem_command = ["free", "-m"]

    cpu_result = run_proxmox_command(cpu_command, cpu_command, config['use_local_only'], host_details)
    mem_result = run_proxmox_command(mem_command, mem_command, config['use_local_only'], host_details)

    if cpu_result.returncode == 0 and mem_result.returncode == 0:
        cpu_info = cpu_result.stdout
        mem_info = mem_result.stdout

        # Extract CPU cores count
        total_cores = 0
        for line in cpu_info.splitlines():
            if "CPU(s):" in line:
                total_cores = int(line.split(":")[1].strip())
                break

        # Extract memory info
        mem_info_lines = mem_info.splitlines()
        total_memory = int(mem_info_lines[1].split()[1])
        free_memory = int(mem_info_lines[1].split()[3])

        return total_cores, total_memory, free_memory
    else:
        logging.error(f"❌ Failed to retrieve host resources: {cpu_result.stderr} {mem_result.stderr}")
        return None, None, None

def get_lxc_resources(instance_id, host_details):
    """Retrieve the allocated CPU cores, CPU units, and memory resources of an LXC container."""
    command = ["pct", "config", instance_id]
    result = run_proxmox_command(command, command, config['use_local_only'], host_details)

    if result.returncode == 0:
        config_lines = result.stdout.splitlines()
        cpulimit = None
        cpuunits = None
        memory = None

        for line in config_lines:
            if "cores" in line:
                cpulimit = int(line.split(":")[1].strip())
            if "cpuunits" in line:
                cpuunits = int(line.split(":")[1].strip())
            if "memory" in line:
                memory = int(line.split(":")[1].strip())

        return cpulimit, cpuunits, memory
    else:
        logging.error(f"❌ Failed to retrieve LXC resources for {instance_id}: {result.stderr}")
        return None, None, None


# Docker Group
@lws.group()
@command_alias('app')
def app():
    """🐳 Manage Docker on LXC containers."""
    pass

# --- Docker inside containers -------------------------------------------------
# Everything that runs in the container goes through run_argv, so the remote
# copy is quoted and the same argument list works over SSH and locally.
# Compose files live in the container under APPS_DIR/<app>/, where <app> is
# the first service name of the file; it is also the Compose project name, so
# repeated deploys and updates address the same containers.

APPS_DIR = "/opt/lws/apps"
DOCKER_INSTALL_SCRIPT = (
    "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io && "
    # Compose: docker-compose-v2 (Compose v2) on Ubuntu, otherwise the distribution's
    # docker-compose package, which is Compose v1 on Debian 12 and v2 from Debian 13.
    # compose_command() finds either.
    "(DEBIAN_FRONTEND=noninteractive apt-get install -y docker-compose-v2 || "
    "DEBIAN_FRONTEND=noninteractive apt-get install -y docker-compose)"
)
DOCKER_PACKAGES = ("docker.io", "docker-compose", "docker-compose-v2", "docker-compose-plugin")


def in_container(instance_id, argv, host_details):
    return run_argv(["pct", "exec", instance_id, "--"] + list(argv), config['use_local_only'], host_details)


def container_is_running(instance_id, host_details):
    status = run_argv(["pct", "status", instance_id], config['use_local_only'], host_details)
    return status.returncode == 0 and "status: running" in status.stdout


def require_running(instance_id, host_details):
    if not container_is_running(instance_id, host_details):
        click.secho(f"❌ LXC container {instance_id} is not running. Start it with: lws lxc start {instance_id}", fg='red')
        sys.exit(1)


def container_features(instance_id, host_details):
    """(features dict, unprivileged bool) from `pct config`."""
    result = run_argv(["pct", "config", instance_id], config['use_local_only'], host_details)
    features, unprivileged = {}, False
    for line in result.stdout.splitlines():
        key, _, value = line.partition(":")
        if key.strip() == "features":
            for item in value.strip().split(","):
                name, _, setting = item.partition("=")
                if name:
                    features[name.strip()] = setting.strip()
        elif key.strip() == "unprivileged":
            unprivileged = value.strip() == "1"
    return features, unprivileged


def docker_features_missing(instance_id, host_details):
    """The LXC features Docker needs that the container lacks, and the full new features value."""
    features, unprivileged = container_features(instance_id, host_details)
    needed = {"nesting": "1"}
    if unprivileged:
        needed["keyctl"] = "1"
    missing = [k for k, v in needed.items() if features.get(k) != v]
    merged = {**features, **needed}
    return missing, ",".join(f"{k}={v}" for k, v in merged.items())


def compose_command(instance_id, host_details):
    """["docker", "compose"] or ["docker-compose"], whichever the container has; None if neither."""
    if in_container(instance_id, ["docker", "compose", "version"], host_details).returncode == 0:
        return ["docker", "compose"]
    if in_container(instance_id, ["docker-compose", "version"], host_details).returncode == 0:
        return ["docker-compose"]
    return None


def fetch_compose_file(compose_file):
    """A local path to the Compose file, downloading it first if it is a URL."""
    if os.path.exists(compose_file):
        return compose_file
    if compose_file.startswith(("http://", "https://")):
        click.secho(f"🔧 Downloading Docker Compose file from {compose_file}...", fg='yellow')
        fd, local_path = tempfile.mkstemp(suffix=".yml", prefix="docker-compose-")
        try:
            response = requests.get(compose_file, timeout=30)
            response.raise_for_status()
            with os.fdopen(fd, 'wb') as file:
                file.write(response.content)
        except requests.exceptions.RequestException as e:
            click.secho(f"❌ Failed to download Docker Compose file: {e}", fg='red')
            sys.exit(1)
        return local_path
    click.secho(f"❌ Docker Compose file not found at {compose_file}.", fg='red')
    sys.exit(1)


def extract_app_name_from_compose(compose_file):
    """Extract the application name from the Docker Compose file."""
    try:
        with open(compose_file, 'r') as file:
            compose_content = yaml.safe_load(file)
            if 'services' in compose_content:
                service_names = list(compose_content['services'].keys())
                if service_names:
                    # Use the first service name as the app_name. It becomes
                    # part of paths in the container and the Compose project
                    # name, so it is restricted to a safe charset here.
                    app_name = service_names[0]
                    if not _SAFE_NAME_RE.match(app_name):
                        logging.error(f"❌ Unsafe service name in Docker Compose file: {app_name!r}")
                        return None
                    return app_name
    except Exception as e:
        logging.error(f"❌ Failed to parse Docker Compose file: {str(e)}")
    return None


def push_file_to_container(instance_id, local_path, container_path, host_details):
    """Copy a local file into a container, through the Proxmox host when remote."""
    directory = os.path.dirname(container_path)
    mkdir = in_container(instance_id, ["mkdir", "-p", directory], host_details)
    if mkdir.returncode != 0:
        click.secho(f"❌ Failed to create {directory} in container {instance_id}: {mkdir.stderr.strip()}", fg='red')
        sys.exit(1)
    source = local_path
    staged = None
    if not config['use_local_only']:
        staged = f"/var/tmp/lws-{instance_id}-{int(time.time())}-{os.path.basename(container_path)}"
        upload = run_scp_command(host_details['ssh_password'], local_path,
                                 f"{host_details['user']}@{host_details['host']}:{staged}")
        if upload.returncode != 0:
            click.secho(f"❌ Failed to upload {os.path.basename(local_path)} to the Proxmox host: {upload.stderr.strip()}", fg='red')
            sys.exit(1)
        source = staged
    push = run_argv(["pct", "push", instance_id, source, container_path], config['use_local_only'], host_details)
    if staged:
        run_argv(["rm", "-f", staged], config['use_local_only'], host_details)
    if push.returncode != 0:
        click.secho(f"❌ Failed to copy the file into container {instance_id}: {push.stderr.strip()}", fg='red')
        sys.exit(1)


@app.command('setup')
@click.argument('instance_id', callback=_validate_pattern(_VMID_RE, "instance id"))
@click.argument('package_name', default='docker')
@click.option('--enable-nesting', is_flag=True,
              help="Turn on the LXC features Docker needs (nesting, and keyctl for unprivileged containers), restarting the container.")
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1.")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1.")
def install_docker(instance_id, package_name, enable_nesting, region, az):
    """📦 Install Docker and Docker Compose in an LXC container (Debian or Ubuntu)."""
    host_details = _host_details(region, az)
    require_running(instance_id, host_details)

    missing, features = docker_features_missing(instance_id, host_details)
    if missing:
        if enable_nesting:
            click.secho(f"🔧 Setting features {features} on container {instance_id} and restarting it...", fg='yellow')
            result = run_argv(["pct", "set", instance_id, "--features", features], config['use_local_only'], host_details)
            if result.returncode != 0:
                click.secho(f"❌ Failed to set the container features: {result.stderr.strip()}", fg='red')
                sys.exit(1)
            result = run_argv(["pct", "reboot", instance_id], config['use_local_only'], host_details)
            if result.returncode != 0:
                click.secho(f"❌ Failed to restart container {instance_id}: {result.stderr.strip()}", fg='red')
                sys.exit(1)
        else:
            click.secho(f"⚠️ Container {instance_id} lacks the LXC feature(s) {', '.join(missing)}, which Docker "
                        f"usually needs. Run again with --enable-nesting to set them (the container restarts).", fg='yellow')

    if in_container(instance_id, ["docker", "--version"], host_details).returncode == 0 and \
            compose_command(instance_id, host_details):
        click.secho(f"✅ Docker and Docker Compose are already installed in container {instance_id}.", fg='green')
        return

    click.secho(f"📦 Installing Docker and Docker Compose in container {instance_id}...", fg='yellow')
    result = in_container(instance_id, ["sh", "-c", DOCKER_INSTALL_SCRIPT], host_details)
    if result.returncode != 0:
        click.secho(f"❌ Failed to install Docker in container {instance_id}: {result.stderr.strip()}", fg='red')
        sys.exit(1)
    click.secho(f"✅ Docker and Docker Compose installed in container {instance_id}.", fg='green')


@app.command('run')
@click.argument('instance_id', callback=_validate_pattern(_VMID_RE, "instance id"))
@click.argument('docker_command', nargs=-1, type=click.UNPROCESSED)
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
def run_docker(instance_id, docker_command, region, az):
    """🚀 Execute docker run inside an LXC container.

    Arguments after `--` are passed to `docker run` one by one:
    lws app run 100 -- -d -p 80:80 nginx
    """
    if not docker_command:
        click.secho("❌ No Docker command provided.", fg='red')
        sys.exit(1)
    host_details = _host_details(region, az)
    require_running(instance_id, host_details)

    if in_container(instance_id, ["docker", "--version"], host_details).returncode != 0:
        click.secho(f"❌ Docker is not installed in container {instance_id}. Install it with: lws app setup {instance_id}", fg='red')
        sys.exit(1)

    result = in_container(instance_id, ["docker", "run"] + list(docker_command), host_details)
    if result.returncode == 0:
        click.secho(f"✅ Docker command executed successfully on instance {instance_id}:\n{result.stdout.strip()}", fg='green')
    else:
        click.secho(f"❌ Failed to execute Docker command on instance {instance_id}: {result.stderr.strip()}", fg='red')
        sys.exit(1)


_COMPOSE_ACTIONS = {
    'install': ['up', '-d'],
    'uninstall': ['down'],
    'start': ['start'],
    'stop': ['stop'],
    'restart': ['restart'],
    'status': ['ps'],
}


@app.command('deploy')
@click.argument('action', type=click.Choice(list(_COMPOSE_ACTIONS)))
@click.argument('instance_id', callback=_validate_pattern(_VMID_RE, "instance id"))
@click.option('--compose-file', required=True, help="Local path or URL of the Docker Compose file. Its first service name is the app name.")
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
@click.option('--auto-start', is_flag=True, help="With install: start the app at boot with a systemd unit in the container.")
def compose(action, instance_id, compose_file, region, az, auto_start):
    """🚀 Manage apps with Compose on LXC containers."""
    host_details = _host_details(region, az)
    require_running(instance_id, host_details)

    local_file = fetch_compose_file(compose_file)
    app_name = extract_app_name_from_compose(local_file)
    if not app_name:
        click.secho("❌ Failed to extract application name from Docker Compose file.", fg='red')
        sys.exit(1)

    compose_cmd = compose_command(instance_id, host_details)
    if not compose_cmd:
        click.secho(f"❌ Docker Compose is not installed in container {instance_id}. Install it with: lws app setup {instance_id}", fg='red')
        sys.exit(1)

    app_dir = f"{APPS_DIR}/{app_name}"
    container_file = f"{app_dir}/docker-compose.yml"
    if action == 'install':
        push_file_to_container(instance_id, local_file, container_file, host_details)
        click.secho(f"✅ Compose file copied to {container_file} in container {instance_id}.", fg='green')
    elif in_container(instance_id, ["test", "-f", container_file], host_details).returncode != 0:
        click.secho(f"❌ Application '{app_name}' is not installed in container {instance_id} ({container_file} is missing).", fg='red')
        sys.exit(1)

    result = in_container(instance_id, compose_cmd + ["-p", app_name, "-f", container_file] + _COMPOSE_ACTIONS[action], host_details)
    if result.returncode != 0:
        click.secho(f"❌ Instance {instance_id} - Failed to {action} application '{app_name}': {result.stderr.strip()}", fg='red')
        sys.exit(1)
    if action == 'status' and result.stdout.strip():
        click.echo(result.stdout.rstrip())
    click.secho(f"✅ Instance {instance_id} - Application '{app_name}' {action} successfully executed.", fg='green')

    if action == 'install' and auto_start:
        setup_auto_start(instance_id, app_name, container_file, compose_cmd, host_details)
    if action == 'uninstall':
        unit = f"lws-{app_name}.service"
        in_container(instance_id, ["sh", "-c",
                                   f"systemctl disable {unit} 2>/dev/null; rm -f /etc/systemd/system/{unit}; systemctl daemon-reload"],
                     host_details)


def setup_auto_start(instance_id, app_name, container_file, compose_cmd, host_details):
    """Install and enable a systemd unit in the container that brings the app up at boot."""
    unit_name = f"lws-{app_name}.service"
    compose = " ".join(["/usr/bin/env"] + compose_cmd + ["-p", app_name, "-f", container_file])
    unit = f"""[Unit]
Description=LWS app {app_name} (Docker Compose)
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory={os.path.dirname(container_file)}
ExecStart={compose} up -d
ExecStop={compose} down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
"""
    fd, local_unit = tempfile.mkstemp(suffix=".service", prefix="lws-")
    try:
        with os.fdopen(fd, 'w') as file:
            file.write(unit)
        push_file_to_container(instance_id, local_unit, f"/etc/systemd/system/{unit_name}", host_details)
    finally:
        os.remove(local_unit)
    result = in_container(instance_id, ["sh", "-c", f"systemctl daemon-reload && systemctl enable {unit_name}"], host_details)
    if result.returncode != 0:
        click.secho(f"❌ Failed to enable {unit_name}: {result.stderr.strip()}", fg='red')
        sys.exit(1)
    click.secho(f"🔧 Auto-start enabled for '{app_name}' on instance {instance_id} ({unit_name}).", fg='green')


@app.command('update')
@click.argument('instance_id', callback=_validate_pattern(_VMID_RE, "instance id"))
@click.argument('compose_file', required=True)
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
def compose_update(instance_id, compose_file, region, az):
    """🆕 Update an app: copy the new Compose file, pull its images and recreate what changed."""
    host_details = _host_details(region, az)
    require_running(instance_id, host_details)

    local_file = fetch_compose_file(compose_file)
    app_name = extract_app_name_from_compose(local_file)
    if not app_name:
        click.secho("❌ Failed to extract application name from Docker Compose file.", fg='red')
        sys.exit(1)
    compose_cmd = compose_command(instance_id, host_details)
    if not compose_cmd:
        click.secho(f"❌ Docker Compose is not installed in container {instance_id}. Install it with: lws app setup {instance_id}", fg='red')
        sys.exit(1)

    container_file = f"{APPS_DIR}/{app_name}/docker-compose.yml"
    push_file_to_container(instance_id, local_file, container_file, host_details)
    base = compose_cmd + ["-p", app_name, "-f", container_file]
    for step, label in ((["pull"], "pulled the images of"), (["up", "-d"], "updated")):
        result = in_container(instance_id, base + step, host_details)
        if result.returncode != 0:
            click.secho(f"❌ Failed to update '{app_name}' on instance {instance_id}: {result.stderr.strip()}", fg='red')
            sys.exit(1)
        click.secho(f"✅ Instance {instance_id}: {label} '{app_name}'.", fg='green')


@app.command('logs')
@click.argument('instance_id', callback=_validate_pattern(_VMID_RE, "instance id"))
@click.argument('container_name_or_id', callback=_validate_pattern(re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$'), "container name or id"))
@click.option('--tail', default='all', callback=_validate_pattern(re.compile(r'^(all|\d{1,7})$'), "tail"), help="Number of lines to show from the end of the logs. Default: all.")
@click.option('--follow', is_flag=True, hidden=True)
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
def logs(instance_id, container_name_or_id, tail, follow, region, az):
    """📄 Show the logs of a Docker container inside an LXC container."""
    host_details = _host_details(region, az)
    if follow:
        click.secho("⚠️ --follow cannot stream through LWS; showing the current logs. To follow them, run "
                    f"`pct exec {instance_id} -- docker logs -f {container_name_or_id}` on the host.", fg='yellow')
    cmd = ["docker", "logs"] + ([] if tail == 'all' else ["--tail", tail]) + [container_name_or_id]
    result = in_container(instance_id, cmd, host_details)
    if result.returncode != 0:
        click.secho(f"❌ Failed to fetch logs for container {container_name_or_id} on instance {instance_id}: {result.stderr.strip()}", fg='red')
        sys.exit(1)
    # docker logs writes the container's stderr stream to stderr.
    click.secho(f"📄 Logs for container {container_name_or_id} on instance {instance_id}:", fg='cyan')
    click.echo((result.stdout + result.stderr).rstrip())


@app.command('list')
@click.argument('instance_id', callback=_validate_pattern(_VMID_RE, "instance id"))
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
def containers(instance_id, region, az):
    """📦 List running Docker containers inside an LXC container."""
    host_details = _host_details(region, az)
    result = in_container(instance_id, ["docker", "ps", "--format", "{{.ID}}: {{.Names}} ({{.Image}})"], host_details)
    if result.returncode != 0:
        click.secho(f"❌ Failed to list running containers on instance {instance_id}: {result.stderr.strip()}", fg='red')
        sys.exit(1)
    click.secho(f"📦 Running containers on instance {instance_id}:", fg='cyan')
    click.echo(result.stdout.rstrip() or "(none)")


@app.command('remove')
@click.argument('instance_ids', nargs=-1, required=True, callback=_validate_pattern(_VMID_RE, "instance id"))
@click.option('--purge', is_flag=True, help="First remove all Docker images, containers, volumes and networks.")
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
def remove(instance_ids, purge, region, az):
    """🗑️ Uninstall Docker and Docker Compose from LXC containers."""
    host_details = _host_details(region, az)
    # Remove only the packages that are installed: apt-get refuses the whole
    # command if one of the names is unknown to it.
    script = (
        'pkgs=""; for p in ' + " ".join(DOCKER_PACKAGES) + '; do '
        'dpkg -s "$p" >/dev/null 2>&1 && pkgs="$pkgs $p"; done; '
        'if [ -n "$pkgs" ]; then DEBIAN_FRONTEND=noninteractive apt-get remove -y $pkgs; fi'
    )
    failed = []
    for instance_id in instance_ids:
        click.secho(f"🔧 Removing Docker and Docker Compose from LXC container {instance_id}...", fg='yellow')
        if purge:
            result = in_container(instance_id, ["docker", "system", "prune", "-a", "-f", "--volumes"], host_details)
            if result.returncode != 0:
                click.secho(f"❌ Failed to purge Docker resources on instance {instance_id}: {result.stderr.strip()}", fg='red')
                failed.append(instance_id)
                continue
        result = in_container(instance_id, ["sh", "-c", script], host_details)
        if result.returncode == 0:
            click.secho(f"✅ Docker and Docker Compose removed from instance {instance_id}.", fg='green')
        else:
            click.secho(f"❌ Failed to remove Docker from instance {instance_id}: {result.stderr.strip()}", fg='red')
            failed.append(instance_id)
    if failed:
        sys.exit(1)


@lxc.command('clone')
@click.argument('source_instance_id', callback=_validate_pattern(_VMID_RE, "instance id"))
@click.argument('target_instance_id', callback=_validate_pattern(_VMID_RE, "instance id"))
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
@click.option('--target-host', default=None, callback=_validate_pattern(_HOSTNAME_RE, "target host"), help="Target Proxmox host for the clone.")
@click.option('--description', default=None, callback=_validate_pattern(_SAFE_FREETEXT_RE, "description"), help="Description for the new container.")
@click.option('--hostname', default=None, callback=_validate_pattern(_HOSTNAME_RE, "hostname"), help="Hostname for the new container.")
@click.option('--storage', default=None, callback=_validate_pattern(_SAFE_NAME_RE, "storage"), help="Target storage for full clone.")
@click.option('--full', is_flag=True, help="Create a full copy of all disks.")
@click.option('--pool', default=None, callback=_validate_pattern(_SAFE_NAME_RE, "pool"), help="Add the new container to the specified pool.")
@click.option('--bwlimit', default=None, callback=_validate_pattern(_VMID_RE, "bwlimit"), help="Override I/O bandwidth limit (in KiB/s).")
@click.option('--start/--no-start', default=True, help="Start the cloned container after creation. Default is true.")
def clone(source_instance_id, target_instance_id, region, az, target_host, description, hostname, storage, full, pool, bwlimit, start):
    """🔄 Clone an LXC container, on this node or (--target-host) another node of the cluster.

    A temporary snapshot of the source is taken so a running container can be
    cloned, and removed once the clone exists.
    """
    host_details = _host_details(region, az)
    use_local = config['use_local_only']
    logging.info(f"Cloning LXC container {source_instance_id} to {target_instance_id}")

    snapshot_name = f"lws-clone-{time.strftime('%Y%m%d%H%M%S')}"
    snapshot_result = run_argv(["pct", "snapshot", source_instance_id, snapshot_name], use_local, host_details)
    if snapshot_result.returncode != 0:
        click.secho(f"❌ Failed to create snapshot {snapshot_name} on instance {source_instance_id}: {snapshot_result.stderr.strip()}", fg='red')
        sys.exit(1)

    clone_cmd = ["pct", "clone", source_instance_id, target_instance_id, "--snapname", snapshot_name]
    if description:
        clone_cmd += ["--description", description]
    if hostname:
        clone_cmd += ["--hostname", hostname]
    if storage:
        clone_cmd += ["--storage", storage]
    if full:
        clone_cmd.append("--full")
    if pool:
        clone_cmd += ["--pool", pool]
    if bwlimit:
        clone_cmd += ["--bwlimit", bwlimit]
    if target_host:
        clone_cmd += ["--target", target_host]
    clone_result = run_argv(clone_cmd, use_local, host_details)

    cleanup = run_argv(["pct", "delsnapshot", source_instance_id, snapshot_name], use_local, host_details)
    if cleanup.returncode != 0:
        click.secho(f"⚠️ Could not remove the temporary snapshot {snapshot_name} of {source_instance_id}: "
                    f"{cleanup.stderr.strip()}. Remove it with: lws lxc snapshot-rm {source_instance_id} {snapshot_name}", fg='yellow')

    if clone_result.returncode != 0:
        click.secho(f"❌ Failed to clone instance {source_instance_id} to {target_instance_id}: {clone_result.stderr.strip()}", fg='red')
        sys.exit(1)
    click.secho(f"✅ Successfully cloned instance {source_instance_id} to {target_instance_id}.", fg='green')

    if start:
        if target_host:
            # The clone lives on the target node; the cluster API starts it there.
            start_cmd = ["pvesh", "create", f"/nodes/{target_host}/lxc/{target_instance_id}/status/start"]
        else:
            start_cmd = ["pct", "start", target_instance_id]
        start_result = run_argv(start_cmd, use_local, host_details)
        if start_result.returncode != 0:
            click.secho(f"❌ Failed to start cloned container {target_instance_id}: {start_result.stderr.strip()}", fg='red')
            sys.exit(1)
        click.secho(f"✅ Cloned container {target_instance_id} started successfully.", fg='green')


@lxc.command('exec')
@click.argument('instance_ids', nargs=-1, required=True, callback=_validate_pattern(_VMID_RE, "instance id"))
@click.argument('command', nargs=1, required=True)
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
def exec_in_container(instance_ids, command, region, az):
    """👨🏻‍💻 Execute an arbitrary command into an LXC container."""
    if not command:
        click.secho("❌ No command provided to execute.", fg='red')
        logging.error("❌ No command provided to execute.")
        return

    host_details = config['regions'][region]['availability_zones'][az]

    # Convert the single command argument into a list of arguments.
    # shlex.split (not str.split) so a quoted argument containing spaces
    # (e.g. exec 101 'echo "a b"') is kept as one token instead of being
    # broken apart on every whitespace.
    try:
        command_list = shlex.split(command)
    except ValueError as e:
        click.secho(f"❌ Could not parse command: {e}", fg='red')
        sys.exit(1)

    had_failure = False
    for instance_id in instance_ids:
        exec_cmd = ["pct", "exec", str(instance_id), "--"] + command_list

        logging.info(f"Executing command in instance {instance_id}: {command}")
        click.secho(f"🔧 Executing command in instance {instance_id}: {command}", fg='cyan')

        # run_argv quotes the remote copy, so `&&`, `;` or `|` in the command
        # reach the container as arguments instead of being run by the
        # Proxmox host's shell. For a pipeline, pass `sh -c '...'` explicitly.
        exec_result = run_argv(exec_cmd, config['use_local_only'], host_details)

        if exec_result.returncode == 0:
            logging.info(f"✅ Command executed successfully in instance {instance_id}.")
            click.secho(f"✅ Command executed successfully in instance {instance_id}.", fg='green')
            logging.debug(f"🔎 Command output for instance {instance_id}: {exec_result.stdout}")
            click.secho(exec_result.stdout, fg='white')
        else:
            logging.error(f"❌ Failed to execute command in instance {instance_id}: {exec_result.stderr}")
            click.secho(f"❌ Failed to execute command in instance {instance_id}: {exec_result.stderr}", fg='red')
            had_failure = True

    if had_failure:
        sys.exit(1)

@lxc.command('net')
@click.argument('instance_id', required=True, callback=_validate_pattern(_VMID_RE, "instance id"))
@click.argument('protocol', type=click.Choice(['tcp', 'udp']), required=True)
@click.argument('port', type=int, required=True)
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target.")
@click.option('--timeout', default=5, help="Timeout in seconds for the network check.")
def net_check(instance_id, protocol, port, region, az, timeout):
    """🌐 Perform simple network checks on LXC containers.
    
    INSTANCE_ID: The ID of the LXC container.
    PROTOCOL: The protocol to check (tcp/udp).
    PORT: The port number to check.
    """
    
    host_details = config['regions'][region]['availability_zones'][az]

    # Step 1: Check if the LXC container is running
    status_cmd = ["pct", "status", instance_id]
    status_result = run_proxmox_command(
        local_cmd=status_cmd, 
        remote_cmd=status_cmd, 
        use_local_only=config['use_local_only'], 
        host_details=host_details
    )

    if status_result.returncode != 0 or "status: stopped" in status_result.stdout:
        click.secho(f"❌ Instance {instance_id} is not running.", fg='red')
        return

    click.secho(f"ℹ️ Instance {instance_id} is running. Proceeding with network check...", fg='yellow')

    # Step 2: Attempt to check the port from within the LXC container.
    # nc -u can only tell that a UDP port is closed if an ICMP "port
    # unreachable" comes back, so a UDP "open" is a best guess.
    nc_flags = ["-zvu"] if protocol == 'udp' else ["-zv"]
    check_port_cmd = ["nc"] + nc_flags + ["-w", str(timeout), "127.0.0.1", str(port)]
    port_check_result = run_argv(["pct", "exec", instance_id, "--"] + check_port_cmd,
                                 config['use_local_only'], host_details)

    if port_check_result.returncode == 0:
        click.secho(f"🟢 {protocol.upper()} port {port} on instance {instance_id} is open.", fg='green')
        return
    else:
        click.secho(f"🔴 {protocol.upper()} port {port} on instance {instance_id} seems closed. Trying to confirm...", fg='red')

    # Step 3: If the direct check failed, try checking from the Proxmox host to the LXC container's IP
    lxc_ip_cmd = ["pct", "exec", instance_id, "--", "hostname", "-I"]
    lxc_ip_result = run_proxmox_command(
        local_cmd=lxc_ip_cmd,
        remote_cmd=lxc_ip_cmd,
        use_local_only=config['use_local_only'],
        host_details=host_details
    )

    if lxc_ip_result.returncode != 0 or not lxc_ip_result.stdout.strip():
        click.secho(f"❌ Failed to retrieve the IP address of instance {instance_id}.", fg='red')
        return

    lxc_ip = lxc_ip_result.stdout.strip().split()[0]
    click.secho(f"ℹ️ Retrieved LXC IP: {lxc_ip}. Checking port from Proxmox host...", fg='yellow')

    proxmox_to_lxc_check_cmd = ["nc"] + nc_flags + ["-w", str(timeout), lxc_ip, str(port)]
    proxmox_to_lxc_result = run_proxmox_command(
        local_cmd=proxmox_to_lxc_check_cmd,
        remote_cmd=proxmox_to_lxc_check_cmd,
        use_local_only=config['use_local_only'],
        host_details=host_details
    )

    if proxmox_to_lxc_result.returncode == 0:
        click.secho(f"🟢 {protocol.upper()} port {port} on instance {instance_id} is open (confirmed from Proxmox host).", fg='green')
    else:
        click.secho(f"🔴 {protocol.upper()} port {port} on instance {instance_id} is closed (confirmed from Proxmox host).", fg='red')

    # Step 4: Inform if LXC is not responding after multiple attempts
    for attempt in range(3):
        time.sleep(2)  # Wait before retrying
        status_result = run_proxmox_command(
            local_cmd=status_cmd,
            remote_cmd=status_cmd,
            use_local_only=config['use_local_only'],
            host_details=host_details
        )

        if status_result.returncode == 0 and "status: running" in status_result.stdout:
            click.secho(f"ℹ️ Instance {instance_id} is still running.", fg='yellow')
        else:
            click.secho(f"🔴 Instance {instance_id} is not responding after {attempt + 1} attempts.", fg='red')
            return

@px.command('templates')
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target.")
def list_templates(region, az):
    """📄 List all available templates in the Proxmox cache directory."""
    
    host_details = config['regions'][region]['availability_zones'][az]
    
    # Command to list the contents of the /var/lib/vz/template/cache directory
    list_cmd = ["ls", "-h", "/var/lib/vz/template/cache"]
    
    try:
        # Run the command on the Proxmox host
        result = run_proxmox_command(
            local_cmd=list_cmd,
            remote_cmd=list_cmd,
            use_local_only=config['use_local_only'],
            host_details=host_details
        )
        
        if result and result.returncode == 0:
            click.secho("📄 Templates available in /var/lib/vz/template/cache:\n", fg='cyan')
            click.secho(result.stdout, fg='white')
        else:
            click.secho(f"❌ Failed to list templates: {result.stderr.strip()}", fg='red')
            sys.exit(1)
    
    except Exception as e:
        click.secho(f"❌ An error occurred while listing templates: {str(e)}", fg='red')
        logging.error(f"❌ An error occurred while listing templates: {str(e)}")
        sys.exit(1)

@px.command('security-groups')
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target.")
def list_security_groups(region, az):
    """🔐 List all security groups and their rules in the Proxmox cluster."""
    host_details = _host_details(region, az)
    groups = pvesh_json("/cluster/firewall/groups", host_details) or []
    if not groups:
        click.secho("ℹ️ No security groups are defined.", fg='yellow')
        return
    click.secho("🔐 Security groups and their rules:\n", fg='cyan')
    for group in sorted(groups, key=lambda g: g.get('group', '')):
        name = group.get('group', '')
        comment = f" - {group['comment']}" if group.get('comment') else ""
        click.secho(f"[group {name}]{comment}", fg='yellow')
        rules = pvesh_json(f"/cluster/firewall/groups/{name}", host_details) or []
        if not rules:
            click.secho("    (no rules)", fg='white')
        for rule in sorted(rules, key=lambda r: int(r.get('pos', 0))):
            state = "" if str(rule.get('enable', 1)) == '1' else " (disabled)"
            click.secho(f"    {rule.get('pos')}: {_describe_rule(rule)}{state}", fg='white')
        click.echo("")


@lxc.command('show-info')
@click.argument('instance_id', required=True, callback=_validate_pattern(_VMID_RE, "instance id"))
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target.")
def get_lxc_info(instance_id, region, az):
    """🌐 Retrieve IP address, hostname, DNS servers, and LXC name from Proxmox."""
    
    host_details = config['regions'][region]['availability_zones'][az]
    
    # Commands to get IP address, hostname, and Proxmox LXC name
    get_ip_cmd = ["pct", "exec", instance_id, "--", "ip", "addr", "show"]
    get_hostname_cmd = ["pct", "exec", instance_id, "--", "hostname"]
    get_dns_cmd = ["pct", "exec", instance_id, "--", "cat", "/etc/resolv.conf"]
    get_lxc_name_cmd = ["pct", "config", instance_id]
    
    try:
        # Get IP address
        ip_result = run_proxmox_command(
            local_cmd=get_ip_cmd,
            remote_cmd=get_ip_cmd,
            use_local_only=config['use_local_only'],
            host_details=host_details
        )
        
        # Get hostname inside the LXC
        hostname_result = run_proxmox_command(
            local_cmd=get_hostname_cmd,
            remote_cmd=get_hostname_cmd,
            use_local_only=config['use_local_only'],
            host_details=host_details
        )
        
        # Get DNS servers inside the LXC
        dns_result = run_proxmox_command(
            local_cmd=get_dns_cmd,
            remote_cmd=get_dns_cmd,
            use_local_only=config['use_local_only'],
            host_details=host_details
        )
        
        # Get LXC name from Proxmox
        lxc_name_result = run_proxmox_command(
            local_cmd=get_lxc_name_cmd,
            remote_cmd=get_lxc_name_cmd,
            use_local_only=config['use_local_only'],
            host_details=host_details
        )
        
        if ip_result.returncode == 0 and hostname_result.returncode == 0 and dns_result.returncode == 0 and lxc_name_result.returncode == 0:
            # Extract IP addresses from the `ip addr show` output
            ip_address = []
            for line in ip_result.stdout.splitlines():
                line = line.strip()
                if line.startswith("inet "):
                    ip_address.append(line.split()[1].split('/')[0])

            ip_address_str = ", ".join(ip_address) if ip_address else "No IP address found"
            
            hostname = hostname_result.stdout.strip()
            
            dns_servers = []
            for line in dns_result.stdout.splitlines():
                line = line.strip()
                if line.startswith("nameserver"):
                    dns_servers.append(line.split()[1])
            
            dns_servers_str = ", ".join(dns_servers) if dns_servers else "No DNS servers found"
            
            # Parse the LXC name from the configuration output
            lxc_name = None
            for line in lxc_name_result.stdout.splitlines():
                if line.startswith("hostname:"):
                    lxc_name = line.split(":")[1].strip()
                    break
            
            click.secho(f"🌐 IP address(es) for instance {instance_id}: {ip_address_str}", fg='green')
            click.secho(f"🏷️ Hostname inside the LXC: {hostname}", fg='green')
            click.secho(f"🌍 DNS servers inside the LXC: {dns_servers_str}", fg='green')
            click.secho(f"📛 LXC name in Proxmox: {lxc_name}", fg='green')
        
        else:
            if ip_result.returncode != 0:
                click.secho(f"❌ Failed to retrieve IP address: {ip_result.stderr.strip()}", fg='red')
            if hostname_result.returncode != 0:
                click.secho(f"❌ Failed to retrieve hostname: {hostname_result.stderr.strip()}", fg='red')
            if dns_result.returncode != 0:
                click.secho(f"❌ Failed to retrieve DNS servers: {dns_result.stderr.strip()}", fg='red')
            if lxc_name_result.returncode != 0:
                click.secho(f"❌ Failed to retrieve LXC name: {lxc_name_result.stderr.strip()}", fg='red')
    
    except Exception as e:
        click.secho(f"❌ An error occurred while retrieving information: {str(e)}", fg='red')
        logging.error(f"❌ An error occurred while retrieving LXC information: {str(e)}")
        sys.exit(1)

@lxc.command('show-public-ip')
@click.argument('instance_id', required=True, callback=_validate_pattern(_VMID_RE, "instance id"))
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target.")
def get_lxc_public_ip(instance_id, region, az):
    """🌐 Retrieve the public IP address(es) of a given LXC container."""
    
    host_details = config['regions'][region]['availability_zones'][az]
    
    # Command to get the public IP address using an external service
    get_public_ip_cmd = ["pct", "exec", instance_id, "--", "curl", "-s", "https://ifconfig.io/forwarded"]

    try:
        # Run the command on the Proxmox host
        result = run_proxmox_command(
            local_cmd=get_public_ip_cmd,
            remote_cmd=get_public_ip_cmd,
            use_local_only=config['use_local_only'],
            host_details=host_details
        )
        
        if result and result.returncode == 0:
            public_ips = result.stdout.strip()
            if public_ips:
                click.secho(f"🌐 Public IP address(es) for instance {instance_id}: {public_ips}", fg='green')
            else:
                click.secho(f"⚠️ No public IP address found for instance {instance_id}.", fg='yellow')
        else:
            click.secho(f"❌ Failed to retrieve public IP address: {result.stderr.strip()}", fg='red')
            sys.exit(1)
    
    except Exception as e:
        click.secho(f"❌ An error occurred while retrieving the public IP address: {str(e)}", fg='red')
        logging.error(f"❌ An error occurred while retrieving the public IP address for LXC {instance_id}: {str(e)}")
        sys.exit(1)

@px.command('exec')
@click.argument('command', nargs=-1, required=True)
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target.")
def exec_proxmox_command(command, region, az):
    """👨🏻‍💻 Execute an arbitrary command into a Proxmox host."""
    
    host_details = config['regions'][region]['availability_zones'][az]

    # Join the command arguments into a single command string. This command's
    # entire purpose is to run whatever shell command the caller asks for on
    # the Proxmox host - there is no injection boundary to enforce here, the
    # arbitrary-command execution is the feature.
    command_str = " ".join(command)

    try:
        # Execute the command on the Proxmox host
        result = run_ssh_command(host_details['host'], host_details['user'], host_details['ssh_password'], [command_str])

        if result.returncode == 0:
            logging.info(f"Command executed successfully on Proxmox host {host_details['host']}:\n{result.stdout.strip()}")
            click.secho(f"✅ Command executed successfully on Proxmox host {host_details['host']}.\nOutput:\n{result.stdout.strip()}", fg='green')
        else:
            logging.error(f"Command failed on Proxmox host {host_details['host']} with return code {result.returncode}:\n{result.stderr.strip()}")
            click.secho(f"❌ Command failed on Proxmox host {host_details['host']}.\nError:\n{result.stderr.strip()}", fg='red')
            sys.exit(1)

    except Exception as e:
        logging.error(f"An error occurred while executing command on Proxmox host {host_details['host']}: {str(e)}")
        click.secho(f"❌ An error occurred while executing the command: {str(e)}", fg='red')
        sys.exit(1)


## scale-check

import yaml
import logging
import click

# Helper function to load the configuration file
def scale_check_load_config(config_path='config.yaml'):
    """Loads the configuration from a YAML file."""
    try:
        with open(config_path, 'r') as file:
            config = yaml.safe_load(file)
        logging.info(f"Configuration loaded successfully from {config_path}")
        return config
    except Exception as e:
        logging.error(f"Failed to load configuration file: {str(e)}")
        return {}

@lxc.command('scale-check')
@click.argument('instance_id', callback=_validate_pattern(_VMID_RE, "instance id"))
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
def scale_check_suggest_resources(instance_id, region, az):
    """⚖️ Scaling adjustments for an LXC container."""
    logging.info(f"Starting scale-check for instance {instance_id} in region {region}, AZ {az}")
    
    config = scale_check_load_config()
    host_details = scale_check_get_proxmox_host_details(region, az)
    if host_details is None:
        click.secho(f"❌ Invalid region '{region}' or availability zone '{az}'.", fg='red')
        sys.exit(1)

    # Retrieve host resource usage
    total_cores, total_memory, free_memory = scale_check_get_host_free_resources(host_details)
    if not total_cores or not total_memory:
        logging.error("Failed to retrieve host resources.")
        click.secho("❌ Could not retrieve host resources.", fg='red')
        sys.exit(1)

    logging.info(f"Proxmox Host resources - Total cores: {total_cores}, Total memory: {total_memory} MB, Free memory: {free_memory} MB")
    click.secho(f"ℹ️ Proxmox Host: {total_cores} cores, {free_memory} MB free memory", fg='cyan')

    # Retrieve LXC resource usage
    cores, cpu_option, memory, storage = scale_check_get_lxc_resources(instance_id, host_details, total_cores)
    if cores is None or memory is None or storage is None:
        logging.error(f"Failed to retrieve resources for container {instance_id}.")
        click.secho(f"❌ Could not retrieve resources for container {instance_id}.", fg='red')
        sys.exit(1)

    logging.info(f"Instance {instance_id} resources - CPU cores: {cores}, Memory: {memory} MB, Storage: {storage} GB")
    click.secho(f"ℹ️ Instance {instance_id}: {cores} cores, {memory} MB total memory, {storage} GB storage", fg='cyan')

    # Fetch thresholds and limits from the config
    scaling = config.get('scaling', {})
    cpu_thresholds = scaling.get('lxc_cpu', {})
    memory_thresholds = scaling.get('lxc_memory', {})
    storage_thresholds = scaling.get('lxc_storage', {})
    limits = scaling.get('limits', {})
    for thresholds in (cpu_thresholds, memory_thresholds, storage_thresholds):
        normalize_thresholds(thresholds)

    min_cores = limits.get('min_cpu_cores', 1)
    max_cores = limits.get('max_cpu_cores', total_cores)
    min_memory_mb = limits.get('min_memory_mb', 512)
    max_memory_mb = limits.get('max_memory_mb', total_memory)
    min_storage_gb = limits.get('min_storage_gb', 10)
    # host_storage.total_storage_gb: read for configuration files written for 1.4.3 or earlier.
    max_storage_gb = limits.get('max_storage_gb', scaling.get('host_storage', {}).get('total_storage_gb', 1024))

    def step_up(current, thresholds, step_key, default_step, default_multiplier, low, high):
        """current + step x multiplier, decimals dropped, kept within [low, high]."""
        step = thresholds.get(step_key, default_step) * thresholds.get('scale_up_multiplier', default_multiplier)
        return max(low, min(high, int(current + step)))

    def step_down(current, thresholds, step_key, default_step, default_multiplier, low, high):
        step = thresholds.get(step_key, default_step) * thresholds.get('scale_down_multiplier', default_multiplier)
        return max(low, min(high, int(current - step)))

    suggestions = []
    apply_options = []

    # CPU, compared with the host's CPUs
    suggested_cores = None
    if cores < total_cores * cpu_thresholds.get('min_threshold', 0.30):
        suggested_cores = step_up(cores, cpu_thresholds, 'step', 1, 1.5, min_cores, max_cores)
    elif cores > total_cores * cpu_thresholds.get('max_threshold', 0.80):
        suggested_cores = step_down(cores, cpu_thresholds, 'step', 1, 0.5, min_cores, max_cores)
    if suggested_cores is not None and suggested_cores != cores:
        verb = "increasing" if suggested_cores > cores else "decreasing"
        logging.info(f"Suggesting {verb} CPU cores to {suggested_cores} for instance {instance_id}.")
        suggestions.append(f"🔧 Consider {verb} CPU cores to {suggested_cores} (current: {cores}).")
        apply_options.append(f"{cpu_option} {suggested_cores}")

    # Memory, compared with the host's memory
    suggested_memory = None
    if memory < total_memory * memory_thresholds.get('min_threshold', 0.40):
        suggested_memory = step_up(memory, memory_thresholds, 'step_mb', 256, 1.25, min_memory_mb, max_memory_mb)
    elif memory > total_memory * memory_thresholds.get('max_threshold', 0.70):
        suggested_memory = step_down(memory, memory_thresholds, 'step_mb', 256, 0.75, min_memory_mb, max_memory_mb)
    if suggested_memory is not None and suggested_memory != memory:
        verb = "increasing" if suggested_memory > memory else "decreasing"
        logging.info(f"Suggesting {verb} memory to {suggested_memory} MB for instance {instance_id}.")
        suggestions.append(f"🔧 Consider {verb} memory to {suggested_memory} MB (current: {memory} MB).")
        apply_options.append(f"--memory {suggested_memory}")

    # Root disk, compared with max_storage_gb. Proxmox cannot shrink a
    # container's disk, so only an increase is ever suggested.
    if storage < max_storage_gb * storage_thresholds.get('min_threshold', 0.50):
        suggested_storage = step_up(storage, storage_thresholds, 'step_gb', 10, 1.5, min_storage_gb, max_storage_gb)
        if suggested_storage > storage:
            logging.info(f"Suggesting storage increase to {suggested_storage} GB for instance {instance_id}.")
            suggestions.append(f"🔧 Consider increasing storage to {suggested_storage} GB (current: {storage} GB).")
            apply_options.append(f"--storage-size {suggested_storage}G")

    # Output the suggestions
    if suggestions:
        logging.info("Suggestions made for scaling adjustments.")
        click.secho("\n".join(suggestions), fg='green')
        click.secho(f"ℹ️ Apply them with: lws lxc scale {instance_id} {' '.join(apply_options)}", fg='cyan')
    else:
        logging.info("No changes recommended based on current resource usage.")
        click.secho("🔧 No changes recommended.", fg='green')


def scale_check_get_proxmox_host_details(region, az):
    """Retrieves the host details from the configuration for a given region and availability zone."""
    config = scale_check_load_config()
    try:
        return config['regions'][region]['availability_zones'][az]
    except KeyError as e:
        logging.error(f"Invalid region or availability zone: {e}")
        return None

def scale_check_get_host_free_resources(host_details):
    """Retrieve free CPU and memory resources on the host."""
    cpu_command = ["lscpu"]
    mem_command = ["free", "-m"]

    cpu_result = run_proxmox_command(cpu_command, cpu_command, config['use_local_only'], host_details)
    mem_result = run_proxmox_command(mem_command, mem_command, config['use_local_only'], host_details)

    if cpu_result.returncode == 0 and mem_result.returncode == 0:
        cpu_info = cpu_result.stdout
        mem_info = mem_result.stdout

        # Extract CPU cores count from the "CPU(s):" line, not "On-line CPU(s) list:"
        total_cores = 0
        match = re.search(r'^CPU\(s\):\s*(\d+)', cpu_info, re.M)
        if match:
            total_cores = int(match.group(1))

        # Extract memory info
        mem_info_lines = mem_info.splitlines()
        total_memory = int(mem_info_lines[1].split()[1])
        free_memory = int(mem_info_lines[1].split()[3])

        return total_cores, total_memory, free_memory
    else:
        logging.error(f"Failed to retrieve host resources: {cpu_result.stderr} {mem_result.stderr}")
        return None, None, None

_SIZE_UNITS_GB = {'K': 1 / (1024 * 1024), 'M': 1 / 1024, 'G': 1, 'T': 1024}


def normalize_thresholds(thresholds):
    """Read threshold values above 1 as percentages (80 -> 0.80), in place.

    The code compares against fractions, but earlier versions of
    config.yaml.example wrote 30 and 80, which made every check suggest an
    increase.
    """
    for key in ('min_threshold', 'max_threshold'):
        value = thresholds.get(key)
        if isinstance(value, (int, float)) and value > 1:
            thresholds[key] = value / 100.0


def scale_check_get_lxc_resources(instance_id, host_details, host_cores=None):
    """
    The CPUs, the lws lxc scale option that sets them, the memory (MB) and the
    root disk size (GB) allocated to a container.

    A container without a `cores` setting may use every CPU of the host; its
    `cpulimit`, if set, caps the time it gets, so that is used instead, and
    `--cpulimit` is the option that changes it.
    """
    command = ["pct", "config", instance_id]
    result = run_proxmox_command(command, command, config['use_local_only'], host_details)

    if result.returncode == 0:
        settings = {}
        for line in result.stdout.splitlines():
            key, sep, value = line.partition(":")
            if sep:
                settings[key.strip()] = value.strip()

        cores = None
        cpu_option = '--cpucores'
        try:
            if 'cores' in settings:
                cores = int(settings['cores'])
            elif float(settings.get('cpulimit', 0) or 0) > 0:
                cores = max(1, math.ceil(float(settings['cpulimit'])))
                cpu_option = '--cpulimit'
            elif host_cores:
                cores = int(host_cores)
            memory = int(settings['memory']) if 'memory' in settings else None
        except ValueError:
            logging.error(f"Unexpected values in pct config for {instance_id}: {settings}")
            return None, None, None, None

        storage = None
        match = re.search(r'size=(\d+(?:\.\d+)?)([KMGT])', settings.get('rootfs', ''))
        if match:
            storage = round(float(match.group(1)) * _SIZE_UNITS_GB[match.group(2)], 2)
            if storage == int(storage):
                storage = int(storage)

        return cores, cpu_option, memory, storage
    else:
        logging.error(f"Failed to retrieve LXC resources for {instance_id}: {result.stderr}")
        return None, None, None, None


@px.command('backup')
@click.argument('backup_dir', callback=_validate_pattern(_SAFE_PATH_RE, "backup directory"))
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Defaults to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Defaults to az1")
def px_backup_hosts(backup_dir, region, az):
    """💾 Back up /etc/pve of a Proxmox host into a directory on that host."""
    logging.info(f"Starting backup for region {region}, AZ {az}")
    host_details = _host_details(region, az)
    use_local_only = config['use_local_only']

    # The archive is written where tar runs, on the Proxmox host, so the
    # directory has to exist there, not on the machine running LWS.
    mkdir = run_argv(["mkdir", "-p", backup_dir], use_local_only, host_details)
    if mkdir.returncode != 0:
        click.secho(f"❌ Failed to create {backup_dir} on the Proxmox host: {mkdir.stderr.strip()}", fg='red')
        sys.exit(1)

    backup_file = os.path.join(backup_dir, "proxmox-backup.tar.gz")
    logging.info(f"🛠️ Preparing to back up Proxmox configurations to {backup_file}.")
    result = run_argv(["tar", "-czf", backup_file, "/etc/pve"], use_local_only, host_details)

    # Check the result and provide appropriate feedback
    if result and result.returncode == 0:
        logging.info(f"✅ Backup completed successfully. Saved to {backup_file}.")
        click.secho(f"✅ Backup completed. Saved to {backup_file} on {host_details['host']}.", fg='green')
    else:
        logging.error(f"❌ Failed to backup hosts: {result.stderr if result else 'Unknown error'}")
        click.secho(f"❌ Failed to backup hosts: {result.stderr if result else 'Unknown error'}", fg='red')
        sys.exit(1)



### sec 
import ipaddress

# Helper function to load the configuration file
def sec_discovery_load_config(config_path='config.yaml'):
    """Loads the configuration from a YAML file."""
    try:
        with open(config_path, 'r') as file:
            config = yaml.safe_load(file)
            logging.debug(f"Configuration loaded successfully from {config_path}.")
            return config
    except Exception as e:
        logging.error(f"Failed to load configuration file: {str(e)}")
        return {}
    
@lws.group()
@command_alias('sec')
def sec():
    """⚠️ Security stuff (experimental)."""
    pass

@sec.command('discovery')
@click.argument('lxc_id', required=False, callback=_validate_pattern(_VMID_RE, "lxc id"))
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
def sec_discovery(lxc_id, region, az):
    """🔍 Discover reachable hosts in the same subnet at client, Proxmox, and LXC levels."""
    logging.info(f"Starting discovery for region {region}, AZ {az}, LXC ID {lxc_id}")

    config = sec_discovery_load_config()
    if not config:
        click.secho("❌ Failed to load configuration.", fg='red')
        return

    discovery_methods = config['security']['discovery'].get('discovery_methods', ['ping'])
    max_workers = config['security']['discovery'].get('max_parallel_workers', 10)

    reachable_hosts = {}

    # Perform discovery at the client level
    client_ip = sec_discovery_get_local_ip_address()
    if client_ip and not client_ip.startswith("127."):
        client_subnet = ipaddress.ip_network(client_ip + '/24', strict=False)
        click.secho(f"🔍 Client IP: {client_ip}, Subnet: {client_subnet}", fg='cyan')
        client_hosts = sec_discovery_perform_discovery('client', client_ip, client_subnet, discovery_methods, max_workers=max_workers)
        for host in client_hosts:
            reachable_hosts.setdefault(host, []).append(f"client ({client_ip})")

    # Perform discovery at the Proxmox node level
    host_details = sec_discovery_get_proxmox_host_details(region, az)
    proxmox_ip = sec_discovery_get_remote_ip_address(host_details)
    if proxmox_ip and not proxmox_ip.startswith("127."):
        proxmox_subnet = ipaddress.ip_network(proxmox_ip + '/24', strict=False)
        click.secho(f"🔍 Proxmox Host IP: {proxmox_ip}, Subnet: {proxmox_subnet}", fg='cyan')
        proxmox_hosts = sec_discovery_perform_discovery('proxmox', proxmox_ip, proxmox_subnet, discovery_methods, max_workers=max_workers, host_details=host_details)
        for host in proxmox_hosts:
            reachable_hosts.setdefault(host, []).append(f"proxmox ({proxmox_ip})")

    # Perform discovery at the LXC level if LXC ID is provided
    if lxc_id:
        lxc_ip = sec_discovery_get_lxc_ip_address(lxc_id, host_details)
        if lxc_ip and not lxc_ip.startswith("127."):
            lxc_subnet = ipaddress.ip_network(lxc_ip + '/24', strict=False)
            click.secho(f"🔍 LXC ID: {lxc_id}, IP: {lxc_ip}, Subnet: {lxc_subnet}", fg='cyan')
            lxc_hosts = sec_discovery_perform_discovery('lxc', lxc_ip, lxc_subnet, discovery_methods, max_workers=max_workers, host_details=host_details)
            for host in lxc_hosts:
                reachable_hosts.setdefault(host, []).append(f"lxc {lxc_id} ({lxc_ip})")

    # Combine and print the final list of reachable hosts
    if reachable_hosts:
        click.secho("🔍 Reachable hosts:", fg='white')
        for host, sources in reachable_hosts.items():
            click.secho(f"🟢 -> {host}", fg='green')
            # click.secho(f"🟢 -> {host} | {' | '.join(sources)}", fg='green')
    else:
        click.secho("❌ No reachable hosts found.", fg='red')
        sys.exit(1)

# Helper functions (prefix with sec_discovery_ to avoid conflicts)
def sec_discovery_get_local_ip_address():
    """Get the local IP address of the client."""
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    return local_ip

def sec_discovery_get_proxmox_host_details(region, az):
    """Retrieve Proxmox host details from the configuration."""
    config = sec_discovery_load_config()
    try:
        return config['regions'][region]['availability_zones'][az]
    except KeyError as e:
        logging.error(f"Invalid region or availability zone: {e}")
        return None

def sec_discovery_get_remote_ip_address(host_details):
    """Retrieve the IP address of a remote Proxmox host."""
    command = ["hostname", "-I"]
    result = run_ssh_command(host_details['host'], host_details['user'], host_details['ssh_password'], command)
    if result.returncode == 0:
        return result.stdout.split()[0]
    else:
        logging.error(f"Failed to retrieve remote IP address: {result.stderr}")
        return None

def sec_discovery_get_lxc_ip_address(lxc_id, host_details):
    """Retrieve the IP address of an LXC container."""
    command = ["pct", "exec", lxc_id, "--", "hostname", "-I"]
    result = run_ssh_command(host_details['host'], host_details['user'], host_details['ssh_password'], command)
    if result.returncode == 0:
        return result.stdout.split()[0]
    else:
        logging.error(f"Failed to retrieve LXC IP address for LXC ID {lxc_id}: {result.stderr}")
        return None



def sec_discovery_perform_discovery(level, source_ip, subnet, discovery_methods, max_workers=10, host_details=None):
    """Perform the discovery using multiple methods."""
    discovered_hosts = []

    def run_discovery_method(method, target_ip):
        command = []
        if method == "ping":
            command = ["ping", "-c", "1", "-W", "1", target_ip]
    #    elif method == "curl":
    #        command = ["curl", "-Is", "--connect-timeout", "1", "--dns-timeout", "1", "--max-time", "1", f"http://{target_ip}"]
    #    elif method == "wget":
    #        command = ["wget", "--read-timeout", "1", "--connect-timeout", "1", "--timeout", "1", f"http://{target_ip}"]

        if command:
            try:
                # Execute with a timeout using subprocess's built-in timeout feature
                result = execute_with_timeout(command, timeout=5, use_local_only=(level == "client"), host_details=host_details)
                if result.returncode == 0:
                    logging.debug(f"{method} succeeded for {target_ip} at level {level}.")
                    discovered_hosts.append(target_ip)
                else:
                    logging.debug(f"{method} failed for {target_ip} at level {level}.")
            except subprocess.TimeoutExpired:
                logging.error(f"Timeout reached for {method} on {target_ip} at level {level}.")
            except Exception as e:
                logging.error(f"An error occurred during discovery with {method} on {target_ip}: {str(e)}")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {
            executor.submit(run_discovery_method, method, str(ip)): str(ip)
            for ip in subnet
            if not str(ip).startswith("127.") and ip != subnet.network_address and ip != subnet.broadcast_address
            for method in discovery_methods
        }
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                future.result()
            except Exception as exc:
                logging.error(f"Error during discovery for {ip}: {exc}")

    return discovered_hosts

def execute_with_timeout(command, timeout, use_local_only, host_details=None):
    """Executes a command with a timeout using subprocess."""
    try:
        if use_local_only:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        else:
            result = run_ssh_command(host_details['host'], host_details['user'], host_details['ssh_password'], command)
        return result
    except subprocess.TimeoutExpired as e:
        logging.error(f"Command '{' '.join(command)}' timed out after {timeout} seconds")
        raise


# Add a dedicated function for diagnosing application-level issues
def diagnose_network(host_details, lxc_id=None):
    """
    Run network diagnostics on Proxmox or LXC container.
    
    Parameters:
    - host_details: Connection details for the Proxmox host
    - lxc_id: Optional ID of LXC container to diagnose
    
    Returns:
    - Dictionary containing diagnostic results
    """
    diagnostics = {}

    # Check network interfaces
    if lxc_id:
        command = ["pct", "exec", lxc_id, "--", "ip", "addr"]
    else:
        command = ["ip", "addr"]
    result = run_ssh_command(host_details['host'], host_details['user'], host_details['ssh_password'], command)
    diagnostics['network_interfaces'] = result.stdout if result.returncode == 0 else result.stderr

    # Check routing table
    if lxc_id:
        command = ["pct", "exec", lxc_id, "--", "ip", "route"]
    else:
        command = ["ip", "route"]
    result = run_ssh_command(host_details['host'], host_details['user'], host_details['ssh_password'], command)
    diagnostics['routing_table'] = result.stdout if result.returncode == 0 else result.stderr

    # Check DNS resolution
    if lxc_id:
        command = ["pct", "exec", lxc_id, "--", "nslookup", "google.com"]
    else:
        command = ["nslookup", "google.com"]
    result = run_ssh_command(host_details['host'], host_details['user'], host_details['ssh_password'], command)
    diagnostics['dns_resolution'] = result.stdout if result.returncode == 0 else result.stderr

    return diagnostics

_CPU_IDLE_RE = re.compile(r'([\d.]+)\s*%?\s*id\b')


def container_cpu_usage(instance_id, host_details):
    """
    CPU usage of a container in percent, from one `top -bn1` run inside it,
    or None if it cannot be read. The Cpu(s) line is parsed here rather than
    with `| grep` in the command, which would run on the Proxmox host over
    SSH and not at all in local mode.
    """
    result = run_argv(["pct", "exec", instance_id, "--", "top", "-bn1"], config['use_local_only'], host_details)
    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        if "Cpu" in line:
            match = _CPU_IDLE_RE.search(line)
            if match:
                return max(0.0, 100.0 - float(match.group(1)))
    return None


def show_top_processes(instance_id, host_details, sort_key, count=5):
    """Print the container's top processes by `sort_key` (`-%cpu` or `-%mem`)."""
    result = run_argv(["pct", "exec", instance_id, "--", "ps", "aux", f"--sort={sort_key}"],
                      config['use_local_only'], host_details)
    if result.returncode == 0:
        lines = result.stdout.strip().splitlines()[:count + 1]
        click.secho("   Busiest processes:\n" + "\n".join(f"   {line}" for line in lines), fg='white')


@lxc.command('health-check')
@click.argument('instance_id', required=True, callback=_validate_pattern(_VMID_RE, "instance id"))
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target.")
@click.option('--fix', is_flag=True, help="When the disk is over 80% full, delete files older than 7 days in /tmp and /var/tmp; when DNS fails, restart networking.")
def container_health_check(instance_id, region, az, fix):
    """💊 Perform health check on an LXC container."""
    host_details = config['regions'][region]['availability_zones'][az]
    
    click.secho(f"🔍 Performing health check on container {instance_id}...", fg='yellow')
    
    # Check if container is running
    status_cmd = ["pct", "status", instance_id]
    status_result = run_proxmox_command(status_cmd, status_cmd, config['use_local_only'], host_details)
    
    if status_result.returncode != 0 or "status: running" not in status_result.stdout:
        click.secho(f"❌ Container {instance_id} is not running.", fg='red')
        return
    
    # Check for high CPU usage. There is no automatic fix: which process to
    # stop is a decision for the operator, so the busiest ones are listed.
    usage_pct = container_cpu_usage(instance_id, host_details)
    if usage_pct is not None:
        if usage_pct > 80:
            click.secho(f"⚠️ High CPU usage detected: {usage_pct:.1f}%", fg='yellow')
            show_top_processes(instance_id, host_details, "-%cpu")
        else:
            click.secho(f"✅ CPU usage is normal: {usage_pct:.1f}%", fg='green')
    
    # Check for high memory usage
    mem_cmd = ["pct", "exec", instance_id, "--", "free", "-m"]
    mem_result = run_proxmox_command(mem_cmd, mem_cmd, config['use_local_only'], host_details)
    
    if mem_result.returncode == 0:
        mem_lines = mem_result.stdout.strip().split('\n')
        if len(mem_lines) >= 2:
            mem_values = mem_lines[1].split()
            total_mem = int(mem_values[1])
            used_mem = int(mem_values[2])
            mem_usage_pct = (used_mem / total_mem) * 100
            if mem_usage_pct > 80:
                click.secho(f"⚠️ High memory usage detected: {mem_usage_pct:.1f}%", fg='yellow')
                show_top_processes(instance_id, host_details, "-%mem")
            else:
                click.secho(f"✅ Memory usage is normal: {mem_usage_pct:.1f}%", fg='green')
    
    # Check for disk space usage
    disk_cmd = ["pct", "exec", instance_id, "--", "df", "-h", "/"]
    disk_result = run_proxmox_command(disk_cmd, disk_cmd, config['use_local_only'], host_details)
    
    if disk_result.returncode == 0:
        disk_lines = disk_result.stdout.strip().split('\n')
        if len(disk_lines) >= 2:
            disk_values = disk_lines[1].split()
            disk_usage_pct = float(disk_values[4].rstrip('%'))
            if disk_usage_pct > 80:
                click.secho(f"⚠️ High disk space usage detected: {disk_usage_pct:.1f}%", fg='yellow')
                if fix:
                    click.secho("🔧 Removing files older than 7 days from /tmp and /var/tmp...", fg='yellow')
                    # Only old temporary files, to avoid breaking running processes.
                    cleanup_cmd = ["pct", "exec", instance_id, "--", "find", "/tmp", "/var/tmp",
                                   "-xdev", "-type", "f", "-mtime", "+7", "-delete"]
                    cleanup_result = run_argv(cleanup_cmd, config['use_local_only'], host_details)
                    if cleanup_result.returncode != 0:
                        click.secho(f"⚠️ Cleanup finished with errors: {cleanup_result.stderr.strip()}", fg='yellow')
            else:
                click.secho(f"✅ Disk space usage is normal: {disk_usage_pct:.1f}%", fg='green')
    
    # Check for network issues
    network_diagnostics = diagnose_network(host_details, lxc_id=instance_id)
    if "unreachable" in network_diagnostics['dns_resolution']:
        click.secho("⚠️ Network issues detected: DNS resolution failed", fg='yellow')
        if fix:
            click.secho("🔧 Attempting to fix DNS resolution...", fg='yellow')
            restart_cmd = ["pct", "exec", instance_id, "--", "systemctl", "restart", "networking"]
            restart_result = run_argv(restart_cmd, config['use_local_only'], host_details)
            if restart_result.returncode != 0:
                click.secho(f"⚠️ Could not restart networking: {restart_result.stderr.strip()}", fg='yellow')
    else:
        click.secho("✅ Network is functioning normally.", fg='green')
    
    click.secho(f"✅ Health check for container {instance_id} completed.", fg='green')

# vzdump reports the archive it writes as
#   INFO: creating vzdump archive '/var/lib/vz/dump/vzdump-lxc-100-2026_10_10-08_00_00.tar.zst'
# (older versions: "creating archive '...'"), on stdout or stderr.
VZDUMP_ARCHIVE_RE = re.compile(r"creating (?:vzdump )?archive '([^']+)'")
# A Proxmox volume ID such as local:backup/vzdump-lxc-100-....tar.zst
_VOLUME_ID_RE = re.compile(r'^[A-Za-z0-9_-]+:\S+$')


@lxc.command('backup-restore')
@click.argument('instance_id', required=True, callback=_validate_pattern(_VMID_RE, "instance id"))
@click.option('--backup-file', required=True,
              help="A vzdump archive: a path on the Proxmox host, a volume ID (local:backup/vzdump-lxc-...), or a file on this machine, which is uploaded.")
@click.option('--storage', default=None, callback=_validate_pattern(_SAFE_NAME_RE, "storage"),
              help="Storage for the restored disks. Default: default_storage from config.yaml.")
@click.option('--start/--no-start', default=True, help="Start the container after the restore. Default: start.")
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target.")
@click.option('--force', is_flag=True, help="Do not ask for confirmation.")
def restore_container(instance_id, backup_file, storage, start, region, az, force):
    """🔄 Restore an LXC container from a vzdump backup.

    If INSTANCE_ID exists, it is stopped and replaced by the backup: its
    current disks are destroyed. The backup file itself is never deleted.
    """
    # Without --storage, pct restore puts every disk on the storage named
    # `local`, which on a default installation cannot hold container disks.
    storage = storage or config.get('default_storage')
    if not storage:
        raise click.UsageError("Pass --storage, or set default_storage in config.yaml: without a storage, "
                               "pct restore uses 'local', which usually cannot hold container disks.")
    host_details = _host_details(region, az)
    use_local = config['use_local_only']

    status = run_argv(["pct", "status", instance_id], use_local, host_details)
    exists = status.returncode == 0
    running = exists and "status: running" in status.stdout

    if not force:
        if exists:
            click.confirm(f"⚠️ Container {instance_id} exists. Replace it with the backup? Its current disks "
                          "are destroyed.", abort=True)
        else:
            click.confirm(f"Restore {backup_file} as new container {instance_id}?", abort=True)

    source = backup_file
    uploaded = None
    if os.path.isfile(backup_file) and not use_local:
        # Keep the archive's own name: pct restore reads the format from the extension.
        uploaded = f"/var/tmp/lws-restore-{int(time.time())}-{os.path.basename(backup_file)}"
        click.secho("📤 Uploading backup file to Proxmox host...", fg='yellow')
        upload = run_scp_command(host_details['ssh_password'], backup_file,
                                 f"{host_details['user']}@{host_details['host']}:{uploaded}")
        if upload.returncode != 0:
            click.secho(f"❌ Failed to upload backup file: {upload.stderr.strip()}", fg='red')
            sys.exit(1)
        source = uploaded
    elif not _VOLUME_ID_RE.match(backup_file):
        check = run_argv(["test", "-f", backup_file], use_local, host_details)
        if check.returncode != 0:
            click.secho(f"❌ Backup file not found on the Proxmox host: {backup_file}", fg='red')
            sys.exit(1)

    if running:
        click.secho("⚠️ Container is running. Stopping it before the restore...", fg='yellow')
        stop = run_argv(["pct", "stop", instance_id], use_local, host_details)
        if stop.returncode != 0:
            click.secho(f"❌ Failed to stop container {instance_id}: {stop.stderr.strip()}", fg='red')
            sys.exit(1)

    restore_cmd = ["pct", "restore", instance_id, source, "--storage", storage]
    if exists:
        restore_cmd += ["--force", "1"]
    click.secho(f"🔄 Restoring container {instance_id} from {backup_file}...", fg='yellow')
    restore = run_argv(restore_cmd, use_local, host_details)

    if uploaded:
        # Only the temporary copy LWS made; the original stays where it was.
        run_argv(["rm", "-f", uploaded], use_local, host_details)

    if restore.returncode != 0:
        click.secho(f"❌ Failed to restore container {instance_id}: {restore.stderr.strip()}", fg='red')
        sys.exit(1)
    click.secho(f"✅ Container {instance_id} restored.", fg='green')

    if start:
        started = run_argv(["pct", "start", instance_id], use_local, host_details)
        if started.returncode != 0:
            click.secho(f"❌ Failed to start container {instance_id}: {started.stderr.strip()}", fg='red')
            sys.exit(1)
        click.secho(f"✅ Container {instance_id} started.", fg='green')


@lxc.command('backup-create')
@click.argument('instance_id', required=True, callback=_validate_pattern(_VMID_RE, "instance id"))
@click.option('--destination', default="/var/lib/vz/dump", callback=_validate_pattern(_SAFE_PATH_RE, "destination"),
              help="Directory on the Proxmox host for the archive (vzdump --dumpdir). Default: /var/lib/vz/dump.")
@click.option('--storage', default=None, callback=_validate_pattern(_SAFE_NAME_RE, "storage"),
              help="A Proxmox backup storage to write to instead of --destination (vzdump --storage).")
@click.option('--mode', type=click.Choice(['snapshot', 'suspend', 'stop']), default='snapshot',
              help="vzdump mode. Default: snapshot (no downtime; needs storage that supports snapshots).")
@click.option('--compress', type=click.Choice(['zstd', 'gzip', 'lzo', 'none']), default='zstd',
              help="Compression of the archive. Default: zstd.")
@click.option('--compress-level', default=None, type=int, hidden=True,
              help="Deprecated and ignored: vzdump has no compression level setting.")
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target.")
@click.option('--download', is_flag=True, help="Copy the archive into the current directory afterwards.")
def create_container_backup(instance_id, destination, storage, mode, compress, compress_level, region, az, download):
    """💾 Create a vzdump backup of an LXC container."""
    host_details = _host_details(region, az)
    use_local = config['use_local_only']

    if compress_level is not None:
        click.secho("⚠️ --compress-level is ignored: vzdump has no compression level. Use --compress.", fg='yellow')

    backup_cmd = ["vzdump", instance_id, "--mode", mode, "--compress", "0" if compress == 'none' else compress]
    if storage:
        backup_cmd += ["--storage", storage]
    else:
        mkdir = run_argv(["mkdir", "-p", destination], use_local, host_details)
        if mkdir.returncode != 0:
            click.secho(f"❌ Failed to create destination directory: {mkdir.stderr.strip()}", fg='red')
            sys.exit(1)
        backup_cmd += ["--dumpdir", destination]

    click.secho(f"📦 Creating backup of container {instance_id}...", fg='yellow')
    backup = run_argv(backup_cmd, use_local, host_details)
    if backup.returncode != 0:
        click.secho(f"❌ Failed to create backup: {backup.stderr.strip()}", fg='red')
        sys.exit(1)

    match = VZDUMP_ARCHIVE_RE.search(f"{backup.stdout}\n{backup.stderr}")
    if not match:
        click.secho("✅ Backup created. vzdump did not report a file name (for example on a Proxmox Backup "
                    "Server storage); list it with: pvesm list <storage>", fg='green')
        if download:
            click.secho("❌ Nothing to download without a file name.", fg='red')
            sys.exit(1)
        return

    backup_path = match.group(1)
    click.secho(f"✅ Backup created: {backup_path}", fg='green')

    if download:
        if use_local:
            click.secho(f"ℹ️ use_local_only is set: the archive is already on this machine at {backup_path}.", fg='yellow')
            return
        local_path = os.path.basename(backup_path)
        click.secho("📥 Downloading backup file to the current directory...", fg='yellow')
        scp = run_scp_command(host_details['ssh_password'],
                              f"{host_details['user']}@{host_details['host']}:{backup_path}", local_path)
        if scp.returncode != 0:
            click.secho(f"❌ Failed to download backup: {scp.stderr.strip()}", fg='red')
            sys.exit(1)
        click.secho(f"✅ Backup downloaded to {os.path.abspath(local_path)}", fg='green')


@sec.command('scan')
@click.argument('instance_id', required=True, callback=_validate_pattern(_VMID_RE, "instance id"))
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target.")
@click.option('--scan-type', type=click.Choice(['quick', 'full']), default='quick', help="Type of security scan to perform.")
def security_scan(instance_id, region, az, scan_type):
    """🔒 Perform a security scan on an LXC container."""
    host_details = config['regions'][region]['availability_zones'][az]
    
    click.secho(f"🔍 Starting {scan_type} security scan of container {instance_id}...", fg='yellow')
    
    # Check if container is running
    status_cmd = ["pct", "status", instance_id]
    status_result = run_proxmox_command(status_cmd, status_cmd, config['use_local_only'], host_details)
    
    if status_result.returncode != 0 or "status: running" not in status_result.stdout:
        click.secho(f"❌ Container {instance_id} is not running.", fg='red')
        return
    
    # Ensure required tools are installed in the container (lynis only for a full scan)
    tools = ["nmap", "lynis"] if scan_type == 'full' else ["nmap"]
    for tool in tools:
        check_tool_cmd = ["pct", "exec", instance_id, "--", "which", tool]
        check_result = run_proxmox_command(check_tool_cmd, check_tool_cmd, config['use_local_only'], host_details)
        
        if check_result.returncode != 0:
            # Try to install the missing tool
            click.secho(f"📦 Installing {tool} in container {instance_id}...", fg='yellow')
            # Both apt-get steps run inside the container: the script goes to the
            # container's shell, quoted so the host's shell does not split it.
            install_cmd = ["pct", "exec", instance_id, "--", "sh", "-c",
                           f"apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y {tool}"]
            install_result = run_argv(install_cmd, config['use_local_only'], host_details)

            if install_result.returncode != 0:
                click.secho(f"❌ Failed to install {tool}: {install_result.stderr}", fg='red')
                sys.exit(1)
    
    # 1. Check for exposed services using nmap
    click.secho("🔍 Checking for exposed services...", fg='yellow')
    nmap_cmd = ["pct", "exec", instance_id, "--", "nmap", "-sT", "-p", "1-65535", "localhost"]
    nmap_result = run_proxmox_command(nmap_cmd, nmap_cmd, config['use_local_only'], host_details)
    
    if nmap_result.returncode == 0:
        click.secho("🔌 Exposed services:", fg='cyan')
        in_services_section = False
        for line in nmap_result.stdout.splitlines():
            if "/tcp" in line and "open" in line:
                click.secho(f"  {line}", fg='white')
    else:
        click.secho(f"❌ Failed to scan for exposed services: {nmap_result.stderr}", fg='red')
    
    # 2. Check for outdated packages
    click.secho("🔍 Checking for outdated packages...", fg='yellow')
    outdated_cmd = ["pct", "exec", instance_id, "--", "apt", "list", "--upgradable"]
    outdated_result = run_proxmox_command(outdated_cmd, outdated_cmd, config['use_local_only'], host_details)
    
    if outdated_result.returncode == 0:
        outdated_packages = [line for line in outdated_result.stdout.splitlines() if "/" in line]
        if outdated_packages:
            click.secho(f"📦 Found {len(outdated_packages)} outdated packages:", fg='yellow')
            for package in outdated_packages[:10]:  # Limit to 10 packages to avoid flooding
                click.secho(f"  {package}", fg='white')
            if len(outdated_packages) > 10:
                click.secho(f"  ... and {len(outdated_packages) - 10} more", fg='white')
        else:
            click.secho("✅ All packages are up to date.", fg='green')
    else:
        click.secho(f"❌ Failed to check for outdated packages: {outdated_result.stderr}", fg='red')
    
    # 3. Run system security audit with Lynis if full scan requested
    if scan_type == 'full':
        click.secho("🔍 Running full system security audit with Lynis...", fg='yellow')
        lynis_cmd = ["pct", "exec", instance_id, "--", "lynis", "audit", "system"]
        lynis_result = run_proxmox_command(lynis_cmd, lynis_cmd, config['use_local_only'], host_details)
        
        if lynis_result.returncode == 0:
            # Extract warnings from Lynis output
            warnings = []
            in_warning_section = False
            for line in lynis_result.stdout.splitlines():
                if "Warnings:" in line:
                    in_warning_section = True
                    continue
                if in_warning_section and line.strip() == "":
                    in_warning_section = False
                    continue
                if in_warning_section:
                    warnings.append(line.strip())
            
            if warnings:
                click.secho(f"⚠️ Security warnings found:", fg='yellow')
                for warning in warnings:
                    click.secho(f"  {warning}", fg='white')
            else:
                click.secho("✅ No critical security issues found.", fg='green')
        else:
            click.secho(f"❌ Failed to run Lynis security audit: {lynis_result.stderr}", fg='red')
            sys.exit(1)
    
    # 4. Check for weak SSH configuration
    click.secho("🔍 Checking SSH configuration...", fg='yellow')
    ssh_cmd = ["pct", "exec", instance_id, "--", "cat", "/etc/ssh/sshd_config"]
    ssh_result = run_proxmox_command(ssh_cmd, ssh_cmd, config['use_local_only'], host_details)
    
    if ssh_result.returncode == 0:
        ssh_issues = []
        
        # Check for root login permitted
        if "PermitRootLogin yes" in ssh_result.stdout:
            ssh_issues.append("Root login is permitted")
        
        # Check for password authentication
        if "PasswordAuthentication yes" in ssh_result.stdout:
            ssh_issues.append("Password authentication is enabled")
        
        # Check for protocol version
        if "Protocol 1" in ssh_result.stdout:
            ssh_issues.append("SSH Protocol 1 is enabled (insecure)")
        
        if ssh_issues:
            click.secho("⚠️ SSH configuration issues:", fg='yellow')
            for issue in ssh_issues:
                click.secho(f"  {issue}", fg='white')
        else:
            click.secho("✅ SSH configuration appears secure.", fg='green')
    else:
        click.secho(f"❌ Failed to check SSH configuration: {ssh_result.stderr}", fg='red')
    
    click.secho(f"✅ Security scan of container {instance_id} completed.", fg='green')

@lxc.command('resources')
@click.argument('instance_id', required=True, callback=_validate_pattern(_VMID_RE, "instance id"))
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target.")
@click.option('--interval', default=2, help="Monitoring interval in seconds.")
@click.option('--count', default=5, help="Number of monitoring intervals.")
def monitor_container_resources(instance_id, region, az, interval, count):
    """📊 Monitor real-time resource usage of an LXC container."""
    host_details = config['regions'][region]['availability_zones'][az]
    
    # Check if container is running
    status_cmd = ["pct", "status", instance_id]
    status_result = run_proxmox_command(status_cmd, status_cmd, config['use_local_only'], host_details)
    
    if status_result.returncode != 0 or "status: running" not in status_result.stdout:
        click.secho(f"❌ Container {instance_id} is not running.", fg='red')
        return
    
    click.secho(f"📊 Monitoring resource usage for container {instance_id} (interval: {interval}s, count: {count})", fg='cyan')
    
    # Get container resource limits
    config_cmd = ["pct", "config", instance_id]
    config_result = run_proxmox_command(config_cmd, config_cmd, config['use_local_only'], host_details)
    
    if config_result.returncode != 0:
        click.secho(f"❌ Failed to get container configuration: {config_result.stderr}", fg='red')
        return
    
    # Parse CPU and memory limits
    settings = {}
    for line in config_result.stdout.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            settings[key.strip()] = value.strip()
    if 'cores' in settings:
        cpu_limit = f"{settings['cores']} cores"
    elif float(settings.get('cpulimit', 0) or 0) > 0:
        cpu_limit = f"limited to the time of {settings['cpulimit']} CPUs"
    else:
        cpu_limit = "all host CPUs"
    memory_limit = settings.get('memory', 'unknown')

    click.secho(f"📌 Resource limits - CPU: {cpu_limit}, Memory: {memory_limit} MB", fg='cyan')
    
    # Monitor resource usage over time
    for i in range(count):
        if i > 0:
            time.sleep(interval)
        
        # Get CPU usage
        usage_pct = container_cpu_usage(instance_id, host_details)

        # Get memory usage
        mem_cmd = ["pct", "exec", instance_id, "--", "free", "-m"]
        mem_result = run_proxmox_command(mem_cmd, mem_cmd, config['use_local_only'], host_details)
        
        # Get disk usage
        disk_cmd = ["pct", "exec", instance_id, "--", "df", "-h", "/"]
        disk_result = run_proxmox_command(disk_cmd, disk_cmd, config['use_local_only'], host_details)
        
        # Get running processes count
        proc_result = run_argv(["pct", "exec", instance_id, "--", "ps", "-e", "--no-headers"],
                               config['use_local_only'], host_details)
        
        click.secho(f"\n📊 Snapshot {i+1}/{count} at {time.strftime('%H:%M:%S')}", fg='yellow')
        
        # Parse and display CPU usage
        if usage_pct is not None:
            cpu_color = 'green' if usage_pct < 70 else ('yellow' if usage_pct < 90 else 'red')
            click.secho(f"CPU Usage: {usage_pct:.1f}%", fg=cpu_color)
        else:
            click.secho("CPU Usage: Unable to retrieve", fg='red')
        
        # Parse and display memory usage
        if mem_result.returncode == 0:
            try:
                mem_lines = mem_result.stdout.strip().split('\n')
                if len(mem_lines) >= 2:
                    mem_values = mem_lines[1].split()
                    total_mem = int(mem_values[1])
                    used_mem = int(mem_values[2])
                    mem_usage_pct = (used_mem / total_mem) * 100 if total_mem > 0 else 0
                    mem_color = 'green' if mem_usage_pct < 70 else ('yellow' if mem_usage_pct < 90 else 'red')
                    click.secho(f"Memory Usage: {used_mem} MB / {total_mem} MB ({mem_usage_pct:.1f}%)", fg=mem_color)
            except (ValueError, IndexError, ZeroDivisionError) as e:
                logging.warning(f"Failed to parse memory usage data: {e}")
                click.secho(f"Memory Usage: Unable to parse", fg='red')
        else:
            click.secho(f"Memory Usage: Unable to retrieve", fg='red')
        
        # Parse and display disk usage
        if disk_result.returncode == 0:
            try:
                disk_lines = disk_result.stdout.strip().split('\n')
                if len(disk_lines) >= 2:
                    disk_values = disk_lines[1].split()
                    if len(disk_values) >= 5:
                        disk_usage = disk_values[4].rstrip('%')
                        disk_color = 'green' if float(disk_usage) < 70 else ('yellow' if float(disk_usage) < 90 else 'red')
                        click.secho(f"Disk Usage: {disk_usage}% of {disk_values[1]}", fg=disk_color)
            except (ValueError, IndexError) as e:
                logging.warning(f"Failed to parse disk usage data: {e}")
                click.secho(f"Disk Usage: Unable to parse", fg='red')
        else:
            click.secho(f"Disk Usage: Unable to retrieve", fg='red')
        
        # Display process count
        if proc_result.returncode == 0:
            try:
                proc_count = len(proc_result.stdout.strip().splitlines())
                click.secho(f"Running Processes: {proc_count}", fg='cyan')
            except ValueError as e:
                logging.warning(f"Failed to parse process count: {e}")
                click.secho(f"Running Processes: Unable to parse", fg='red')
        else:
            click.secho(f"Running Processes: Unable to retrieve", fg='red')
    
    click.secho(f"\n✅ Resource monitoring for container {instance_id} completed.", fg='green')

@lxc.command('report')
@click.argument('instance_id', required=True, callback=_validate_pattern(_VMID_RE, "instance id"))
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target.")
@click.option('--output', type=click.Choice(['text', 'json']), default='text', help="Output format.")
@click.option('--file', type=click.Path(), help="Save report to file instead of displaying.")
def generate_container_report(instance_id, region, az, output, file):
    """📋 Generate a comprehensive report about an LXC container."""
    host_details = config['regions'][region]['availability_zones'][az]
    
    click.secho(f"🔍 Generating report for container {instance_id}...", fg='yellow')
    
    report = {
        "container_id": instance_id,
        "report_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "region": region,
        "availability_zone": az
    }
    
    # 1. Get container status
    status_cmd = ["pct", "status", instance_id]
    status_result = run_proxmox_command(status_cmd, status_cmd, config['use_local_only'], host_details)
    
    if status_result.returncode == 0:
        status_text = status_result.stdout.strip()
        if "status: running" in status_text:
            report["status"] = "running"
        elif "status: stopped" in status_text:
            report["status"] = "stopped"
        else:
            report["status"] = "unknown"
    else:
        report["status"] = "error"
        report["status_error"] = status_result.stderr.strip()
    
    # 2. Get container configuration
    config_cmd = ["pct", "config", instance_id]
    config_result = run_proxmox_command(config_cmd, config_cmd, config['use_local_only'], host_details)
    
    if config_result.returncode == 0:
        config_text = config_result.stdout.strip()
        config_dict = {}
        
        for line in config_text.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                config_dict[key.strip()] = value.strip()
        
        report["configuration"] = config_dict
    else:
        report["configuration"] = {"error": config_result.stderr.strip()}
    
    # 3. Get resource usage (if running)
    if report["status"] == "running":
        # CPU usage
        cpu_cmd = ["pct", "exec", instance_id, "--", "top", "-bn1"]
        cpu_result = run_proxmox_command(cpu_cmd, cpu_cmd, config['use_local_only'], host_details)
        
        if cpu_result.returncode == 0:
            cpu_info = {"raw": cpu_result.stdout.strip()}
            
            # Parse CPU usage
            cpu_line = None
            for line in cpu_result.stdout.splitlines():
                if "Cpu(s):" in line:
                    cpu_line = line.strip()
                    break
            
            if cpu_line:
                cpu_info["usage_line"] = cpu_line
                try:
                    idle_part = cpu_line.split("id,")[0].split()[-1]
                    idle_pct = float(idle_part)
                    cpu_info["usage_percent"] = round(100.0 - idle_pct, 1)
                except (ValueError, IndexError) as e:
                    logging.debug(f"Could not parse CPU usage: {e}")
                    cpu_info["usage_percent"] = None
            
            report["cpu"] = cpu_info
        else:
            report["cpu"] = {"error": cpu_result.stderr.strip()}
        
        # Memory usage
        mem_cmd = ["pct", "exec", instance_id, "--", "free", "-m"]
        mem_result = run_proxmox_command(mem_cmd, mem_cmd, config['use_local_only'], host_details)
        
        if mem_result.returncode == 0:
            mem_info = {"raw": mem_result.stdout.strip()}
            
            try:
                mem_lines = mem_result.stdout.strip().split('\n')
                if len(mem_lines) >= 2:
                    mem_values = mem_lines[1].split()
                    mem_info["total_mb"] = int(mem_values[1])
                    mem_info["used_mb"] = int(mem_values[2])
                    mem_info["free_mb"] = int(mem_values[3])
                    mem_info["usage_percent"] = round((mem_info["used_mb"] / mem_info["total_mb"]) * 100, 1)
            except (ValueError, IndexError, ZeroDivisionError) as e:
                logging.debug(f"Could not parse memory details: {e}")
                pass
            
            report["memory"] = mem_info
        else:
            report["memory"] = {"error": mem_result.stderr.strip()}
        
        # Disk usage
        disk_cmd = ["pct", "exec", instance_id, "--", "df", "-h"]
        disk_result = run_proxmox_command(disk_cmd, disk_cmd, config['use_local_only'], host_details)
        
        if disk_result.returncode == 0:
            disk_info = {"raw": disk_result.stdout.strip()}
            
            try:
                # Parse the filesystem information
                filesystems = []
                disk_lines = disk_result.stdout.strip().split('\n')
                headers = disk_lines[0].split()
                
                for line in disk_lines[1:]:
                    values = line.split()
                    if len(values) >= len(headers):
                        fs_info = {}
                        for i, header in enumerate(headers):
                            fs_info[header.lower()] = values[i]
                        filesystems.append(fs_info)
                
                disk_info["filesystems"] = filesystems
            except (ValueError, IndexError) as e:
                logging.debug(f"Could not parse disk details: {e}")
                pass
            
            report["disk"] = disk_info
        else:
            report["disk"] = {"error": disk_result.stderr.strip()}
        
        # Network information
        net_cmd = ["pct", "exec", instance_id, "--", "ip", "addr"]
        net_result = run_proxmox_command(net_cmd, net_cmd, config['use_local_only'], host_details)
        
        if net_result.returncode == 0:
            net_info = {"raw": net_result.stdout.strip()}
            
            # Extract IP addresses
            ip_addresses = []
            current_interface = None
            
            for line in net_result.stdout.splitlines():
                line = line.strip()
                
                # Match interface lines
                if ": " in line and not line.startswith(" "):
                    current_interface = line.split(": ")[1].split("@")[0]
                
                # Match IP address lines
                elif "inet " in line and current_interface:
                    ip_addr = line.split("inet ")[1].split("/")[0]
                    ip_addresses.append({"interface": current_interface, "address": ip_addr})
            
            net_info["ip_addresses"] = ip_addresses
            report["network"] = net_info
        else:
            report["network"] = {"error": net_result.stderr.strip()}
        
        # Running processes
        ps_cmd = ["pct", "exec", instance_id, "--", "ps", "aux", "--sort=-%mem"]
        ps_result = run_argv(ps_cmd, config['use_local_only'], host_details)
        
        if ps_result.returncode == 0:
            # Header plus the ten processes using the most memory.
            proc_lines = ps_result.stdout.strip().split('\n')[:11]
            
            if len(proc_lines) > 1:  # Ensure we have at least a header and a process
                top_processes = []
                headers = proc_lines[0].split()
                
                for line in proc_lines[1:]:
                    process = {}
                    parts = line.split(None, len(headers) - 1)
                    
                    for i, header in enumerate(headers):
                        if i < len(parts):
                            # Try to convert numeric values
                            try:
                                if header in ['%CPU', '%MEM']:
                                    process[header.lower().replace('%', '')] = float(parts[i])
                                elif header in ['PID', 'VSZ', 'RSS']:
                                    process[header.lower()] = int(parts[i])
                                else:
                                    process[header.lower()] = parts[i]
                            except (ValueError, IndexError) as e:
                                logging.debug(f"Could not convert process value {parts[i] if i < len(parts) else 'N/A'} for {header}: {e}")
                                process[header.lower()] = parts[i]
                    
                    top_processes.append(process)
                
                report["processes"] = {
                    "top_by_memory": top_processes,
                    "count": len(top_processes)
                }
            else:
                report["processes"] = {"raw": ps_result.stdout.strip()}
        else:
            report["processes"] = {"error": ps_result.stderr.strip()}
    
    # Format and output the report
    if output == 'json':
        formatted_report = json.dumps(report, indent=2)
    else:  # text format
        formatted_report = f"Container Report: {instance_id}\n"
        formatted_report += f"Generated: {report['report_time']}\n"
        formatted_report += f"Region: {report['region']}, AZ: {report['availability_zone']}\n\n"
        
        # Status
        formatted_report += f"Status: {report['status'].upper()}\n\n"
        
        # Configuration
        formatted_report += "Configuration:\n"
        if "configuration" in report and isinstance(report["configuration"], dict):
            for key, value in report["configuration"].items():
                formatted_report += f"  {key}: {value}\n"
        
        # Resource usage
        if report["status"] == "running":
            formatted_report += "\nResource Usage:\n"
            
            # CPU
            if "cpu" in report and "usage_percent" in report["cpu"] and report["cpu"]["usage_percent"] is not None:
                formatted_report += f"  CPU: {report['cpu']['usage_percent']}% used\n"
            
            # Memory
            if "memory" in report and "usage_percent" in report["memory"]:
                formatted_report += f"  Memory: {report['memory']['used_mb']}/{report['memory']['total_mb']} MB ({report['memory']['usage_percent']}%)\n"
            
            # Disk
            if "disk" in report and "filesystems" in report["disk"]:
                formatted_report += "  Disk Usage:\n"
                for fs in report["disk"]["filesystems"]:
                    if "filesystem" in fs and "use%" in fs:
                        formatted_report += f"    {fs.get('filesystem', 'unknown')}: {fs.get('use%', 'unknown')} of {fs.get('size', 'unknown')}\n"
            
            # Network
            if "network" in report and "ip_addresses" in report["network"]:
                formatted_report += "  IP Addresses:\n"
                for ip in report["network"]["ip_addresses"]:
                    formatted_report += f"    {ip['interface']}: {ip['address']}\n"
            
            # Processes
            if "processes" in report and "top_by_memory" in report["processes"]:
                formatted_report += "\nTop Processes (by memory usage):\n"
                for proc in report["processes"]["top_by_memory"][:5]:  # Limit to top 5
                    formatted_report += f"  {proc.get('pid', 'N/A')} {proc.get('user', 'N/A')} {proc.get('cpu', 'N/A')}% {proc.get('mem', 'N/A')}% {proc.get('command', 'N/A')}\n"
    
    # Output the report
    if file:
        with open(file, 'w') as f:
            f.write(formatted_report)
        click.secho(f"✅ Report saved to {file}", fg='green')
    else:
        click.secho(formatted_report, fg='cyan')
    
    click.secho(f"✅ Report generation for container {instance_id} completed.", fg='green')

if __name__ == '__main__':
    try:
        lws()
    except Exception as e:
        click.secho(f"❌ An unexpected error occurred: {str(e)}", fg='red')
        logging.exception("Unexpected error in main execution")
        sys.exit(1)
