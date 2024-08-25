#!/usr/bin/env python3

import os
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
from concurrent.futures import ThreadPoolExecutor, as_completed



class JsonFormatter(logging.Formatter):
    """Custom JSON formatter for logging."""

    def format(self, record):
        log_record = {
            'timestamp': self.formatTime(record, self.datefmt),
            'level': record.levelname,
            'module': record.name,
            'message': record.getMessage(),
        }
        if record.exc_info:
            log_record['exception'] = self.formatException(record.exc_info)
        return json.dumps(log_record)

def setup_logging(log_level=logging.DEBUG, log_file=None, json_log_file=None):
    """
    Sets up the logging configuration.
    
    Parameters:
    - log_level: The logging level (e.g., logging.DEBUG, logging.INFO).
    - log_file: Optional file path to log in standard format.
    - json_log_file: Optional file path to log in JSON format.
    """
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    log_date_format = "%Y-%m-%d %H:%M:%S"

    handlers = {
        'console': {
            'level': log_level,
            'class': 'logging.StreamHandler',
            'formatter': 'default',
        }
    }

    if log_file:
        handlers['file'] = {
            'level': log_level,
            'class': 'logging.FileHandler',
            'formatter': 'default',
            'filename': log_file,
        }

    if json_log_file:
        handlers['json_file'] = {
            'level': log_level,
            'class': 'logging.FileHandler',
            'formatter': 'json',
            'filename': json_log_file,
        }

    logging_config = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'default': {
                'format': log_format,
                'datefmt': log_date_format,
            },
            'json': {
                '()': JsonFormatter,
                'datefmt': log_date_format,
            }
        },
        'handlers': handlers,
        'root': {
            'level': log_level,
            'handlers': (handlers.keys()),
        },
    }

    logging.config.dictConfig(logging_config)
    logging.info("Logging setup complete. Logging to console, and additional JSON logging to file {}".format(json_log_file if json_log_file else "not configured"))

# Example usage:
log_file_path = os.path.join(os.getcwd(), 'lws.log')  # Standard log file path
json_log_file_path = os.path.join(os.getcwd(), 'lws.json.log')  # JSON log file path

# Set up logging: standard logging to console and file, JSON logging to a separate file
setup_logging(log_level=logging.ERROR, log_file=log_file_path, json_log_file=json_log_file_path)

# Load and validate the configuration
def load_config():
    try:
        with open('config.yaml', 'r') as file:
            config = yaml.safe_load(file)
        validate_config(config)
        return config
    except FileNotFoundError:
        logging.error("Configuration file 'config.yaml' not found.")
        raise
    except yaml.YAMLError as e:
        logging.error(f"Error parsing configuration file: {e}")
        raise

def validate_config(config):
    required_keys = ['regions', 'instance_sizes']
    for key in required_keys:
        if key not in config:
            logging.error(f"Missing required configuration key: {key}")
            raise ValueError(f"Missing required configuration key: {key}")

    if not isinstance(config['regions'], dict) or not config['regions']:
        logging.error("Invalid or empty 'regions' configuration.")
        raise ValueError("Invalid or empty 'regions' configuration.")

    if not isinstance(config['instance_sizes'], dict) or not config['instance_sizes']:
        logging.error("Invalid or empty 'instance_sizes' configuration.")
        raise ValueError("Invalid or empty 'instance_sizes' configuration.")

config = load_config()

# lws
@click.group()
def lws():
    """🐧 Linux (Containers) Web Services"""
    pass

def run_ssh_command(host, user, ssh_password, command):
    """Runs an SSH command on a remote host, with error handling and logging."""
    ssh_cmd = ["sshpass", "-p", ssh_password, "ssh", f"{user}@{host}"] + command
    
    # Construct a sanitized command for logging (hides the password)
    sanitized_ssh_cmd = ["sshpass", "-p", "****", "ssh", f"{user}@{host}"] + command

    try:
        # Log the sanitized command instead of the real command with the password
        logging.debug(f"Executing SSH command: {' '.join(sanitized_ssh_cmd)}")
        
        # Execute the command
        result = subprocess.run(ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        result.check_returncode()  # This raises CalledProcessError if returncode is non-zero
        
        # Log the successful execution and output
        logging.debug(f"SSH command executed successfully: {' '.join(sanitized_ssh_cmd)}")
        logging.debug(f"Command output: {result.stdout}")
        
        return result  # Return the entire result object

    except subprocess.CalledProcessError as e:
        # Log the error without showing the password
        logging.error(f"SSH command failed with return code {e.returncode}: {' '.join(sanitized_ssh_cmd)}")
        logging.error(f"Error output: {e.stderr}")
        return e

    except Exception as e:
        logging.error(f"An unexpected error occurred while running SSH command: {str(e)}")
        return None

def execute_command(cmd, use_local_only, host_details=None):
    """Executes a command locally or via SSH based on the configuration."""
    if use_local_only:
        logging.debug(f"Executing local command: {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            result.check_returncode()
            logging.debug(f"Local command output: {result.stdout}")
            return result
        except subprocess.CalledProcessError as e:
            logging.error(f"Local command failed: {e}")
            return e
    else:
        logging.debug(f"Executing remote command: {' '.join(cmd)} on {host_details['host']}")
        return run_ssh_command(host_details['host'], host_details['user'], host_details['ssh_password'], cmd)

def run_proxmox_command(local_cmd, remote_cmd=None, use_local_only=False, host_details=None):
    """Executes a Proxmox command either locally or remotely."""
    cmd = local_cmd if use_local_only else remote_cmd
    if cmd is None:
        raise ValueError("Command cannot be None.")
    return execute_command(cmd, use_local_only, host_details)


# Command alias decorator
def command_alias(*aliases):
    def decorator(f):
        for alias in aliases:
            lws.command(alias)(f)
        return f
    return decorator

# Generic function to process instance commands
def process_instance_command(instance_ids, command_type, region, az, **kwargs):
    host_details = config['regions'][region]['availability_zones'][az]

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

    for instance_id in instance_ids:
        if command_type in ['snapshot_create', 'snapshot_delete']:
            local_cmd, remote_cmd = command_map[command_type](instance_id, kwargs.get('snapshot_name'))
        else:
            local_cmd, remote_cmd = command_map[command_type](instance_id)
        result = run_proxmox_command(local_cmd, remote_cmd, config['use_local_only'], host_details)

        if result.returncode == 0:
            if command_type == 'describe':
                click.secho(f"🔧 Instance {instance_id} configuration:\n{result.stdout}", fg='cyan')
            elif command_type == '_snapshots':
                click.secho(f"📜 Snapshots for instance {instance_id}:\n{result.stdout}", fg='cyan')
            else:
                click.secho(f"✅ Instance {instance_id} {command_type}d successfully.", fg='green')
        else:
            click.secho(f"❌ Failed to {command_type} instance {instance_id}: {result.stderr}", fg='red')

def build_resize_command(instance_id, memory=None, cpulimit=None, storage_size=None):
    resize_cmd = ["pct", "set", instance_id]
    if memory:
        resize_cmd.extend(["--memory", str(memory)])
    if cpulimit:
        resize_cmd.extend(["--cpulimit", str(cpulimit)])
    if storage_size:
        resize_cmd.extend(["--rootfs", f"{config['default_storage']}:{storage_size}"])
    return (resize_cmd, resize_cmd)

# Function to mask sensitive information
def mask_sensitive_info(config):
    if isinstance(config, dict):
        return {k: ("***" if "ssh_password" in k.lower() else mask_sensitive_info(v)) for k, v in config.items()}
    elif isinstance(config, ):
        return [mask_sensitive_info(i) for i in config]
    else:
        return config

@lws.group()
@command_alias('conf')
def conf():
    """🛠️ Manage client configuration."""
    pass

@conf.command('show')
def show_conf():
    """📄 Show current configuration."""
    config = load_config()
    masked_config = mask_sensitive_info(config)
    click.secho(yaml.dump(masked_config, default_flow_style=False), fg='cyan')

@conf.command('validate')
def validate_configuration_command():
    """📄 Validate the current configuration."""
    logging.info("Validating configuration")
    try:
        validate_config(config)  # Using the existing validate_config function
        click.secho(f"✅ Configuration is valid.", fg='green')
        logging.info("Configuration validation succeeded")
    except ValueError as e:
        click.secho(f"❌ Configuration validation failed: {str(e)}", fg='red')
        logging.error(f"Configuration validation failed: {str(e)}")


@conf.command('backup')
@click.argument('destination_path')
@click.option('--timestamp', is_flag=True, help="Append timestamp to the backup file name.")
@click.option('--compress', is_flag=True, help="Compress the backup file.")
def backup_config(destination_path, timestamp, compress):
    """💾 Backup the current configuration to a file."""
    if timestamp:
        destination_path = f"{destination_path}_{time.strftime('%Y%m%d%H%M%S')}"

    logging.info(f"Backing up configuration to {destination_path}")

    # Write the configuration to a file
    with open(destination_path, 'w') as backup_file:
        yaml.dump(config, backup_file)
    
    click.secho(f"✅ Configuration backed up to {destination_path}.", fg='green')
    logging.info(f"Configuration backed up to {destination_path}")

    if compress:
        compressed_path = f"{destination_path}.gz"
        with open(destination_path, 'rb') as f_in, gzip.open(compressed_path, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
        os.remove(destination_path)  # Remove the uncompressed file
        click.secho(f"✅ Backup compressed to {compressed_path}.", fg='green')
        logging.info(f"Backup compressed to {compressed_path}")


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
def list_hosts():
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

    # click.secho("Available Proxmox Hosts:", fg='cyan')

    # Collect tasks for parallel execution
    tasks = []
    with ThreadPoolExecutor(max_workers=10) as executor:  # Adjust the number of workers if needed
        for region, details in config['regions'].items():
            for az, az_details in details['availability_zones'].items():
                tasks.append(executor.submit(process_host, region, az, az_details))

        # Process results as they complete
        for future in as_completed(tasks):
            try:
                result = future.result()
                click.secho(result, fg='cyan')
            except Exception as e:
                click.secho(f"Error checking host: {e}", fg='red')
            
@px.command('reboot')
#@command_alias('proxmox-reboot')
@click.option('--region', default='eu-south-1', help="Region in which the Proxmox host is located. Defaults to 'eu-south-1'.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target. Defaults to 'az1'.")
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

    # Construct the ssh command to reboot the Proxmox host
    ssh_cmd = [
        "sshpass", "-p", ssh_password, "ssh",
        f"{user}@{host}", "reboot"
    ]

    try:
        # Execute the SSH command to reboot the Proxmox host
        result = subprocess.run(ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode == 0:
            click.secho(f"✅ Proxmox host {host} rebooted successfully.", fg='green')
        else:
            click.secho(f"❌ Failed to reboot Proxmox host {host}: {result.stderr}", fg='red')

    except Exception as e:
        click.secho(f"❌ An error occurred: {str(e)}", fg='red')



@px.command('upload')
#@command_alias('upload-template')
@click.argument('local_path')
@click.argument('remote_template_name', required=False)
@click.option('--region', default='eu-south-1', help="Region in which the Proxmox host is located. Defaults to 'eu-south-1'.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target. Defaults to 'az1'.")
@click.option('--storage-path', default='/var/lib/vz/template/cache', help="Remote path to upload the template. Defaults to Proxmox template directory.")
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

    # Construct the scp command to copy the file to the remote Proxmox server
    scp_cmd = [
        "sshpass", "-p", ssh_password, "scp",
        local_path,
        f"{user}@{host}:{storage_path}/{remote_template_name}"
    ]

    try:
        # Execute the SCP command to upload the template
        result = subprocess.run(scp_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode == 0:
            click.secho(f"✅ Template '{remote_template_name}' uploaded successfully to {storage_path} on {host}.", fg='green')
        else:
            click.secho(f"❌ Failed to upload template: {result.stderr}", fg='red')

    except Exception as e:
        click.secho(f"❌ An error occurred: {str(e)}", fg='red')


@px.command('status')
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target.")
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
        "Memory Info": ["cat", "/proc/meminfo"],
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

@px.command('list-clusters')
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target.")
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



@px.command('backup-hosts')
@click.argument('backup_dir')
def px_backup_hosts(backup_dir):
    """💾 Backup configurations from all Proxmox hosts."""
    command = ["tar", "-czf", f"{backup_dir}/proxmox-backup.tar.gz", "/etc/pve"]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if result.returncode == 0:
        click.secho(f"✅ Backup completed successfully. Saved to {backup_dir}.", fg='green')
    else:
        click.secho(f"❌ Failed to backup hosts: {result.stderr}", fg='red')

@px.command('update-hosts')
def px_update_hosts():
    """🔄 Update all Proxmox hosts."""
    command = ["apt-get", "update", "&&", "apt-get", "upgrade", "-y"]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if result.returncode == 0:
        click.secho("✅ All hosts updated successfully.", fg='green')
    else:
        click.secho(f"❌ Failed to update hosts: {result.stderr}", fg='red')

@px.command('start-cluster-services')
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target.")
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

@px.command('stop-cluster-services')
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target.")
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

@px.command('restart-cluster-services')
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target.")
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



@px.command('create-backup')
@click.argument('vmid')
@click.option('--storage', required=True, help="The storage target where the backup will be stored.")
@click.option('--mode', default='snapshot', type=click.Choice(['snapshot', 'suspend', 'stop']), help="Backup mode: snapshot, suspend, or stop.")
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target.")
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


# lxc

# Function to get the next available VMID
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
        logging.error("Failed to retrieve existing VMIDs. Defaulting to start_vmid.")
        return start_vmid


# Command to run LXC instances
import time

def is_container_locked(instance_id, host_details):
    """Checks if the container is locked by using the pct config command."""
    check_lock_cmd = ["pct", "config", str(instance_id)]
    result = run_proxmox_command(check_lock_cmd, check_lock_cmd, config['use_local_only'], host_details)
    
    if result.returncode == 0:
        return 'lock' in result.stdout
    else:
        logging.error(f"Failed to check lock status for instance {instance_id}: {result.stderr}")
        return False  # Assume it's not locked if the command fails to avoid indefinite retries

@lxc.command('run-instances')
@click.option('--image-id', required=True, help="ID of the container image template.")
@click.option('--count', default=1, help="Number of instances to run.")
@click.option('--size', default='small', type=click.Choice(list(config['instance_sizes'].keys())), help="Instance size.")
@click.option('--hostname', default=None, help="Hostname for the container.")
@click.option('--net0', default=f"name=eth0,bridge={config.get('default_network', 'vmbr0')}", help="Network settings for the container.")
@click.option('--storage-size', default=None, help="Override storage size for the container (e.g., 16G).")
@click.option('--onboot', default=config.get('default_onboot', True), help="Start the container on boot.")
@click.option('--lock', default=None, help="Set lock for the container. By default, no lock is set.")
@click.option('--init', default=False, is_flag=True, help="Run initialization script after container creation.")
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target.")
@click.option('--max-retries', default=5, help="Maximum number of retries to start the container.")
@click.option('--retry-delay', default=5, help="Delay in seconds between retries.")
def run_instances(image_id, count, size, hostname, net0, storage_size, onboot, lock, init, region, az, max_retries, retry_delay):
    """🛠️ Create and start LXC containers."""
    start_vmid = config.get('start_vmid', 10000)
    instance_config = config['instance_sizes'][size]
    storage = instance_config['storage']

    if storage_size:
        storage = f"{config['default_storage']}:{storage_size}"

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

        create_result = run_proxmox_command(create_cmd, create_cmd, config['use_local_only'], host_details)

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


@lxc.command('stop-instances')
@click.argument('instance_ids', nargs=-1)
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target.")
def stop_instances(instance_ids, region, az):
    """🛑 Stop running LXC containers."""
    process_instance_command(instance_ids, 'stop', region, az)

@lxc.command('terminate-instances')
@click.argument('instance_ids', nargs=-1)
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target.")
def terminate_instances(instance_ids, region, az):
    """💥 Terminate (destroy) LXC containers."""
    process_instance_command(instance_ids, 'terminate', region, az)

@lxc.command('describe-instances')
@click.argument('instance_ids', nargs=-1, required=False)
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target.")
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

@lxc.command('scale-instances')
@click.argument('instance_ids', nargs=-1)
@click.option('--memory', default=None, help="New memory size in MB.")
@click.option('--cpulimit', default=None, help="New CPU limit.")
@click.option('--cpucores', default=None, help="New number of CPU cores.")
@click.option('--storage-size', default=None, help="New root storage size (e.g., 16G).")
@click.option('--net-limit', default=None, help="Network bandwidth limit (e.g., 10mbit).")
@click.option('--disk-read-limit', default=None, help="Disk read limit (e.g., 50mb).")
@click.option('--disk-write-limit', default=None, help="Disk write limit (e.g., 30mb).")
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target.")
def scale_instances(instance_ids, memory, cpulimit, cpucores, storage_size, net_limit, disk_read_limit, disk_write_limit, region, az):
    """📏 Scale resources LXC containers."""
    
    # Retrieve the host details from the configuration
    host_details = config['regions'][region]['availability_zones'][az]
    host = host_details['host']
    user = host_details['user']
    ssh_password = host_details['ssh_password']
    
    # Loop through each instance ID and apply the scaling configuration
    for instance_id in instance_ids:
        # Build the command to set the new resource parameters
        scale_cmd = ["pct", "set", instance_id]
        
        if memory:
            scale_cmd.extend(["--memory", str(memory)])
        
        if cpulimit:
            scale_cmd.extend(["--cpulimit", str(cpulimit)])
        
        if cpucores:
            scale_cmd.extend(["--cores", str(cpucores)])
        
        if storage_size:
            scale_cmd.extend(["--rootfs", f"{config['default_storage']}:{storage_size}"])
        
        if net_limit:
            scale_cmd.extend(["--net0", f"rate={net_limit}"])

        if disk_read_limit:
            scale_cmd.extend(["--mp0", f"iops_rd={disk_read_limit}"])

        if disk_write_limit:
            scale_cmd.extend(["--mp0", f"iops_wr={disk_write_limit}"])
        
        # Execute the scale command on the Proxmox host using SSH
        result = run_proxmox_command(scale_cmd, scale_cmd, config['use_local_only'], host_details)
        
        # Output the result of the command
        if result.returncode == 0:
            click.secho(f"✅ Instance '{instance_id}' successfully scaled.", fg='green')
        else:
            click.secho(f"❌ Failed to scale instance '{instance_id}': {result.stderr.strip()}", fg='red')

@lxc.command('create-snapshot')
@click.argument('instance_id')
@click.argument('snapshot_name')
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target.")
def create_snapshot(instance_id, snapshot_name, region, az):
    """📸 Create a snapshot of an LXC container."""
    process_instance_command([instance_id], 'snapshot_create', region, az, snapshot_name=snapshot_name)

@lxc.command('delete-snapshot')
@click.argument('instance_id')
@click.argument('snapshot_name')
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target.")
def delete_snapshot(instance_id, snapshot_name, region, az):
    """🗑️ Delete a snapshot of an LXC container."""
    process_instance_command([instance_id], 'snapshot_delete', region, az, snapshot_name=snapshot_name)

@lxc.command('list-snapshots')
@click.argument('instance_id')
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target.")
def list_snapshots(instance_id, region, az):
    """🗃️ List all snapshots of an LXC container."""
    process_instance_command([instance_id], 'list_snapshots', region, az)

@lxc.command('start-instances')
@click.argument('instance_ids', nargs=-1)
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target.")
def start_instances(instance_ids, region, az):
    """🚀 Start stopped LXC containers."""
    process_instance_command(instance_ids, 'start', region, az)

@lxc.command('reboot-instances')
@click.argument('instance_ids', nargs=-1)
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target.")
def reboot_instances(instance_ids, region, az):
    """🔄 Reboot running LXC containers."""
    process_instance_command(instance_ids, 'reboot', region, az)

@lxc.command('create-image')
@click.argument('instance_id')
@click.argument('template_name')
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target.")
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
    else:
        click.secho(f"❌ Failed to stop instance {instance_id}: {stop_result.stderr}", fg='red')

@lxc.command('delete-image')
@click.argument('template_name')
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target.")
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


@lxc.command('attach-volume')
@click.argument('instance_id')
@click.argument('volume_name')
@click.argument('volume_size')
@click.option('--mount-point', default=None, help="The mount point for the volume inside the container (e.g., /mnt/data).")
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target.")
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

@lxc.command('detach-volume')
@click.argument('instance_id')
@click.argument('volume_name')
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target.")
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

@lxc.command('status')
@click.argument('instance_ids', nargs=-1)
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target.")
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

import subprocess

@lxc.command('service')
@click.argument('action', type=click.Choice(['status', 'start', 'stop', 'restart', 'reload', 'enable']))
@click.argument('service_name')
@click.argument('instance_ids', nargs=-1)
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target.")
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
@click.argument('instance_id')
@click.option('--target-host', required=True, help="Target Proxmox host where the LXC container will be migrated.")
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) where the LXC container currently resides.")
def lxc_migrate(instance_id, target_host, region, az):
    """🔄 Migrate LXC container between hosts."""
    
    # Load configuration
    config = load_config()
    host_details = config['regions'][region]['availability_zones'][az]
    source_host = host_details['host']
    user = host_details['user']
    ssh_password = host_details['ssh_password']

    # Command to migrate the LXC container
    migrate_cmd = ["pct", "migrate", instance_id, target_host]

    # Execute the migration command on the source host
    result = run_ssh_command(source_host, user, ssh_password, migrate_cmd)

    # Output the result of the command
    if result.returncode == 0:
        click.secho(f"✅ Instance {instance_id} successfully migrated to {target_host}.", fg='green')
    else:
        click.secho(f"❌ Failed to migrate instance {instance_id} to {target_host}: {result.stderr.strip()}", fg='red')


def is_clustered():
    """
    Determine if the Proxmox setup is clustered by checking for cluster configuration files
    and the status of corosync and pve-cluster services.
    """
    # Check if corosync.conf exists
    corosync_conf_path = '/etc/pve/corosync.conf'
    if not os.path.exists(corosync_conf_path):
        return False
    
    # Check if corosync service is active
    if not is_service_active('corosync'):
        return False
    
    # Check if pve-cluster service is active
    if not is_service_active('pve-cluster'):
        return False

    return True


@lxc.command('security-group-add')
@click.argument('group_name')
@click.option('--description', default='', help="Description of the security group.")
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target.")
def create_security_group_cluster(group_name, description, region, az):
    """🔐 Create security group on Proxmox host."""

    # Prepare the line to add to the cluster.fw file
    security_group_line = f"[group {group_name}]"
    #### security_group_line = f"[group {group_name}] # {description}"

    # Retrieve the host details from the configuration
    host_details = config['regions'][region]['availability_zones'][az]
    host = host_details['host']
    user = host_details['user']
    ssh_password = host_details['ssh_password']

    # Command to append the security group to the cluster.fw file
    append_cmd = f"echo '{security_group_line}' | tee -a /etc/pve/firewall/cluster.fw"

    # Execute the command on the Proxmox host using SSH
    result = run_ssh_command(host, user, ssh_password, [append_cmd])

    # Output the result of the command
    if result.returncode == 0:
        click.secho(f"✅ Security group '{group_name}' successfully added to cluster.fw on host {host}.", fg='green')
    else:
        click.secho(f"❌ Failed to add security group on host {host}: {result.stderr.strip()}", fg='red')

@lxc.command('security-group-rm')
@click.argument('group_name')
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target.")
def remove_security_group_cluster(group_name, region, az):
    """🗑️ Delete a security group on Proxmox host."""

    # Retrieve the host details from the configuration
    host_details = config['regions'][region]['availability_zones'][az]
    host = host_details['host']
    user = host_details['user']
    ssh_password = host_details['ssh_password']

    # Command to delete the security group section from the cluster.fw file
    remove_cmd = f"sed -i '/\\[group {group_name}\\]/,/^$/d' /etc/pve/firewall/cluster.fw"

    # Execute the command on the Proxmox host using SSH
    result = run_ssh_command(host, user, ssh_password, [remove_cmd])

    # Output the result of the command
    if result.returncode == 0:
        # Validate that the group has been removed
        validate_cmd = f"grep -q '\\[group {group_name}\\]' /etc/pve/firewall/cluster.fw"
        validation_result = run_ssh_command(host, user, ssh_password, [validate_cmd])

        if validation_result.returncode != 0:
            click.secho(f"✅ Security group '{group_name}' successfully removed from cluster.fw on host {host}.", fg='green')
        else:
            click.secho(f"❌ Security group '{group_name}' was not fully removed from cluster.fw on host {host}.", fg='red')
    else:
        click.secho(f"❌ Failed to remove security group on host {host}: {result.stderr.strip()}", fg='red')


@lxc.command('security-group-rule-add')
@click.argument('group_name')
@click.option('--direction', type=click.Choice(['IN', 'OUT']), required=True, help="Direction of the rule (IN or OUT).")
@click.option('--action', type=click.Choice(['ACCEPT', 'DROP', 'REJECT']), default='ACCEPT', help="Action to take on the traffic (ACCEPT, DROP, REJECT).")
@click.option('--protocol', default='tcp', help="Protocol (e.g., tcp, udp, icmp).")
@click.option('--source-ip', default=None, help="Source IP or CIDR for ingress rules.")
@click.option('--source-port', default=None, help="Source port number or range (e.g., 22, 80:443).")
@click.option('--destination-ip', default=None, help="Destination IP or CIDR for egress rules.")
@click.option('--destination-port', default=None, help="Destination port number or range (e.g., 22, 80:443).")
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target.")
def add_rule_to_group(group_name, direction, action, protocol, source_ip, source_port, destination_ip, destination_port, region, az):
    """➕ Add a rule to a existing security group."""

    # Construct the rule based on provided options
    rule = f"{direction} {action} -p {protocol}"

    if source_ip:
        rule += f" --source {source_ip}"
    if source_port:
        rule += f" --sport {source_port}"
    if destination_ip:
        rule += f" --dest {destination_ip}"
    if destination_port:
        rule += f" --dport {destination_port}"

    # Retrieve the host details from the configuration
    host_details = config['regions'][region]['availability_zones'][az]
    host = host_details['host']
    user = host_details['user']
    ssh_password = host_details['ssh_password']

    # Command to add the rule to the specific security group in the cluster.fw file
    append_cmd = f"sed -i '/\\[group {group_name}\\]/a {rule}' /etc/pve/firewall/cluster.fw"

    # Execute the command on the Proxmox host using SSH
    result = run_ssh_command(host, user, ssh_password, [append_cmd])

    # Output the result of the command
    if result.returncode == 0:
        click.secho(f"✅ Rule '{rule}' successfully added to group '{group_name}' in cluster.fw on host {host}.", fg='green')
    else:
        click.secho(f"❌ Failed to add rule to group '{group_name}' on host {host}: {result.stderr.strip()}", fg='red')

@lxc.command('security-group-rule-rm')
@click.argument('group_name')
@click.option('--direction', type=click.Choice(['IN', 'OUT']), required=True, help="Direction of the rule (IN or OUT).")
@click.option('--action', type=click.Choice(['ACCEPT', 'DROP', 'REJECT']), default='ACCEPT', help="Action to take on the traffic (ACCEPT, DROP, REJECT).")
@click.option('--protocol', default='tcp', help="Protocol (e.g., tcp, udp, icmp).")
@click.option('--source-ip', default=None, help="Source IP or CIDR for ingress rules.")
@click.option('--source-port', default=None, help="Source port number or range (e.g., 22, 80:443).")
@click.option('--destination-ip', default=None, help="Destination IP or CIDR for egress rules.")
@click.option('--destination-port', default=None, help="Destination port number or range (e.g., 22, 80:443).")
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target.")
def remove_rule_from_group(group_name, direction, action, protocol, source_ip, source_port, destination_ip, destination_port, region, az):
    """➖ Remove a rule from an existing security group."""

    # Construct the rule based on provided options
    rule = f"{direction} {action} -p {protocol}"

    if source_ip:
        rule += f" --source {source_ip}"
    if source_port:
        rule += f" --sport {source_port}"
    if destination_ip:
        rule += f" --dest {destination_ip}"
    if destination_port:
        rule += f" --dport {destination_port}"

    # Retrieve the host details from the configuration
    host_details = config['regions'][region]['availability_zones'][az]
    host = host_details['host']
    user = host_details['user']
    ssh_password = host_details['ssh_password']

    # Command to remove the rule from the specific security group in the cluster.fw file
    remove_cmd = f"sed -i '/\\[group {group_name}\\]/,/^$/ {{ /{rule}/d }}' /etc/pve/firewall/cluster.fw"

    # Execute the command on the Proxmox host using SSH
    result = run_ssh_command(host, user, ssh_password, [remove_cmd])

    # Output the result of the command
    if result.returncode == 0:
        click.secho(f"✅ Rule '{rule}' successfully removed from group '{group_name}' in cluster.fw on host {host}.", fg='green')
    else:
        click.secho(f"❌ Failed to remove rule from group '{group_name}' on host {host}: {result.stderr.strip()}", fg='red')

@lxc.command('security-group-attach')
@click.argument('group_name')
@click.argument('vmid')
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target.")
def attach_security_group_to_lxc(group_name, vmid, region, az):
    """🔗 Attach security group to an LXC container."""

    # Prepare the line to add to the VMID.fw file under the [RULES] section
    security_group_line = f"|GROUP {group_name}"

    # Retrieve the host details from the configuration
    host_details = config['regions'][region]['availability_zones'][az]
    host = host_details['host']
    user = host_details['user']
    ssh_password = host_details['ssh_password']

    # Check if [RULES] section exists; if not, add it
    check_rules_section_cmd = f"grep -q '^\\[RULES\\]' /etc/pve/firewall/{vmid}.fw || echo '[RULES]' >> /etc/pve/firewall/{vmid}.fw"

    # Execute the command to ensure [RULES] section exists
    ensure_rules_section = run_ssh_command(host, user, ssh_password, [check_rules_section_cmd])

    if ensure_rules_section.returncode != 0:
        click.secho(f"❌ Failed to ensure [RULES] section in LXC '{vmid}' on host {host}: {ensure_rules_section.stderr.strip()}", fg='red')
        return

    # Command to append the security group to the LXC's firewall configuration file
    append_cmd = f"sed -i '/^\\[RULES\\]/a {security_group_line}' /etc/pve/firewall/{vmid}.fw"

    # Execute the command on the Proxmox host using SSH
    result = run_ssh_command(host, user, ssh_password, [append_cmd])

    # Output the result of the command
    if result.returncode == 0:
        click.secho(f"✅ Security group '{group_name}' successfully attached to LXC '{vmid}' on host {host}.", fg='green')
    else:
        click.secho(f"❌ Failed to attach security group to LXC '{vmid}' on host {host}: {result.stderr.strip()}", fg='red')

@lxc.command('security-group-detach')
@click.argument('group_name')
@click.argument('vmid')
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target.")
def detach_security_group_from_lxc(group_name, vmid, region, az):
    """🔓 Detach security group from an LXC container."""

    # Prepare the line to remove from the VMID.fw file under the [RULES] section
    security_group_line = f"|GROUP {group_name}"

    # Retrieve the host details from the configuration
    host_details = config['regions'][region]['availability_zones'][az]
    host = host_details['host']
    user = host_details['user']
    ssh_password = host_details['ssh_password']

    # Command to remove the security group from the LXC's firewall configuration file
    remove_cmd = f"sed -i '/{security_group_line}/d' /etc/pve/firewall/{vmid}.fw"

    # Execute the command on the Proxmox host using SSH
    result = run_ssh_command(host, user, ssh_password, [remove_cmd])

    # Validation command to check if the security group line was successfully removed
    validate_cmd = f"grep -q '{security_group_line}' /etc/pve/firewall/{vmid}.fw"

    # Execute the validation command
    validation_result = run_ssh_command(host, user, ssh_password, [validate_cmd])

    # Output the result of the command
    if result.returncode == 0 and validation_result.returncode != 0:
        click.secho(f"✅ Security group '{group_name}' successfully detached from LXC '{vmid}' on host {host}.", fg='green')
    else:
        click.secho(f"❌ Failed to detach security group '{group_name}' from LXC '{vmid}' on host {host}: {result.stderr.strip()}", fg='red')


@lxc.command('bulk-start')
@click.argument('vmids', nargs=-1)
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target.")
def bulk_start_vms(vmids, region, az):
    """🚀 Start a list of LXC containers."""
    if not vmids:
        click.secho("❌ No VM IDs provided.", fg='red')
        return

    # Retrieve the host details from the configuration
    host_details = config['regions'][region]['availability_zones'][az]

    for vmid in vmids:
        result = run_proxmox_command(["pct", "start", vmid], ["pct", "start", vmid], config['use_local_only'], host_details)
        
        if result.returncode == 0:
            click.secho(f"✅ VMID {vmid} started.", fg='green')
        else:
            click.secho(f"❌ Failed to start VMID {vmid}: {result.stderr}", fg='red')

@lxc.command('bulk-stop')
@click.argument('vmids', nargs=-1)
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target.")
def bulk_stop_vms(vmids, region, az):
    """🛑 Stop a list of LXC containers."""
    if not vmids:
        click.secho("❌ No VM IDs provided.", fg='red')
        return

    # Retrieve the host details from the configuration
    host_details = config['regions'][region]['availability_zones'][az]

    for vmid in vmids:
        result = run_proxmox_command(["pct", "stop", vmid], ["pct", "stop", vmid], config['use_local_only'], host_details)

        if result.returncode == 0:
            click.secho(f"✅ VMID {vmid} stopped.", fg='green')
        else:
            click.secho(f"❌ Failed to stop VMID {vmid}: {result.stderr}", fg='red')

@lxc.command('list-storage')
@click.argument('instance_id')
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target.")
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
    else:
        click.secho(f"❌ Failed to retrieve storage details for instance {instance_id}: {result.stderr.strip()}", fg='red')



import click
import subprocess
import logging

def get_host_details(region, az):
    """Retrieves the host details from the configuration for a given region and availability zone."""
    config = load_config()
    try:
        return config['regions'][region]['availability_zones'][az]
    except KeyError as e:
        logging.error(f"Invalid region or availability zone: {e}")
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
        logging.error(f"Failed to retrieve host resources: {cpu_result.stderr} {mem_result.stderr}")
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
        logging.error(f"Failed to retrieve LXC resources for {instance_id}: {result.stderr}")
        return None, None, None


@lxc.command('scale-suggest')
@click.argument('instance_id')
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target.")
def suggest_resources(instance_id, region, az):
    """⚖️ Scaling adjustments for an LXC container."""
    config = load_config()
    host_details = get_host_details(region, az)

    total_cores, total_memory, free_memory = get_host_free_resources(host_details)
    if total_cores is None or total_memory is None:
        click.secho("❌ Could not retrieve host resources.", fg='red')
        return

    click.secho(f"ℹ️ Proxmox Host: {total_cores} cores, {free_memory} MB free memory", fg='cyan')

    cpulimit, cpuunits, memory = get_lxc_resources(instance_id, host_details)

    if cpulimit is None or memory is None:
        click.secho(f"❌ Could not retrieve resources for container {instance_id}.", fg='red')
        return

    click.secho(f"ℹ️ Instance {instance_id}: {cpulimit} cores, {memory} MB total memory", fg='cyan')

    # Fetch minimum resources from the config
    min_cores = config.get('minimum_resources', {}).get('cores', 1)
    min_memory_mb = config.get('minimum_resources', {}).get('memory_mb', 512)

    suggestions = []

    # Suggest CPU core adjustments
    if cpulimit < total_cores // 2:
        suggested_cores = min(total_cores, cpulimit + 1)
        if suggested_cores > cpulimit:
            suggestions.append(f"🔧 Consider increasing CPU cores to {suggested_cores} (current: {cpulimit}).")
    elif cpulimit > total_cores:
        suggested_cores = max(min_cores, total_cores)
        if suggested_cores < cpulimit:
            suggestions.append(f"🔧 Consider decreasing CPU cores to {suggested_cores} (current: {cpulimit}).")

    # Suggest memory adjustments
    if memory < free_memory // 4:
        suggested_memory = min(free_memory, memory + 256)  # Increase by 256 MB or to the available free memory
        if suggested_memory > memory:
            suggestions.append(f"🔧 Consider increasing memory to {suggested_memory} MB (current: {memory} MB).")
    elif memory > free_memory // 2:
        suggested_memory = max(min_memory_mb, memory - 256)  # Decrease by 256 MB but not below minimum memory
        if suggested_memory < memory:
            suggestions.append(f"🔧 Consider decreasing memory to {suggested_memory} MB (current: {memory} MB).")

    # Output the suggestions
    if suggestions:
        click.secho("\n".join(suggestions), fg='green')
    else:
        click.secho("🔧 No changes recommended.", fg='green')



# Docker Group
@lws.group()
@command_alias('app')
def app():
    """🐳 Manage Docker on LXC containers."""
    pass

@app.command('setup')
@click.argument('instance_ids', nargs=-1)  # Accept multiple instance IDs
@click.argument('package_name', default='docker')
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target.")
def install_docker(instance_ids, package_name, region, az):
    """📦 Install Docker and Compose on an LXC container."""
    host_details = config['regions'][region]['availability_zones'][az]

    for instance_id in instance_ids:
        click.secho(f"🔧 Processing LXC container {instance_id}...", fg='yellow')

        # Check if the container is running
        status_result = run_proxmox_command(
            ["pct", "status", instance_id],
            ["pct", "status", instance_id],
            config['use_local_only'], host_details
        )

        if "status: running" not in status_result.stdout:
            click.secho(f"❌ LXC container {instance_id} is not running.", fg='red')
            continue

        # Check if Docker is already installed
        docker_check_cmd = ["pct", "exec", instance_id, "--", "which", "docker"]
        docker_check_result = run_proxmox_command(docker_check_cmd, docker_check_cmd, config['use_local_only'], host_details)

        if docker_check_result.returncode == 0:
            click.secho(f"✅ Docker is already installed on instance {instance_id}.", fg='green')
        else:
            # Install Docker in a non-interactive way
            docker_install_cmd = [
                "pct", "exec", instance_id, "--", "bash", "-c",
                "'DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y docker.io'"
            ]
            docker_install_result = run_proxmox_command(
                docker_install_cmd, docker_install_cmd, config['use_local_only'], host_details
            )

            if docker_install_result.returncode == 0:
                click.secho(f"✅ Docker installed successfully on instance {instance_id}.", fg='green')
            else:
                click.secho(f"❌ Failed to install Docker on instance {instance_id}: {docker_install_result.stderr}", fg='red')
                continue

        # Check if Docker Compose plugin is already installed
        compose_check_cmd = ["pct", "exec", instance_id, "--", "which", "docker-compose"]
        compose_check_result = run_proxmox_command(compose_check_cmd, compose_check_cmd, config['use_local_only'], host_details)

        if compose_check_result.returncode == 0:
            click.secho(f"✅ Docker Compose plugin is already installed on instance {instance_id}.", fg='green')
        else:
            # Install Docker Compose plugin in a non-interactive way
            compose_plugin_install_cmd = [
                "pct", "exec", instance_id, "--", "bash", "-c",
                "'DEBIAN_FRONTEND=noninteractive apt-get install -y docker-compose-plugin'"
            ]
            compose_install_result = run_proxmox_command(
                compose_plugin_install_cmd, compose_plugin_install_cmd, config['use_local_only'], host_details
            )

            if compose_install_result.returncode == 0:
                click.secho(f"✅ Docker Compose plugin installed successfully on instance {instance_id}.", fg='green')
            else:
                click.secho(f"❌ Failed to install Docker Compose plugin on instance {instance_id}: {compose_install_result.stderr}", fg='red')

        click.secho(f"🔧 Finished processing LXC container {instance_id}.\n", fg='yellow')

    click.secho(f"🎉 All specified LXC containers have been processed: {', '.join(instance_ids)}", fg='cyan')


@app.command('run')
@click.argument('instance_id')
@click.argument('docker_command', nargs=-1, type=click.UNPROCESSED)
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target.")
def run_docker(instance_id, docker_command, region, az):
    """🚀 Execute docker run inside an LXC container."""
    logging.debug(f"Starting dock run with instance_id: {instance_id} and docker_command: {docker_command}")
    
    if not docker_command:
        click.secho("❌ No Docker command provided.", fg='red')
        return

    # Fetch host details from the configuration
    host_details = config['regions'][region]['availability_zones'][az]
    logging.debug(f"Host details: {host_details}")
    
    # Check if the container is running
    status_cmd = ["pct", "status", instance_id]
    status_result = run_proxmox_command(status_cmd, status_cmd, config['use_local_only'], host_details)
    logging.debug(f"Executed status command: {status_cmd}")
    logging.debug(f"Container status result: {status_result.stdout.strip()}")
    logging.debug(f"Container status stderr: {status_result.stderr.strip()}")

    if "status: running" not in status_result.stdout:
        click.secho(f"❌ LXC container {instance_id} is not running.", fg='red')
        return
    
    # Ensure Docker is installed
    docker_check_cmd = ["pct", "exec", instance_id, "--", "docker", "--version"]
    docker_check_result = run_proxmox_command(docker_check_cmd, docker_check_cmd, config['use_local_only'], host_details)
    logging.debug(f"Executed Docker check command: {docker_check_cmd}")
    logging.debug(f"Docker version check result: {docker_check_result.stdout.strip()}")
    logging.debug(f"Docker version check stderr: {docker_check_result.stderr.strip()}")

    if docker_check_result.returncode != 0:
        click.secho(f"🔧 Docker not found on instance {instance_id}. Installing Docker...", fg='yellow')
        install_docker_cmd = ["pct", "exec", instance_id, "--", "apt-get", "update"]
        update_result = run_proxmox_command(install_docker_cmd, install_docker_cmd, config['use_local_only'], host_details)
        logging.debug(f"Executed apt-get update command: {install_docker_cmd}")
        logging.debug(f"apt-get update result stdout: {update_result.stdout.strip()}")
        logging.debug(f"apt-get update result stderr: {update_result.stderr.strip()}")

        install_docker_cmd = ["pct", "exec", instance_id, "--", "apt-get", "install", "-y", "docker.io"]
        install_result = run_proxmox_command(install_docker_cmd, install_docker_cmd, config['use_local_only'], host_details)
        
        logging.debug(f"Executed Docker install command: {install_docker_cmd}")
        logging.debug(f"Docker install result stdout: {install_result.stdout.strip()}")
        logging.debug(f"Docker install result stderr: {install_result.stderr.strip()}")

        if install_result.returncode == 0:
            click.secho(f"✅ Docker installed successfully on instance {instance_id}.", fg='green')
        else:
            click.secho(f"❌ Docker installation failed on instance {instance_id}: {install_result.stderr.strip()}", fg='red')
            return

    # Prepend "docker run" to the Docker command, remove "-d" if it conflicts with port mapping
    docker_run_cmd = ["pct", "exec", instance_id, "--", "docker", "run"] + list(docker_command)
    logging.debug(f"Final Docker command to execute: {docker_run_cmd}")

    run_result = run_proxmox_command(
        docker_run_cmd,
        docker_run_cmd,
        config['use_local_only'], host_details
    )
    
    logging.debug(f"Docker command execution stdout: {run_result.stdout.strip()}")
    logging.debug(f"Docker command execution stderr: {run_result.stderr.strip()}")

    if run_result.returncode == 0:
        click.secho(f"✅ Docker command executed successfully on instance {instance_id}:\n{run_result.stdout.strip()}", fg='green')
    else:
        click.secho(f"❌ Failed to execute Docker command on instance {instance_id}: {run_result.stderr.strip()}", fg='red')


### compose
@app.command('compose')
@click.argument('action', type=click.Choice(['install', 'uninstall', 'start', 'stop', 'restart', 'status']))
@click.argument('instance_id')  # Instance ID is now a positional argument
@click.option('--compose_file', required=True, help="Local path or remote URL to the Docker Compose YAML file.")
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target.")
@click.option('--auto_start', is_flag=True, help="Enable auto-start for the application.")
def compose(action, instance_id, compose_file, region, az, auto_start):
    """🚀 Manage apps with Compose on LXC containers."""
    host_details = config['regions'][region]['availability_zones'][az]

    # Ensure the Docker Compose file is available locally
    if not os.path.exists(compose_file):
        if compose_file.startswith("http://") or compose_file.startswith("https://"):
            click.secho(f"🔧 Downloading Docker Compose file from {compose_file}...", fg='yellow')
            local_compose_file = f"/tmp/docker-compose.yml"
            try:
                response = requests.get(compose_file)
                response.raise_for_status()
                with open(local_compose_file, 'wb') as file:
                    file.write(response.content)
                compose_file = local_compose_file
                click.secho(f"✅ Docker Compose file downloaded to {compose_file}.", fg='green')
            except requests.exceptions.RequestException as e:
                click.secho(f"❌ Failed to download Docker Compose file: {e}", fg='red')
                return
        else:
            click.secho(f"❌ Docker Compose file not found at {compose_file}.", fg='red')
            return

    # Extract APP_NAME from the Docker Compose file
    app_name = extract_app_name_from_compose(compose_file)
    if not app_name:
        click.secho(f"❌ Failed to extract application name from Docker Compose file.", fg='red')
        return

    # Upload the Compose file to the Proxmox host
    remote_host_path = f"/tmp/{app_name}-docker-compose.yml"
    scp_cmd = ["scp", compose_file, f"{host_details['user']}@{host_details['host']}:{remote_host_path}"]
    result = subprocess.run(scp_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        click.secho(f"❌ Failed to upload Docker Compose file to Proxmox host: {result.stderr.strip()}", fg='red')
        return
    
    click.secho(f"✅ Docker Compose file uploaded to Proxmox host at {remote_host_path}.", fg='green')

    # Transfer the file to the LXC container using pct push
    pct_push_cmd = ["sshpass", "-p", host_details['ssh_password'], "ssh", f"{host_details['user']}@{host_details['host']}", "pct", "push", instance_id, remote_host_path, remote_host_path]
    result = subprocess.run(pct_push_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        click.secho(f"❌ Failed to transfer Docker Compose file to LXC container: {result.stderr.strip()}", fg='red')
        return
    
    click.secho(f"✅ Docker Compose file transferred to {remote_host_path} on instance {instance_id}.", fg='green')

    # Verify the file inside the container
    verify_cmd = ["pct", "exec", instance_id, "--", "cat", remote_host_path]
    result = run_proxmox_command(verify_cmd, verify_cmd, config['use_local_only'], host_details)
    if result.returncode != 0:
        click.secho(f"❌ Failed to verify Docker Compose file inside LXC container: {result.stderr.strip()}", fg='red')
        return
    click.secho(f"📄 Docker Compose file content:\n{result.stdout}", fg='cyan')

    # Ensure Docker Compose is installed in the container
    if not check_and_install_docker_compose(instance_id, host_details):
        return
    
    # Define the base Docker Compose command
    compose_cmd = ["pct", "exec", instance_id, "--", "docker-compose", "-f", remote_host_path]
    
    # Define actions
    if action == 'install':
        compose_cmd.append("up -d")
    elif action == 'uninstall':
        compose_cmd.append("down")
    elif action in ['start', 'stop', 'restart']:
        compose_cmd.append(action)
    elif action == 'status':
        compose_cmd.append("ps")
    
    # Execute the command
    result = run_proxmox_command(compose_cmd, compose_cmd, config['use_local_only'], host_details)
    
    # Handle the output and check for errors during Docker Compose execution
    if result.returncode == 0:
        click.secho(f"✅ Instance {instance_id} - Application '{app_name}' {action} successfully executed.", fg='green')
    else:
        click.secho(f"❌ Instance {instance_id} - Failed to {action} application '{app_name}': {result.stderr.strip()}", fg='red')
        return

    # Verify that the Docker containers are running
    if action == 'install':
        verify_docker_service_running(instance_id, host_details)

    # Handle auto-start if required
    if action == 'install' and auto_start:
        setup_auto_start(instance_id, app_name, remote_host_path, host_details)
        click.secho(f"🔧 Auto-start enabled for '{app_name}' on instance {instance_id}.", fg='green')

def extract_app_name_from_compose(compose_file):
    """Extract the application name from the Docker Compose file."""
    try:
        with open(compose_file, 'r') as file:
            compose_content = yaml.safe_load(file)
            if 'services' in compose_content:
                service_names = list(compose_content['services'].keys())
                if service_names:
                    # Use the first service name as the app_name
                    return service_names[0]
    except Exception as e:
        logging.error(f"Failed to parse Docker Compose file: {str(e)}")
    return None

def verify_docker_service_running(instance_id, host_details):
    """Check that the Docker service is running correctly after the Docker Compose command."""
    # First, check if any containers are running
    verify_cmd = ["pct", "exec", instance_id, "--", "docker", "ps"]
    result = run_proxmox_command(verify_cmd, verify_cmd, config['use_local_only'], host_details)
    if result.returncode == 0:
        if result.stdout.strip():
            click.secho(f"✅ Docker containers running on instance {instance_id}:\n{result.stdout}", fg='green')
        else:
            click.secho(f"❌ No Docker containers are running on instance {instance_id}.", fg='red')
            # Since no containers are running, let's dig deeper
            diagnose_docker_compose_issue(instance_id, host_details)
    else:
        click.secho(f"❌ Failed to verify running Docker containers on instance {instance_id}: {result.stderr.strip()}", fg='red')


def diagnose_docker_compose_issue(instance_id, host_details):
    """Diagnose issues with Docker Compose by checking the logs and service status."""
    # Check Docker Compose service status
    compose_ps_cmd = ["pct", "exec", instance_id, "--", "docker-compose", "ps"]
    result = run_proxmox_command(compose_ps_cmd, compose_ps_cmd, config['use_local_only'], host_details)
    if result.returncode == 0:
        click.secho(f"📋 Docker Compose service status on instance {instance_id}:\n{result.stdout}", fg='cyan')
    else:
        click.secho(f"❌ Failed to get Docker Compose service status on instance {instance_id}: {result.stderr.strip()}", fg='red')
    
    # Check Docker Compose logs for any errors
    compose_logs_cmd = ["pct", "exec", instance_id, "--", "docker-compose", "logs"]
    result = run_proxmox_command(compose_logs_cmd, compose_logs_cmd, config['use_local_only'], host_details)
    if result.returncode == 0:
        click.secho(f"📄 Docker Compose logs on instance {instance_id}:\n{result.stdout}", fg='yellow')
    else:
        click.secho(f"❌ Failed to get Docker Compose logs on instance {instance_id}: {result.stderr.strip()}", fg='red')

def check_and_install_docker_compose(instance_id, host_details):
    """Check if Docker Compose is installed in the LXC container and install it if not."""
    compose_check_cmd = ["pct", "exec", instance_id, "--", "which", "docker-compose"]
    result = run_proxmox_command(compose_check_cmd, compose_check_cmd, config['use_local_only'], host_details)
    
    if result.returncode != 0:
        click.secho(f"🔧 Docker Compose not found in instance {instance_id}. Installing Docker Compose...", fg='yellow')
        
        install_cmds = [
            ["pct", "exec", instance_id, "--", "curl", "-L", "https://github.com/docker/compose/releases/latest/download/docker-compose-`uname -s`-`uname -m`", "-o", "/usr/local/bin/docker-compose"],
            ["pct", "exec", instance_id, "--", "chmod", "+x", "/usr/local/bin/docker-compose"]
        ]
        
        for cmd in install_cmds:
            install_result = run_proxmox_command(cmd, cmd, config['use_local_only'], host_details)
            if install_result.returncode != 0:
                click.secho(f"❌ Failed to install Docker Compose on instance {instance_id}: {install_result.stderr.strip()}", fg='red')
                return False
        click.secho(f"✅ Docker Compose installed successfully on instance {instance_id}.", fg='green')
    return True

def setup_auto_start(instance_id, app_name, compose_file, host_details):
    """Set up auto-start for the Docker Compose application."""
    service_name = f"{app_name}-{instance_id}.service"
    systemd_service = f"""
[Unit]
Description=Docker Compose Application Service for {app_name} on Instance {instance_id}
After=docker.service
Requires=docker.service

[Service]
Restart=always
WorkingDirectory={os.path.dirname(compose_file)}
ExecStart=/usr/local/bin/docker-compose -f {compose_file} up -d
ExecStop=/usr/local/bin/docker-compose -f {compose_file} down

[Install]
WantedBy=multi-user.target
"""
    service_path = f"/etc/systemd/system/{service_name}"
    
    # Create the systemd service file
    create_cmd = ["pct", "exec", instance_id, "--", "bash", "-c", f"echo '{systemd_service}' > {service_path}"]
    run_proxmox_command(create_cmd, create_cmd, config['use_local_only'], host_details)

    # Enable and start the systemd service
    subprocess.run(["pct", "exec", instance_id, "--", "systemctl", "enable", service_name])
    subprocess.run(["pct", "exec", instance_id, "--", "systemctl", "start", service_name])

@app.command('compose-update')
@click.argument('instance_id')
@click.argument('compose_file', required=True)
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target.")
def compose_update(instance_id, compose_file, region, az):
    """🆕 Update app within an LXC container via Compose."""
    host_details = config['regions'][region]['availability_zones'][az]
    logging.info(f"Starting Docker Compose update for instance {instance_id}")

    # Ensure the Docker Compose file is available locally
    if not os.path.exists(compose_file):
        click.secho(f"❌ Docker Compose file not found at {compose_file}.", fg='red')
        logging.error(f"Docker Compose file not found: {compose_file}")
        return

    # Upload the Compose file to the Proxmox host
    remote_host_path = f"/tmp/{os.path.basename(compose_file)}"
    scp_cmd = ["scp", compose_file, f"{host_details['user']}@{host_details['host']}:{remote_host_path}"]
    result = subprocess.run(scp_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        click.secho(f"❌ Failed to upload Docker Compose file to Proxmox host: {result.stderr.strip()}", fg='red')
        logging.error(f"Failed to upload Docker Compose file to Proxmox host: {result.stderr.strip()}")
        return

    click.secho(f"✅ Docker Compose file uploaded to Proxmox host at {remote_host_path}.", fg='green')
    logging.info(f"Docker Compose file uploaded to Proxmox host: {remote_host_path}")

    # Transfer the file to the LXC container using pct push
    pct_push_cmd = ["sshpass", "-p", host_details['ssh_password'], "ssh", f"{host_details['user']}@{host_details['host']}", "pct", "push", instance_id, remote_host_path, remote_host_path]
    result = subprocess.run(pct_push_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        click.secho(f"❌ Failed to transfer Docker Compose file to LXC container: {result.stderr.strip()}", fg='red')
        logging.error(f"Failed to transfer Docker Compose file to LXC container: {result.stderr.strip()}")
        return
    
    click.secho(f"✅ Docker Compose file transferred to {remote_host_path} on instance {instance_id}.", fg='green')
    logging.info(f"Docker Compose file transferred to LXC container: {remote_host_path}")

    # Define the Docker Compose update commands
    compose_pull_cmd = ["pct", "exec", instance_id, "--", "docker-compose", "-f", remote_host_path, "pull"]
    compose_up_cmd = ["pct", "exec", instance_id, "--", "docker-compose", "-f", remote_host_path, "up", "-d"]

    # Execute docker-compose pull
    logging.info(f"Pulling Docker Compose images for instance {instance_id}")
    pull_result = run_proxmox_command(compose_pull_cmd, compose_pull_cmd, config['use_local_only'], host_details)
    if pull_result.returncode == 0:
        click.secho(f"✅ Docker Compose application images pulled successfully on instance {instance_id}.", fg='green')
        logging.info(f"Docker Compose application images pulled successfully on instance {instance_id}")
    else:
        click.secho(f"❌ Failed to pull Docker Compose images on instance {instance_id}: {pull_result.stderr.strip()}", fg='red')
        logging.error(f"Failed to pull Docker Compose images on instance {instance_id}: {pull_result.stderr.strip()}")
        return

    # Execute docker-compose up -d
    logging.info(f"Starting Docker Compose application on instance {instance_id}")
    up_result = run_proxmox_command(compose_up_cmd, compose_up_cmd, config['use_local_only'], host_details)
    if up_result.returncode == 0:
        click.secho(f"✅ Docker Compose application updated successfully on instance {instance_id}.", fg='green')
        logging.info(f"Docker Compose application updated successfully on instance {instance_id}")
    else:
        click.secho(f"❌ Failed to update Docker Compose application on instance {instance_id}: {up_result.stderr.strip()}", fg='red')
        logging.error(f"Failed to update Docker Compose application on instance {instance_id}: {up_result.stderr.strip()}")


@app.command('logs')
@click.argument('instance_id')
@click.argument('container_name_or_id')
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target.")
@click.option('--tail', default='all', help="Number of lines to show from the end of the logs.")
@click.option('--follow', is_flag=True, help="Stream logs in real-time.")
def logs(instance_id, container_name_or_id, region, az, tail, follow):
    """📄 Fetch Docker logs from an LXC container."""
    host_details = config['regions'][region]['availability_zones'][az]
    logging.info(f"Fetching logs for container {container_name_or_id} on instance {instance_id}")

    # Build the docker logs command
    logs_cmd = ["pct", "exec", instance_id, "--", "docker", "logs"]
    if follow:
        logs_cmd.append("-f")
    if tail != 'all':
        logs_cmd.extend(["--tail", tail])
    logs_cmd.append(container_name_or_id)

    # Execute the command
    result = run_proxmox_command(logs_cmd, logs_cmd, config['use_local_only'], host_details)

    if result.returncode == 0:
        click.secho(f"📄 Logs for container {container_name_or_id} on instance {instance_id}:\n{result.stdout}", fg='cyan')
        logging.info(f"Logs fetched for container {container_name_or_id} on instance {instance_id}")
    else:
        click.secho(f"❌ Failed to fetch logs for container {container_name_or_id} on instance {instance_id}: {result.stderr.strip()}", fg='red')
        logging.error(f"Failed to fetch logs for container {container_name_or_id} on instance {instance_id}: {result.stderr.strip()}")


@app.command('list')
@click.argument('instance_id')
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target.")
def containers(instance_id, region, az):
    """📦 List Docker containers in an LXC container."""
    host_details = config['regions'][region]['availability_zones'][az]
    logging.info(f"Listing running Docker containers on instance {instance_id}")

    # Build the docker ps command
    ps_cmd = ["pct", "exec", instance_id, "--", "docker", "ps", "--format", "'{{.ID}}: {{.Names}} ({{.Image}})'"]

    # Execute the command
    result = run_proxmox_command(ps_cmd, ps_cmd, config['use_local_only'], host_details)

    if result.returncode == 0:
        click.secho(f"📦 Running containers on instance {instance_id}:\n{result.stdout}", fg='cyan')
        logging.info(f"Listed running containers on instance {instance_id}")
    else:
        click.secho(f"❌ Failed to list running containers on instance {instance_id}: {result.stderr.strip()}", fg='red')
        logging.error(f"Failed to list running containers on instance {instance_id}: {result.stderr.strip()}")


@app.command('remove')
@click.argument('instance_ids', nargs=-1)  # Accept multiple instance IDs
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target.")
@click.option('--purge', is_flag=True, help="Remove all Docker images, containers, volumes, and networks.")
def remove(instance_ids, region, az, purge):
    """🗑️ Uninstall Docker and Compose from LXC containers."""
    host_details = config['regions'][region]['availability_zones'][az]

    for instance_id in instance_ids:
        click.secho(f"🔧 Removing Docker and Docker Compose from LXC container {instance_id}...", fg='yellow')
        logging.info(f"Removing Docker and Docker Compose from instance {instance_id}")

        if purge:
            # Purge all Docker resources
            purge_cmd = ["pct", "exec", instance_id, "--", "docker", "system", "prune", "-a", "-f", "--volumes"]
            purge_result = run_proxmox_command(purge_cmd, purge_cmd, config['use_local_only'], host_details)
            if purge_result.returncode != 0:
                click.secho(f"❌ Failed to purge Docker resources on instance {instance_id}: {purge_result.stderr.strip()}", fg='red')
                logging.error(f"Failed to purge Docker resources on instance {instance_id}: {purge_result.stderr.strip()}")
                continue

        # Remove Docker and Docker Compose
        remove_cmd = ["pct", "exec", instance_id, "--", "apt-get", "remove", "-y", "docker.io", "docker-compose-plugin"]
        remove_result = run_proxmox_command(remove_cmd, remove_cmd, config['use_local_only'], host_details)

        if remove_result.returncode == 0:
            click.secho(f"✅ Docker and Docker Compose removed successfully from instance {instance_id}.", fg='green')
            logging.info(f"Docker and Docker Compose removed from instance {instance_id}")
        else:
            click.secho(f"❌ Failed to remove Docker and Docker Compose from instance {instance_id}: {remove_result.stderr.strip()}", fg='red')
            logging.error(f"Failed to remove Docker and Docker Compose from instance {instance_id}: {remove_result.stderr.strip()}")


@lxc.command('clone')
@click.argument('source_instance_id')
@click.argument('target_instance_id')
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target.")
@click.option('--target-host', default=None, help="Target Proxmox host for the clone.")
@click.option('--description', default=None, help="Description for the new container.")
@click.option('--hostname', default=None, help="Hostname for the new container.")
@click.option('--storage', default=None, help="Target storage for full clone.")
@click.option('--full', is_flag=True, help="Create a full copy of all disks.")
@click.option('--pool', default=None, help="Add the new container to the specified pool.")
@click.option('--bwlimit', default=None, help="Override I/O bandwidth limit (in KiB/s).")
@click.option('--start/--no-start', default=True, help="Start the cloned container after creation. Default is true.")
def clone(source_instance_id, target_instance_id, region, az, target_host, description, hostname, storage, full, pool, bwlimit, start):
    """🔄 Clone an LXC container locally or remote."""
    host_details = config['regions'][region]['availability_zones'][az]
    logging.info(f"Cloning LXC container {source_instance_id} to {target_instance_id}")

    # Generate a unique snapshot name
    snapshot_name = f"snapshot-{time.strftime('%Y%m%d%H%M%S')}"

    # Create a snapshot
    snapshot_cmd = ["pct", "snapshot", source_instance_id, snapshot_name]
    snapshot_result = run_proxmox_command(snapshot_cmd, snapshot_cmd, config['use_local_only'], host_details)

    if snapshot_result.returncode != 0:
        click.secho(f"❌ Failed to create snapshot {snapshot_name} on instance {source_instance_id}: {snapshot_result.stderr.strip()}", fg='red')
        logging.error(f"Failed to create snapshot {snapshot_name} on instance {source_instance_id}: {snapshot_result.stderr.strip()}")
        return

    # Construct the clone command
    clone_cmd = ["pct", "clone", source_instance_id, target_instance_id, "--snapname", snapshot_name]

    if description:
        clone_cmd.extend(["--description", description])
    if hostname:
        clone_cmd.extend(["--hostname", hostname])
    if storage:
        clone_cmd.extend(["--storage", storage])
    if full:
        clone_cmd.append("--full")
    if pool:
        clone_cmd.extend(["--pool", pool])
    if bwlimit:
        clone_cmd.extend(["--bwlimit", bwlimit])
    if target_host:
        clone_cmd.extend(["--target", target_host])

    # Execute the clone command
    clone_result = run_proxmox_command(clone_cmd, clone_cmd, config['use_local_only'], host_details)

    if clone_result.returncode == 0:
        click.secho(f"✅ Successfully cloned instance {source_instance_id} to {target_instance_id} from snapshot {snapshot_name}.", fg='green')
        logging.info(f"Successfully cloned instance {source_instance_id} to {target_instance_id} from snapshot {snapshot_name}")

        # Automatically start the cloned container if the option is enabled
        if start:
            logging.info(f"Starting cloned LXC container {target_instance_id}")
            start_cmd = ["pct", "start", target_instance_id]
            start_result = run_proxmox_command(start_cmd, start_cmd, config['use_local_only'], host_details)

            if start_result.returncode == 0:
                click.secho(f"✅ Cloned container {target_instance_id} started successfully.", fg='green')
                logging.info(f"Cloned container {target_instance_id} started successfully")
            else:
                click.secho(f"❌ Failed to start cloned container {target_instance_id}: {start_result.stderr.strip()}", fg='red')
                logging.error(f"Failed to start cloned container {target_instance_id}: {start_result.stderr.strip()}")
    else:
        click.secho(f"❌ Failed to clone instance {source_instance_id} to {target_instance_id}: {clone_result.stderr.strip()}", fg='red')
        logging.error(f"Failed to clone instance {source_instance_id} to {target_instance_id}: {clone_result.stderr.strip()}")


@lxc.command('exec')
@click.argument('instance_ids', nargs=-1, required=True)
@click.argument('command', nargs=1, required=True)
@click.option('--region', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', default='az1', help="Availability zone (Proxmox host) to target.")
def exec_in_container(instance_ids, command, region, az):
    """👨🏻‍💻 Execute a command in one or more LXC containers."""
    if not command:
        click.secho("❌ No command provided to execute.", fg='red')
        logging.error("No command provided to execute.")
        return

    host_details = config['regions'][region]['availability_zones'][az]

    # Convert the single command argument into a list of arguments
    command_list = command.split()

    for instance_id in instance_ids:
        exec_cmd = ["pct", "exec", str(instance_id), "--"] + command_list

        logging.info(f"Executing command in instance {instance_id}: {command}")
        click.secho(f"🔧 Executing command in instance {instance_id}: {command}", fg='cyan')
        
        exec_result = run_proxmox_command(exec_cmd, exec_cmd, config['use_local_only'], host_details)

        if exec_result.returncode == 0:
            logging.info(f"Command executed successfully in instance {instance_id}.")
            click.secho(f"✅ Command executed successfully in instance {instance_id}.", fg='green')
            logging.debug(f"Command output for instance {instance_id}: {exec_result.stdout}")
            click.secho(exec_result.stdout, fg='white')
        else:
            logging.error(f"Failed to execute command in instance {instance_id}: {exec_result.stderr}")
            click.secho(f"❌ Failed to execute command in instance {instance_id}: {exec_result.stderr}", fg='red')


if __name__ == '__main__':
    lws()
