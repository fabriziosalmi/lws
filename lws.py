#!/usr/bin/env python3

# to create lws alias:
# chmod +x lws.py && alias lws='python3 lws.py'
# then u can just run..
# lws

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
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
from tqdm import tqdm

# Global version information
__version__ = '1.1.0'


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
            'handlers': list(handlers.keys()),
        },
    }

    logging.config.dictConfig(logging_config)
    logging.debug("🔎 Logging to console, and additional JSON logging to file {}".format(json_log_file if json_log_file else "not configured"))

# Example usage:
log_file_path = os.path.join(os.getcwd(), 'lws.log')  # Standard log file path
json_log_file_path = os.path.join(os.getcwd(), 'lws.json.log')  # JSON log file path

# Set up logging: standard logging to console and file, JSON logging to a separate file
setup_logging(log_level=logging.ERROR, log_file=log_file_path, json_log_file=json_log_file_path)


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


# Load and validate the configuration
def load_config():
    """
    Load and validate the configuration from config.yaml.
    
    Returns:
    - Validated configuration dictionary
    
    Raises:
    - FileNotFoundError: If config.yaml is not found
    - yaml.YAMLError: If config.yaml has invalid YAML syntax
    - ValueError: If configuration is invalid
    """
    try:
        config_path = os.path.join(os.getcwd(), 'config.yaml')
        if not os.path.exists(config_path):
            logging.error(f"❌ Configuration file not found at {config_path}")
            raise FileNotFoundError(f"Configuration file not found at {config_path}")
            
        with open('config.yaml', 'r') as file:
            config = yaml.safe_load(file)
        validate_config(config)
        return config
    except FileNotFoundError:
        logging.error("❌ Configuration file 'config.yaml' not found.")
        raise
    except yaml.YAMLError as e:
        logging.error(f"❌ Error parsing configuration file: {e}")
        raise
    except Exception as e:
        logging.error(f"❌ Unexpected error loading configuration: {str(e)}")
        raise


def validate_config(config):
    """
    Validate the configuration structure and content.
    
    Parameters:
    - config: Configuration dictionary to validate
    
    Raises:
    - ValueError: If configuration is invalid
    """
    if not isinstance(config, dict):
        error_msg = "Configuration must be a dictionary"
        logging.error(f"❌ {error_msg}")
        raise ValueError(error_msg)
        
    required_keys = ['regions', 'instance_sizes']
    for key in required_keys:
        if key not in config:
            error_msg = f"Missing required configuration key: {key}"
            logging.error(f"❌ {error_msg}")
            raise ValueError(error_msg)

    if not isinstance(config['regions'], dict) or not config['regions']:
        error_msg = "Invalid or empty 'regions' configuration."
        logging.error(f"❌ {error_msg}")
        raise ValueError(error_msg)

    if not isinstance(config['instance_sizes'], dict) or not config['instance_sizes']:
        error_msg = "Invalid or empty 'instance_sizes' configuration."
        logging.error(f"❌ {error_msg}")
        raise ValueError(error_msg)
        
    # Validate each region has az with proper host details
    for region_name, region in config['regions'].items():
        if 'availability_zones' not in region or not isinstance(region['availability_zones'], dict):
            error_msg = f"Region '{region_name}' must have 'availability_zones' dictionary"
            logging.error(f"❌ {error_msg}")
            raise ValueError(error_msg)
            
        for az_name, az in region['availability_zones'].items():
            required_az_keys = ['host', 'user', 'ssh_password']
            for key in required_az_keys:
                if key not in az:
                    error_msg = f"Missing '{key}' for availability zone '{az_name}' in region '{region_name}'"
                    logging.error(f"❌ {error_msg}")
                    raise ValueError(error_msg)

    # Validate instance sizes
    for size_name, size_config in config['instance_sizes'].items():
        required_size_keys = ['memory', 'cpulimit', 'storage']
        for key in required_size_keys:
            if key not in size_config:
                error_msg = f"Missing '{key}' for instance size '{size_name}'"
                logging.error(f"❌ {error_msg}")
                raise ValueError(error_msg)


try:
    config = load_config()
except (FileNotFoundError, yaml.YAMLError, ValueError) as e:
    click.secho(f"Configuration error: {str(e)}", fg='red')
    config = {
        'regions': {},
        'instance_sizes': {},
        'use_local_only': False,
        'default_storage': 'local',
        'default_network': 'vmbr0'
    }


# lws
@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version=__version__)
def lws():
    """🐧 Linux (Containers) Web Services - A CLI tool for managing LXC containers on Proxmox."""
    pass


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
            
        except subprocess.TimeoutExpired:
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
                stderr="Error: SSH command timed out after 60 seconds"
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


# Command alias decorator
def command_alias(*aliases):
    """
    Decorator that creates command aliases for Click commands.
    
    Parameters:
    - aliases: List of command name aliases
    
    Returns:
    - Decorator function
    """
    def decorator(f):
        for alias in aliases:
            lws.command(alias)(f)
        return f
    return decorator


# Generic function to process instance commands
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


def build_resize_command(instance_id, memory=None, cpulimit=None, storage_size=None):
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


# Function to mask sensitive information
def mask_sensitive_info(config):
    """
    Mask sensitive information in the configuration.
    
    Parameters:
    - config: Configuration dictionary
    
    Returns:
    - Configuration with sensitive information masked
    """
    if isinstance(config, dict):
        return {k: ("***" if "password" in k.lower() or "secret" in k.lower() or "key" in k.lower() else mask_sensitive_info(v)) for k, v in config.items()}
    elif isinstance(config, list):
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
    try:
        config = load_config()
        masked_config = mask_sensitive_info(config)
        click.secho(yaml.dump(masked_config, default_flow_style=False), fg='cyan')
    except Exception as e:
        click.secho(f"❌ Error loading configuration: {str(e)}", fg='red')


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


@conf.command('backup')
@click.argument('destination_path')
@click.option('--timestamp', is_flag=True, help="Append timestamp to the backup file name.")
@click.option('--compress', is_flag=True, help="Compress the backup file.")
def backup_config(destination_path, timestamp, compress):
    """💾 Backup the current configuration to a file."""
    if timestamp:
        destination_path = f"{destination_path}_{time.strftime('%Y%m%d%H%M%S')}"

    logging.info(f"Backing up configuration to {destination_path}")

    try:
        # Write the configuration to a file
        with open(destination_path, 'w') as backup_file:
            yaml.dump(config, backup_file)
        
        click.secho(f"✅ Configuration backed up to {destination_path}.", fg='green')
        logging.info(f"✅ Configuration backed up to {destination_path}")

        if compress:
            compressed_path = f"{destination_path}.gz"
            with open(destination_path, 'rb') as f_in, gzip.open(compressed_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
            os.remove(destination_path)  # Remove the uncompressed file
            click.secho(f"✅ Backup compressed to {compressed_path}.", fg='green')
            logging.info(f"✅ Backup compressed to {compressed_path}")
    except Exception as e:
        click.secho(f"❌ Error backing up configuration: {str(e)}", fg='red')
        logging.error(f"❌ Error backing up configuration: {str(e)}")


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
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
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


@px.command('update')
def px_update_hosts():
    """🔄 Update all Proxmox hosts."""
    command = ["apt-get", "update", "&&", "apt-get", "upgrade", "-y"]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if result.returncode == 0:
        click.secho("✅ All hosts updated successfully.", fg='green')
    else:
        click.secho(f"❌ Failed to update hosts: {result.stderr}", fg='red')

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



@px.command('backup-lxc')
@click.argument('vmid')
@click.option('--storage', required=True, help="The storage target where the backup will be stored.")
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
        logging.error("❌ Failed to retrieve existing VMIDs. Defaulting to start_vmid.")
        return start_vmid


# Command to run LXC instances

def is_container_locked(instance_id, host_details):
    """Checks if the container is locked by using the pct config command."""
    check_lock_cmd = ["pct", "config", str(instance_id)]
    result = run_proxmox_command(check_lock_cmd, check_lock_cmd, config['use_local_only'], host_details)
    
    if result.returncode == 0:
        return 'lock' in result.stdout
    else:
        logging.error(f"❌ Failed to check lock status for instance {instance_id}: {result.stderr}")
        return False  # Assume it's not locked if the command fails to avoid indefinite retries

@lxc.command('run')
@click.option('--image-id', required=True, help="ID of the container image template.")
@click.option('--count', default=1, help="Number of instances to run.")
@click.option('--size', default='small', type=click.Choice(list(config['instance_sizes'].keys())), help="Instance size.")
@click.option('--hostname', default=None, help="Hostname for the container.")
@click.option('--net0', default=f"name=eth0,bridge={config.get('default_network', 'vmbr0')}", help="Network settings for the container.")
@click.option('--storage-size', default=None, help="Override storage size for the container (e.g., 16G).")
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
def run_instances(image_id, count, size, hostname, net0, storage_size, onboot, lock, init, region, az, max_retries, retry_delay, password, ip, netmask, gateway, dns, dhcp):
    """🛠️ Create and start LXC containers with optional network configuration, root password, gateway, and DNS settings."""
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

        if password:
            create_cmd.extend(["--password", password])

        # Set up network configuration
        if dhcp:
            create_cmd.extend(["--net0", f"{net0},ip=dhcp"])
        elif ip:
            net_config = f"{net0},ip={ip}/{netmask}"
            if gateway:
                net_config += f",gw={gateway}"
            create_cmd.extend(["--net0", net_config])

        # Add DNS settings if provided
        if dns:
            create_cmd.extend(["--nameserver", dns])

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



@lxc.command('stop')
@click.argument('instance_ids', nargs=-1)
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
def stop_instances(instance_ids, region, az):
    """🛑 Stop running LXC containers."""
    process_instance_command(instance_ids, 'stop', region, az)

@lxc.command('terminate')
@click.argument('instance_ids', nargs=-1)
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
def terminate_instances(instance_ids, region, az):
    """💥 Terminate (destroy) LXC containers."""
    process_instance_command(instance_ids, 'terminate', region, az)

@lxc.command('show')
@click.argument('instance_ids', nargs=-1, required=False)
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

@lxc.command('scale')
@click.argument('instance_ids', nargs=-1)
@click.option('--memory', default=None, help="New memory size in MB.")
@click.option('--cpulimit', default=None, help="New CPU limit.")
@click.option('--cpucores', default=None, help="New number of CPU cores.")
@click.option('--storage-size', default=None, help="New root storage size (e.g., 16G).")
@click.option('--net-limit', default=None, help="Network bandwidth limit (e.g., 10mbit).")
@click.option('--disk-read-limit', default=None, help="Disk read limit (e.g., 50mb).")
@click.option('--disk-write-limit', default=None, help="Disk write limit (e.g., 30mb).")
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
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

@lxc.command('snapshot-add')
@click.argument('instance_id')
@click.argument('snapshot_name')
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
def create_snapshot(instance_id, snapshot_name, region, az):
    """📸 Create a snapshot of an LXC container."""
    process_instance_command([instance_id], 'snapshot_create', region, az, snapshot_name=snapshot_name)

@lxc.command('snapshot-rm')
@click.argument('instance_id')
@click.argument('snapshot_name')
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
def delete_snapshot(instance_id, snapshot_name, region, az):
    """🗑️ Delete a snapshot of an LXC container."""
    process_instance_command([instance_id], 'snapshot_delete', region, az, snapshot_name=snapshot_name)

@lxc.command('snapshots')
@click.argument('instance_id')
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
@click.argument('instance_ids', nargs=-1)
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
def start_instances(instance_ids, region, az):
    """🚀 Start stopped LXC containers."""
    process_instance_command(instance_ids, 'start', region, az)

@lxc.command('reboot')
@click.argument('instance_ids', nargs=-1)
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
def reboot_instances(instance_ids, region, az):
    """🔄 Reboot running LXC containers."""
    process_instance_command(instance_ids, 'reboot', region, az)

@px.command('image-add')
@click.argument('instance_id')
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
    else:
        click.secho(f"❌ Failed to stop instance {instance_id}: {stop_result.stderr}", fg='red')

@px.command('image-rm')
@click.argument('template_name')
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


@lxc.command('volume-attach')
@click.argument('instance_id')
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

@lxc.command('volume-detach')
@click.argument('instance_id')
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

@lxc.command('status')
@click.argument('instance_ids', nargs=-1)
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
@click.argument('service_name')
@click.argument('instance_ids', nargs=-1)
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
@click.argument('instance_id')
@click.option('--target-host', required=True, help="Target Proxmox host where the LXC container will be migrated.")
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
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


@px.command('security-group-add')
@click.argument('group_name')
@click.option('--description', default='', help="Description of the security group.")
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
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

@px.command('security-group-rm')
@click.argument('group_name')
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
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


@px.command('security-group-rule-add')
@click.argument('group_name')
@click.option('--direction', type=click.Choice(['IN', 'OUT']), required=True, help="Direction of the rule (IN or OUT).")
@click.option('--action', type=click.Choice(['ACCEPT', 'DROP', 'REJECT']), default='ACCEPT', help="Action to take on the traffic (ACCEPT, DROP, REJECT).")
@click.option('--protocol', default='tcp', help="Protocol (e.g., tcp, udp, icmp).")
@click.option('--source-ip', default=None, help="Source IP or CIDR for ingress rules.")
@click.option('--source-port', default=None, help="Source port number or range (e.g., 22, 80:443).")
@click.option('--destination-ip', default=None, help="Destination IP or CIDR for egress rules.")
@click.option('--destination-port', default=None, help="Destination port number or range (e.g., 22, 80:443).")
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
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

@px.command('security-group-rule-rm')
@click.argument('group_name')
@click.option('--direction', type=click.Choice(['IN', 'OUT']), required=True, help="Direction of the rule (IN or OUT).")
@click.option('--action', type=click.Choice(['ACCEPT', 'DROP', 'REJECT']), default='ACCEPT', help="Action to take on the traffic (ACCEPT, DROP, REJECT).")
@click.option('--protocol', default='tcp', help="Protocol (e.g., tcp, udp, icmp).")
@click.option('--source-ip', default=None, help="Source IP or CIDR for ingress rules.")
@click.option('--source-port', default=None, help="Source port number or range (e.g., 22, 80:443).")
@click.option('--destination-ip', default=None, help="Destination IP or CIDR for egress rules.")
@click.option('--destination-port', default=None, help="Destination port number or range (e.g., 22, 80:443).")
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
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

@px.command('security-group-attach')
@click.argument('group_name')
@click.argument('vmid')
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
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

@px.command('security-group-detach')
@click.argument('group_name')
@click.argument('vmid')
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
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

@lxc.command('show-storage')
@click.argument('instance_id')
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
    else:
        click.secho(f"❌ Failed to retrieve storage details for instance {instance_id}: {result.stderr.strip()}", fg='red')



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

@app.command('setup')
@click.argument('instance_id')  # Accept a single instance ID
@click.argument('package_name', default='docker')
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1.")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1.")
def install_docker(instance_id, package_name, region, az):
    """📦 Install Docker and Compose on an LXC container."""
    host_details = config['regions'][region]['availability_zones'][az]
    logging.debug(f"🔧 Processing LXC container {instance_id} on host {host_details['host']}")

    click.secho(f"🔧 Processing LXC container {instance_id}...", fg='yellow')

    # Check if the container is running
    status_cmd = ["pct", "status", instance_id]
    logging.debug(f"🔎 Checking status with command: {' '.join(status_cmd)}")
    
    status_result = run_proxmox_command(
        status_cmd,
        status_cmd,
        config['use_local_only'], host_details
    )

    if status_result is None or "status: running" not in status_result.stdout:
        logging.error(f"❌ LXC container {instance_id} is not running.")
        click.secho(f"❌ LXC container {instance_id} is not running.", fg='red')
        return

    logging.debug(f"✅ LXC container {instance_id} is running.")

    # Check if Docker is already installed inside the container
    docker_check_cmd = ["pct", "exec", instance_id, "--", "which", "docker"]
    logging.debug(f"🔎 Checking if Docker is installed with command: {' '.join(docker_check_cmd)}")

    docker_check_result = run_proxmox_command(docker_check_cmd, docker_check_cmd, config['use_local_only'], host_details)

    if docker_check_result.returncode == 0:
        logging.info(f"✅ Docker is already installed on instance {instance_id}.")
        click.secho(f"✅ Docker is already installed on instance {instance_id}.", fg='green')
    else:
        # Install Docker and Docker Compose using apt inside the LXC container
        docker_install_cmd = [
            "pct", "exec", instance_id, "--", "bash", "-c",
            "\"apt-get update && apt-get install -y docker.io docker-compose\""
        ]
        logging.debug(f"🔧 Installing Docker and Docker Compose with command: {' '.join(docker_install_cmd)}")
        docker_install_result = run_proxmox_command(
            docker_install_cmd, docker_install_cmd, config['use_local_only'], host_details
        )

        if docker_install_result.returncode == 0:
            logging.info(f"✅ Docker and Docker Compose installed successfully on instance {instance_id}.")
            click.secho(f"✅ Docker and Docker Compose installed successfully on instance {instance_id}.", fg='green')
        else:
            logging.error(f"❌ Failed to install Docker and Docker Compose on instance {instance_id}: {docker_install_result.stderr}")
            click.secho(f"❌ Failed to install Docker and Docker Compose on instance {instance_id}.", fg='red')
            return

    logging.info(f"🔧 Finished processing LXC container {instance_id}.")
    click.secho(f"🔧 Finished processing LXC container {instance_id}.\n", fg='yellow')



@app.command('run')
@click.argument('instance_id')
@click.argument('docker_command', nargs=-1, type=click.UNPROCESSED)
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
def run_docker(instance_id, docker_command, region, az):
    """🚀 Execute docker run inside an LXC container."""
    logging.debug(f"🔎 Starting dock run with instance_id: {instance_id} and docker_command: {docker_command}")
    
    if not docker_command:
        click.secho("❌ No Docker command provided.", fg='red')
        return

    # Fetch host details from the configuration
    host_details = config['regions'][region]['availability_zones'][az]
    logging.debug(f"🔎 Host details: {host_details}")
    
    # Check if the container is running
    status_cmd = ["pct", "status", instance_id]
    status_result = run_proxmox_command(status_cmd, status_cmd, config['use_local_only'], host_details)
    logging.debug(f"🔎 Executed status command: {status_cmd}")
    logging.debug(f"🔎 Container status result: {status_result.stdout.strip()}")
    logging.debug(f"🔎 Container status stderr: {status_result.stderr.strip()}")

    if "status: running" not in status_result.stdout:
        click.secho(f"❌ LXC container {instance_id} is not running.", fg='red')
        return
    
    # Ensure Docker is installed
    docker_check_cmd = ["pct", "exec", instance_id, "--", "docker", "--version"]
    docker_check_result = run_proxmox_command(docker_check_cmd, docker_check_cmd, config['use_local_only'], host_details)
    logging.debug(f"🔎 Executed Docker check command: {docker_check_cmd}")
    logging.debug(f"🔎 Docker version check result: {docker_check_result.stdout.strip()}")
    logging.debug(f"🔎 Docker version check stderr: {docker_check_result.stderr.strip()}")

    if docker_check_result.returncode != 0:
        click.secho(f"🔧 Docker not found on instance {instance_id}. Installing Docker...", fg='yellow')
        install_docker_cmd = ["pct", "exec", instance_id, "--", "apt-get", "update"]
        update_result = run_proxmox_command(install_docker_cmd, install_docker_cmd, config['use_local_only'], host_details)
        logging.debug(f"🔎 Executed apt-get update command: {install_docker_cmd}")
        logging.debug(f"🔎 apt-get update result stdout: {update_result.stdout.strip()}")
        logging.debug(f"🔎 apt-get update result stderr: {update_result.stderr.strip()}")

        install_docker_cmd = ["pct", "exec", instance_id, "--", "apt-get", "install", "-y", "docker.io"]
        install_result = run_proxmox_command(install_docker_cmd, install_docker_cmd, config['use_local_only'], host_details)
        
        logging.debug(f"🔎 Executed Docker install command: {install_docker_cmd}")
        logging.debug(f"🔎 Docker install result stdout: {install_result.stdout.strip()}")
        logging.debug(f"🔎 Docker install result stderr: {install_result.stderr.strip()}")

        if install_result.returncode == 0:
            click.secho(f"✅ Docker installed successfully on instance {instance_id}.", fg='green')
        else:
            click.secho(f"❌ Docker installation failed on instance {instance_id}: {install_result.stderr.strip()}", fg='red')
            return

    # Prepend "docker run" to the Docker command, remove "-d" if it conflicts with port mapping
    docker_run_cmd = ["pct", "exec", instance_id, "--", "docker", "run"] + list(docker_command)
    logging.debug(f"🔎 Final Docker command to execute: {docker_run_cmd}")

    run_result = run_proxmox_command(
        docker_run_cmd,
        docker_run_cmd,
        config['use_local_only'], host_details
    )
    
    logging.debug(f"🔎 Docker command execution stdout: {run_result.stdout.strip()}")
    logging.debug(f"🔎 Docker command execution stderr: {run_result.stderr.strip()}")

    if run_result.returncode == 0:
        click.secho(f"✅ Docker command executed successfully on instance {instance_id}:\n{run_result.stdout.strip()}", fg='green')
    else:
        click.secho(f"❌ Failed to execute Docker command on instance {instance_id}: {run_result.stderr.strip()}", fg='red')


### compose
@app.command('deploy')
@click.argument('action', type=click.Choice(['install', 'uninstall', 'start', 'stop', 'restart', 'status']))
@click.argument('instance_id')  # Instance ID is now a positional argument
@click.option('--compose_file', required=True, help="Local path or remote URL to the Docker Compose YAML file.")
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
@click.option('--auto_start', is_flag=True, help="Enable auto-start for the application.")
def compose(action, instance_id, compose_file, region, az, auto_start):
    """🚀 Manage apps with Compose on LXC containers."""
    host_details = config['regions'][region]['availability_zones'][az]

    # Ensure the Docker Compose file is available locally
    if not os.path.exists(compose_file):
        if compose_file.startswith("http://") or compose_file.startswith("https://"):
            click.secho(f"🔧 Downloading Docker Compose file from {compose_file}...", fg='yellow')
            # Use secure temporary file creation instead of hardcoded /tmp
            temp_fd, local_compose_file = tempfile.mkstemp(suffix=".yml", prefix="docker-compose-")
            try:
                # Add timeout to prevent indefinite blocking
                response = requests.get(compose_file, timeout=30)
                response.raise_for_status()
                with os.fdopen(temp_fd, 'wb') as file:
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

    # Upload the Compose file to the Proxmox host using secure temp directory
    # Use timestamp to ensure uniqueness and avoid collisions
    timestamp = int(time.time())
    remote_host_path = f"/var/tmp/lws-{app_name}-{timestamp}-docker-compose.yml"
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
        logging.error(f"❌ Failed to parse Docker Compose file: {str(e)}")
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

@app.command('update')
@click.argument('instance_id')
@click.argument('compose_file', required=True)
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
def compose_update(instance_id, compose_file, region, az):
    """🆕 Update app within an LXC container via Compose."""
    host_details = config['regions'][region]['availability_zones'][az]
    logging.info(f"✅ Starting Docker Compose update for instance {instance_id}")

    # Ensure the Docker Compose file is available locally
    if not os.path.exists(compose_file):
        click.secho(f"❌ Docker Compose file not found at {compose_file}.", fg='red')
        logging.error(f"❌ Docker Compose file not found: {compose_file}")
        return

    # Upload the Compose file to the Proxmox host using secure temp directory
    timestamp = int(time.time())
    compose_basename = os.path.basename(compose_file)
    remote_host_path = f"/var/tmp/lws-{timestamp}-{compose_basename}"
    scp_cmd = ["scp", compose_file, f"{host_details['user']}@{host_details['host']}:{remote_host_path}"]
    result = subprocess.run(scp_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        click.secho(f"❌ Failed to upload Docker Compose file to Proxmox host: {result.stderr.strip()}", fg='red')
        logging.error(f"❌ Failed to upload Docker Compose file to Proxmox host: {result.stderr.strip()}")
        return

    click.secho(f"✅ Docker Compose file uploaded to Proxmox host at {remote_host_path}.", fg='green')
    logging.info(f"✅ Docker Compose file uploaded to Proxmox host: {remote_host_path}")

    # Transfer the file to the LXC container using pct push
    pct_push_cmd = ["sshpass", "-p", host_details['ssh_password'], "ssh", f"{host_details['user']}@{host_details['host']}", "pct", "push", instance_id, remote_host_path, remote_host_path]
    result = subprocess.run(pct_push_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        click.secho(f"❌ Failed to transfer Docker Compose file to LXC container: {result.stderr.strip()}", fg='red')
        logging.error(f"❌ Failed to transfer Docker Compose file to LXC container: {result.stderr.strip()}")
        return
    
    click.secho(f"✅ Docker Compose file transferred to {remote_host_path} on instance {instance_id}.", fg='green')
    logging.info(f"✅ Docker Compose file transferred to LXC container: {remote_host_path}")

    # Define the Docker Compose update commands
    compose_pull_cmd = ["pct", "exec", instance_id, "--", "docker-compose", "-f", remote_host_path, "pull"]
    compose_up_cmd = ["pct", "exec", instance_id, "--", "docker-compose", "-f", remote_host_path, "up", "-d"]

    # Execute docker-compose pull
    logging.info(f"Pulling Docker Compose images for instance {instance_id}")
    pull_result = run_proxmox_command(compose_pull_cmd, compose_pull_cmd, config['use_local_only'], host_details)
    if pull_result.returncode == 0:
        click.secho(f"✅ Docker Compose application images pulled successfully on instance {instance_id}.", fg='green')
        logging.info(f"✅ Docker Compose application images pulled successfully on instance {instance_id}")
    else:
        click.secho(f"❌ Failed to pull Docker Compose images on instance {instance_id}: {pull_result.stderr.strip()}", fg='red')
        logging.error(f"❌ Failed to pull Docker Compose images on instance {instance_id}: {pull_result.stderr.strip()}")
        return

    # Execute docker-compose up -d
    logging.info(f"Starting Docker Compose application on instance {instance_id}")
    up_result = run_proxmox_command(compose_up_cmd, compose_up_cmd, config['use_local_only'], host_details)
    if up_result.returncode == 0:
        click.secho(f"✅ Docker Compose application updated successfully on instance {instance_id}.", fg='green')
        logging.info(f"✅ Docker Compose application updated successfully on instance {instance_id}")
    else:
        click.secho(f"❌ Failed to update Docker Compose application on instance {instance_id}: {up_result.stderr.strip()}", fg='red')
        logging.error(f"❌ Failed to update Docker Compose application on instance {instance_id}: {up_result.stderr.strip()}")


@app.command('logs')
@click.argument('instance_id')
@click.argument('container_name_or_id')
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
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
        logging.info(f"📄 Logs fetched for container {container_name_or_id} on instance {instance_id}")
    else:
        click.secho(f"❌ Failed to fetch logs for container {container_name_or_id} on instance {instance_id}: {result.stderr.strip()}", fg='red')
        logging.error(f"❌ Failed to fetch logs for container {container_name_or_id} on instance {instance_id}: {result.stderr.strip()}")


@app.command('list')
@click.argument('instance_id')
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
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
        logging.info(f"📦 Listed running containers on instance {instance_id}")
    else:
        click.secho(f"❌ Failed to list running containers on instance {instance_id}: {result.stderr.strip()}", fg='red')
        logging.error(f"❌ Failed to list running containers on instance {instance_id}: {result.stderr.strip()}")


@app.command('remove')
@click.argument('instance_ids', nargs=-1)  # Accept multiple instance IDs
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
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
                logging.error(f"❌ Failed to purge Docker resources on instance {instance_id}: {purge_result.stderr.strip()}")
                continue

        # Remove Docker and Docker Compose
        remove_cmd = ["pct", "exec", instance_id, "--", "apt-get", "remove", "-y", "docker.io", "docker-compose-plugin"]
        remove_result = run_proxmox_command(remove_cmd, remove_cmd, config['use_local_only'], host_details)

        if remove_result.returncode == 0:
            click.secho(f"✅ Docker and Docker Compose removed successfully from instance {instance_id}.", fg='green')
            logging.info(f"✅ Docker and Docker Compose removed from instance {instance_id}")
        else:
            click.secho(f"❌ Failed to remove Docker and Docker Compose from instance {instance_id}: {remove_result.stderr.strip()}", fg='red')
            logging.error(f"❌ Failed to remove Docker and Docker Compose from instance {instance_id}: {remove_result.stderr.strip()}")


@lxc.command('clone')
@click.argument('source_instance_id')
@click.argument('target_instance_id')
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
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
        logging.error(f"❌ Failed to create snapshot {snapshot_name} on instance {source_instance_id}: {snapshot_result.stderr.strip()}")
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
        logging.info(f"✅ Successfully cloned instance {source_instance_id} to {target_instance_id} from snapshot {snapshot_name}")

        # Automatically start the cloned container if the option is enabled
        if start:
            logging.info(f"Starting cloned LXC container {target_instance_id}")
            start_cmd = ["pct", "start", target_instance_id]
            start_result = run_proxmox_command(start_cmd, start_cmd, config['use_local_only'], host_details)

            if start_result.returncode == 0:
                click.secho(f"✅ Cloned container {target_instance_id} started successfully.", fg='green')
                logging.info(f"✅ Cloned container {target_instance_id} started successfully")
            else:
                click.secho(f"❌ Failed to start cloned container {target_instance_id}: {start_result.stderr.strip()}", fg='red')
                logging.error(f"❌ Failed to start cloned container {target_instance_id}: {start_result.stderr.strip()}")
    else:
        click.secho(f"❌ Failed to clone instance {source_instance_id} to {target_instance_id}: {clone_result.stderr.strip()}", fg='red')
        logging.error(f"❌ Failed to clone instance {source_instance_id} to {target_instance_id}: {clone_result.stderr.strip()}")


@lxc.command('exec')
@click.argument('instance_ids', nargs=-1, required=True)
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

    # Convert the single command argument into a list of arguments
    command_list = command.split()

    for instance_id in instance_ids:
        exec_cmd = ["pct", "exec", str(instance_id), "--"] + command_list

        logging.info(f"Executing command in instance {instance_id}: {command}")
        click.secho(f"🔧 Executing command in instance {instance_id}: {command}", fg='cyan')
        
        exec_result = run_proxmox_command(exec_cmd, exec_cmd, config['use_local_only'], host_details)

        if exec_result.returncode == 0:
            logging.info(f"✅ Command executed successfully in instance {instance_id}.")
            click.secho(f"✅ Command executed successfully in instance {instance_id}.", fg='green')
            logging.debug(f"🔎 Command output for instance {instance_id}: {exec_result.stdout}")
            click.secho(exec_result.stdout, fg='white')
        else:
            logging.error(f"❌ Failed to execute command in instance {instance_id}: {exec_result.stderr}")
            click.secho(f"❌ Failed to execute command in instance {instance_id}: {exec_result.stderr}", fg='red')

@lxc.command('net')
@click.argument('instance_id', required=True)
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

    # Step 2: Attempt to check the port from within the LXC container
    check_port_cmd = ["nc", "-zv", "-w", str(timeout), f"127.0.0.1", str(port)]
    port_check_result = run_proxmox_command(
        local_cmd=check_port_cmd,
        remote_cmd=["pct", "exec", instance_id, "--"] + check_port_cmd,
        use_local_only=config['use_local_only'],
        host_details=host_details
    )

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

    proxmox_to_lxc_check_cmd = ["nc", "-zv", "-w", str(timeout), lxc_ip, str(port)]
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
    
    except Exception as e:
        click.secho(f"❌ An error occurred while listing templates: {str(e)}", fg='red')
        logging.error(f"❌ An error occurred while listing templates: {str(e)}")

@px.command('security-groups')
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target.")
def list_security_groups(region, az):
    """🔐 List all security groups and their rules in the Proxmox cluster."""
    
    host_details = config['regions'][region]['availability_zones'][az]
    
    # Command to read the entire cluster.fw file
    list_sg_cmd = ["cat", "/etc/pve/firewall/cluster.fw"]
    
    try:
        # Run the command on the Proxmox host
        result = run_proxmox_command(
            local_cmd=list_sg_cmd,
            remote_cmd=list_sg_cmd,
            use_local_only=config['use_local_only'],
            host_details=host_details
        )
        
        if result and result.returncode == 0:
            click.secho("🔐 Security Groups and their rules in the cluster:\n", fg='cyan')
            
            lines = result.stdout.splitlines()
            inside_group = False
            
            for line in lines:
                line = line.strip()
                
                if line.startswith("[group "):
                    # Print the security group name
                    click.secho(f"\n{line}", fg='yellow')
                    inside_group = True
                elif inside_group:
                    if line == "":
                        inside_group = False
                    else:
                        # Print the rules within the group
                        click.secho(f"  {line}", fg='white')
                        
        else:
            click.secho(f"❌ Failed to list security groups: {result.stderr.strip()}", fg='red')
    
    except Exception as e:
        click.secho(f"❌ An error occurred while listing security groups: {str(e)}", fg='red')
        logging.error(f"❌ An error occurred while listing security groups: {str(e)}")


@lxc.command('show-info')
@click.argument('instance_id', required=True)
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

@lxc.command('show-public-ip')
@click.argument('instance_id', required=True)
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
    
    except Exception as e:
        click.secho(f"❌ An error occurred while retrieving the public IP address: {str(e)}", fg='red')
        logging.error(f"❌ An error occurred while retrieving the public IP address for LXC {instance_id}: {str(e)}")

@px.command('exec')
@click.argument('command', nargs=-1, required=True)
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target.")
def exec_proxmox_command(command, region, az):
    """👨🏻‍💻 Execute an arbitrary command into a Proxmox host."""
    
    host_details = config['regions'][region]['availability_zones'][az]

    # Join the command arguments into a single command string
    command_str = " ".join(command)

    # Build the SSH command to execute the arbitrary command on the Proxmox host
    ssh_command = ["sshpass", "-p", host_details['ssh_password'], "ssh", f"{host_details['user']}@{host_details['host']}", command_str]

    # Log the command being executed (sanitized)
    sanitized_ssh_command = ["sshpass", "-p", "****", "ssh", f"{host_details['user']}@{host_details['host']}", command_str]
    logging.debug(f"Executing SSH command on Proxmox host: {' '.join(sanitized_ssh_command)}")

    try:
        # Execute the command on the Proxmox host
        result = subprocess.run(ssh_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if result.returncode == 0:
            logging.info(f"Command executed successfully on Proxmox host {host_details['host']}:\n{result.stdout.strip()}")
            click.secho(f"✅ Command executed successfully on Proxmox host {host_details['host']}.\nOutput:\n{result.stdout.strip()}", fg='green')
        else:
            logging.error(f"Command failed on Proxmox host {host_details['host']} with return code {result.returncode}:\n{result.stderr.strip()}")
            click.secho(f"❌ Command failed on Proxmox host {host_details['host']}.\nError:\n{result.stderr.strip()}", fg='red')

    except Exception as e:
        logging.error(f"An error occurred while executing command on Proxmox host {host_details['host']}: {str(e)}")
        click.secho(f"❌ An error occurred while executing the command: {str(e)}", fg='red')


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
@click.argument('instance_id')
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Default to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Default to az1")
def scale_check_suggest_resources(instance_id, region, az):
    """⚖️ Scaling adjustments for an LXC container."""
    logging.info(f"Starting scale-check for instance {instance_id} in region {region}, AZ {az}")
    
    config = scale_check_load_config()
    host_details = scale_check_get_proxmox_host_details(region, az)

    logging.debug(f"Retrieved host details: {host_details}")

    # Retrieve host resource usage
    total_cores, total_memory, free_memory = scale_check_get_host_free_resources(host_details)
    if total_cores is None or total_memory is None:
        logging.error("Failed to retrieve host resources.")
        click.secho("❌ Could not retrieve host resources.", fg='red')
        return

    logging.info(f"Proxmox Host resources - Total cores: {total_cores}, Total memory: {total_memory} MB, Free memory: {free_memory} MB")
    click.secho(f"ℹ️ Proxmox Host: {total_cores} cores, {free_memory} MB free memory", fg='cyan')

    # Retrieve LXC resource usage
    cpulimit, cpuunits, memory, storage = scale_check_get_lxc_resources(instance_id, host_details)
    if cpulimit is None or memory is None or storage is None:
        logging.error(f"Failed to retrieve resources for container {instance_id}.")
        click.secho(f"❌ Could not retrieve resources for container {instance_id}.", fg='red')
        return

    logging.info(f"Instance {instance_id} resources - CPU cores: {cpulimit}, Memory: {memory} MB, Storage: {storage} GB")
    click.secho(f"ℹ️ Instance {instance_id}: {cpulimit} cores, {memory} MB total memory, {storage} GB storage", fg='cyan')

    # Fetch thresholds and limits from the config
    cpu_thresholds_host = config.get('scaling', {}).get('host_cpu', {})
    cpu_thresholds_lxc = config.get('scaling', {}).get('lxc_cpu', {})
    memory_thresholds_host = config.get('scaling', {}).get('host_memory', {})
    memory_thresholds_lxc = config.get('scaling', {}).get('lxc_memory', {})
    storage_thresholds_host = config.get('scaling', {}).get('host_storage', {})
    storage_thresholds_lxc = config.get('scaling', {}).get('lxc_storage', {})
    limits = config.get('scaling', {}).get('limits', {})

    min_cores = limits.get('min_cpu_cores', 1)
    max_cores = limits.get('max_cpu_cores', total_cores)
    min_memory_mb = limits.get('min_memory_mb', 512)
    max_memory_mb = limits.get('max_memory_mb', total_memory)
    min_storage_gb = limits.get('min_storage_gb', 10)
    max_storage_gb = limits.get('max_storage_gb', storage_thresholds_host.get('total_storage_gb', 1024))

    suggestions = []

    # CPU core adjustments based on host and LXC usage
    if cpulimit < (total_cores * cpu_thresholds_lxc.get('min_threshold', 0.30)):
        suggested_cores = min(max_cores, int(cpulimit + cpu_thresholds_lxc.get('step', 1) * cpu_thresholds_lxc.get('scale_up_multiplier', 1.5)))
        if suggested_cores > cpulimit:
            logging.info(f"Suggesting CPU core increase to {suggested_cores} for instance {instance_id}.")
            suggestions.append(f"🔧 Consider increasing CPU cores to {suggested_cores} (current: {cpulimit}).")
    elif cpulimit > (total_cores * cpu_thresholds_lxc.get('max_threshold', 0.80)):
        suggested_cores = max(min_cores, int(cpulimit - cpu_thresholds_lxc.get('step', 1) * cpu_thresholds_lxc.get('scale_down_multiplier', 0.5)))
        if suggested_cores < cpulimit:
            logging.info(f"Suggesting CPU core decrease to {suggested_cores} for instance {instance_id}.")
            suggestions.append(f"🔧 Consider decreasing CPU cores to {suggested_cores} (current: {cpulimit}).")

    # Memory adjustments based on host and LXC usage
    if memory < (total_memory * memory_thresholds_lxc.get('min_threshold', 0.40)):
        suggested_memory = min(max_memory_mb, int(memory + memory_thresholds_lxc.get('step_mb', 256) * memory_thresholds_lxc.get('scale_up_multiplier', 1.25)))
        if suggested_memory > memory:
            logging.info(f"Suggesting memory increase to {suggested_memory} MB for instance {instance_id}.")
            suggestions.append(f"🔧 Consider increasing memory to {suggested_memory} MB (current: {memory} MB).")
    elif memory > (total_memory * memory_thresholds_lxc.get('max_threshold', 0.70)):
        suggested_memory = max(min_memory_mb, int(memory - memory_thresholds_lxc.get('step_mb', 256) * memory_thresholds_lxc.get('scale_down_multiplier', 0.75)))
        if suggested_memory < memory:
            logging.info(f"Suggesting memory decrease to {suggested_memory} MB for instance {instance_id}.")
            suggestions.append(f"🔧 Consider decreasing memory to {suggested_memory} MB (current: {memory} MB).")

    # Storage adjustments based on host and LXC usage
    if storage < (max_storage_gb * storage_thresholds_lxc.get('min_threshold', 0.50)):
        suggested_storage = min(max_storage_gb, int(storage + storage_thresholds_lxc.get('step_gb', 10) * storage_thresholds_lxc.get('scale_up_multiplier', 1.5)))
        if suggested_storage > storage:
            logging.info(f"Suggesting storage increase to {suggested_storage} GB for instance {instance_id}.")
            suggestions.append(f"🔧 Consider increasing storage to {suggested_storage} GB (current: {storage} GB).")
    elif storage > (max_storage_gb * storage_thresholds_lxc.get('max_threshold', 0.85)):
        suggested_storage = max(min_storage_gb, int(storage - storage_thresholds_lxc.get('step_gb', 10) * storage_thresholds_lxc.get('scale_down_multiplier', 0.5)))
        if suggested_storage < storage:
            logging.info(f"Suggesting storage decrease to {suggested_storage} GB for instance {instance_id}.")
            suggestions.append(f"🔧 Consider decreasing storage to {suggested_storage} GB (current: {storage} GB).")

    # Output the suggestions
    if suggestions:
        logging.info("Suggestions made for scaling adjustments.")
        click.secho("\n".join(suggestions), fg='green')
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

def scale_check_get_lxc_resources(instance_id, host_details):
    """Retrieve the allocated CPU cores, CPU units, memory, and storage resources of an LXC container."""
    command = ["pct", "config", instance_id]
    result = run_proxmox_command(command, command, config['use_local_only'], host_details)

    if result.returncode == 0:
        config_lines = result.stdout.splitlines()
        cpulimit = None
        cpuunits = None
        memory = None
        storage = None

        for line in config_lines:
            if "cores" in line:
                cpulimit = int(line.split(":")[1].strip())
            elif "cpuunits" in line:
                cpuunits = int(line.split(":")[1].strip())
            elif "memory" in line:
                memory = int(line.split(":")[1].strip())
            elif "rootfs" in line:
                # Extracting the storage size from the rootfs line
                storage_part = line.split(",")[1]
                if "size=" in storage_part:
                    storage = int(storage_part.split("=")[1].replace("G", "").strip())

        return cpulimit, cpuunits, memory, storage
    else:
        logging.error(f"Failed to retrieve LXC resources for {instance_id}: {result.stderr}")
        return None, None, None, None


@px.command('backup')
@click.argument('backup_dir')
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate. Defaults to eu-south-1")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target. Defaults to az1")
def px_backup_hosts(backup_dir, region, az):
    """💾 Backup configurations from all Proxmox hosts."""
    logging.info(f"Starting backup for region {region}, AZ {az}")

    # Load configuration
    config = load_config()
    if not config:
        click.secho("❌ Failed to load configuration.", fg='red')
        return

    # Get host details from configuration based on region and AZ
    try:
        host_details = config['regions'][region]['availability_zones'][az]
        use_local_only = config.get('use_local_only', False)
    except KeyError as e:
        logging.error(f"❌ Invalid region or availability zone: {e}")
        click.secho(f"❌ Invalid region or availability zone: {e}", fg='red')
        return

    # Ensure the backup directory exists, or create it
    if not os.path.exists(backup_dir):
        try:
            os.makedirs(backup_dir)
            logging.info(f"📁 Created backup directory {backup_dir}.")
        except OSError as e:
            logging.error(f"❌ Failed to create backup directory {backup_dir}: {str(e)}")
            click.secho(f"❌ Failed to create backup directory {backup_dir}: {str(e)}", fg='red')
            return

    backup_file = os.path.join(backup_dir, "proxmox-backup.tar.gz")
    tar_command = ["tar", "-czf", backup_file, "/etc/pve"]

    logging.info(f"🛠️ Preparing to back up Proxmox configurations to {backup_file}.")

    # Run the backup command
    result = run_proxmox_command(local_cmd=tar_command, remote_cmd=tar_command, use_local_only=use_local_only, host_details=host_details)

    # Check the result and provide appropriate feedback
    if result and result.returncode == 0:
        logging.info(f"✅ Backup completed successfully. Saved to {backup_file}.")
        click.secho(f"✅ Backup completed successfully. Saved to {backup_file}.", fg='green')
    else:
        logging.error(f"❌ Failed to backup hosts: {result.stderr if result else 'Unknown error'}")
        click.secho(f"❌ Failed to backup hosts: {result.stderr if result else 'Unknown error'}", fg='red')



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
@click.argument('lxc_id', required=False)
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

@lxc.command('health-check')
@click.argument('instance_id', required=True)
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target.")
@click.option('--fix', is_flag=True, help="Attempt to fix common issues.")
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
    
    # Check for high CPU usage
    cpu_cmd = ["pct", "exec", instance_id, "--", "top", "-bn1", "|", "grep", "Cpu"]
    cpu_result = run_proxmox_command(cpu_cmd, cpu_cmd, config['use_local_only'], host_details)
    
    if cpu_result.returncode == 0:
        cpu_line = cpu_result.stdout.strip()
        if "id," in cpu_line:  # Look for idle percentage
            idle_pct = float(cpu_line.split("id,")[0].split()[-1])
            usage_pct = 100.0 - idle_pct
            if usage_pct > 80:
                click.secho(f"⚠️ High CPU usage detected: {usage_pct:.1f}%", fg='yellow')
                if fix:
                    click.secho("🔧 Attempting to reduce CPU usage...", fg='yellow')
                    # Example fix: Restart high CPU usage processes
                    restart_cmd = ["pct", "exec", instance_id, "--", "pkill", "-f", "high_cpu_process"]
                    run_proxmox_command(restart_cmd, restart_cmd, config['use_local_only'], host_details)
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
                if fix:
                    click.secho("🔧 Attempting to reduce memory usage...", fg='yellow')
                    # Example fix: Restart high memory usage processes
                    restart_cmd = ["pct", "exec", instance_id, "--", "pkill", "-f", "high_mem_process"]
                    run_proxmox_command(restart_cmd, restart_cmd, config['use_local_only'], host_details)
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
                    click.secho("🔧 Attempting to free up disk space...", fg='yellow')
                    # Example fix: Clean up temporary files using safer approach
                    # Only remove files older than 7 days to avoid breaking running processes
                    cleanup_cmd = ["pct", "exec", instance_id, "--", "find", "/tmp", "/var/tmp", 
                                 "-type", "f", "-mtime", "+7", "-delete", "2>/dev/null", "||", "true"]
                    run_proxmox_command(cleanup_cmd, cleanup_cmd, config['use_local_only'], host_details)
            else:
                click.secho(f"✅ Disk space usage is normal: {disk_usage_pct:.1f}%", fg='green')
    
    # Check for network issues
    network_diagnostics = diagnose_network(host_details, lxc_id=instance_id)
    if "unreachable" in network_diagnostics['dns_resolution']:
        click.secho("⚠️ Network issues detected: DNS resolution failed", fg='yellow')
        if fix:
            click.secho("🔧 Attempting to fix DNS resolution...", fg='yellow')
            # Example fix: Restart networking service
            restart_cmd = ["pct", "exec", instance_id, "--", "systemctl", "restart", "networking"]
            run_proxmox_command(restart_cmd, restart_cmd, config['use_local_only'], host_details)
    else:
        click.secho("✅ Network is functioning normally.", fg='green')
    
    click.secho(f"✅ Health check for container {instance_id} completed.", fg='green')

@lxc.command('backup-restore')
@click.argument('instance_id', required=True)
@click.option('--backup-file', required=True, help="Path to the backup file to restore.")
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target.")
@click.option('--force', is_flag=True, help="Force restore without confirmation.")
def restore_container(instance_id, backup_file, region, az, force):
    """🔄 Restore an LXC container from a backup file."""
    host_details = config['regions'][region]['availability_zones'][az]
    
    if not force:
        click.confirm(f"⚠️ This will overwrite the current state of container {instance_id}. Are you sure?", abort=True)
    
    # Check if the container exists and is stopped
    status_cmd = ["pct", "status", instance_id]
    status_result = run_proxmox_command(status_cmd, status_cmd, config['use_local_only'], host_details)
    
    if status_result.returncode != 0:
        click.secho(f"❌ Failed to get status of container {instance_id}: {status_result.stderr}", fg='red')
        return
    
    if "status: running" in status_result.stdout:
        click.secho("⚠️ Container is running. Stopping container before restore...", fg='yellow')
        stop_cmd = ["pct", "stop", instance_id]
        stop_result = run_proxmox_command(stop_cmd, stop_cmd, config['use_local_only'], host_details)
        
        if stop_result.returncode != 0:
            click.secho(f"❌ Failed to stop container {instance_id}: {stop_result.stderr}", fg='red')
            return
        
        click.secho("✅ Container stopped successfully.", fg='green')
    
    # First, check if backup file exists on local system
    if os.path.exists(backup_file):
        # Upload backup to Proxmox host using secure temp directory
        click.secho(f"📤 Uploading backup file to Proxmox host...", fg='yellow')
        timestamp = int(time.time())
        remote_backup_path = f"/var/tmp/lws-backup-{instance_id}-{timestamp}.tar.gz"
        
        scp_cmd = ["scp", backup_file, f"{host_details['user']}@{host_details['host']}:{remote_backup_path}"]
        scp_result = subprocess.run(scp_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if scp_result.returncode != 0:
            click.secho(f"❌ Failed to upload backup file: {scp_result.stderr}", fg='red')
            return
        
        backup_path = remote_backup_path
    else:
        # Check if file exists on remote host
        check_file_cmd = ["test", "-f", backup_file, "&&", "echo", "exists"]
        file_check_result = run_proxmox_command(check_file_cmd, check_file_cmd, config['use_local_only'], host_details)
        
        if "exists" not in file_check_result.stdout:
            click.secho(f"❌ Backup file not found: {backup_file}", fg='red')
            return
        
        backup_path = backup_file
    
    click.secho(f"🔄 Restoring container {instance_id} from backup...", fg='yellow')
    
    # Extract the backup to a secure temporary directory
    timestamp = int(time.time())
    temp_dir = f"/var/tmp/lws-restore-{instance_id}-{timestamp}"
    mkdir_cmd = ["mkdir", "-p", temp_dir]
    mkdir_result = run_proxmox_command(mkdir_cmd, mkdir_cmd, config['use_local_only'], host_details)
    
    if mkdir_result.returncode != 0:
        click.secho(f"❌ Failed to create temporary directory: {mkdir_result.stderr}", fg='red')
        return
    
    # Extract the backup
    extract_cmd = ["tar", "-xzf", backup_path, "-C", temp_dir]
    extract_result = run_proxmox_command(extract_cmd, extract_cmd, config['use_local_only'], host_details)
    
    if extract_result.returncode != 0:
        click.secho(f"❌ Failed to extract backup: {extract_result.stderr}", fg='red')
        return
    
    # Restore the configuration
    restore_config_cmd = ["pct", "restore", instance_id, f"{temp_dir}/vzdump-lxc-{instance_id}.tar.gz", "--force"]
    restore_result = run_proxmox_command(restore_config_cmd, restore_config_cmd, config['use_local_only'], host_details)
    
    if restore_result.returncode != 0:
        click.secho(f"❌ Failed to restore container: {restore_result.stderr}", fg='red')
        return
    
    # Clean up temporary files
    cleanup_cmd = ["rm", "-rf", temp_dir, backup_path]
    run_proxmox_command(cleanup_cmd, cleanup_cmd, config['use_local_only'], host_details)
    
    click.secho(f"✅ Container {instance_id} restored successfully.", fg='green')
    
    # Start the container
    start_cmd = ["pct", "start", instance_id]
    start_result = run_proxmox_command(start_cmd, start_cmd, config['use_local_only'], host_details)
    
    if start_result.returncode == 0:
        click.secho(f"✅ Container {instance_id} started successfully.", fg='green')
    else:
        click.secho(f"❌ Failed to start container {instance_id}: {start_result.stderr}", fg='red')

@lxc.command('backup-create')
@click.argument('instance_id', required=True)
@click.option('--destination', default="/var/lib/vz/dump", help="Destination directory for the backup.")
@click.option('--region', '--location', default='eu-south-1', help="Region in which to operate.")
@click.option('--az', '--node', default='az1', help="Availability zone (Proxmox host) to target.")
@click.option('--download', is_flag=True, help="Download the backup file to local system.")
@click.option('--compress-level', default=6, type=int, help="Compression level (1-9).")
def create_container_backup(instance_id, destination, region, az, download, compress_level):
    """💾 Create a backup of an LXC container."""
    host_details = config['regions'][region]['availability_zones'][az]
    
    # Create the destination directory if it doesn't exist
    mkdir_cmd = ["mkdir", "-p", destination]
    mkdir_result = run_proxmox_command(mkdir_cmd, mkdir_cmd, config['use_local_only'], host_details)
    
    if mkdir_result.returncode != 0:
        click.secho(f"❌ Failed to create destination directory: {mkdir_result.stderr}", fg='red')
        return
    
    # Create the backup using vzdump
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    backup_filename = f"backup-{instance_id}-{timestamp}.tar.gz"
    backup_path = os.path.join(destination, backup_filename)
    
    click.secho(f"📦 Creating backup of container {instance_id}...", fg='yellow')
    backup_cmd = [
        "vzdump", instance_id, 
        "--compress", str(compress_level),
        "--dumpdir", destination,
        "--mode", "snapshot"
    ]
    
    backup_result = run_proxmox_command(backup_cmd, backup_cmd, config['use_local_only'], host_details)
    
    if backup_result.returncode != 0:
        click.secho(f"❌ Failed to create backup: {backup_result.stderr}", fg='red')
        return
    
    # Get the actual backup filename from the output
    for line in backup_result.stdout.splitlines():
        if "creating archive" in line:
            backup_path = line.split("creating archive '")[1].split("'")[0]
            break
    
    click.secho(f"✅ Backup created successfully: {backup_path}", fg='green')
    
    # Download the backup if requested
    if download:
        click.secho(f"📥 Downloading backup file to current directory...", fg='yellow')
        local_path = os.path.basename(backup_path)
        
        scp_cmd = ["scp", f"{host_details['user']}@{host_details['host']}:{backup_path}", local_path]
        scp_result = subprocess.run(scp_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if scp_result.returncode == 0:
            click.secho(f"✅ Backup downloaded successfully to {os.path.abspath(local_path)}", fg='green')
        else:
            click.secho(f"❌ Failed to download backup: {scp_result.stderr}", fg='red')

@sec.command('scan')
@click.argument('instance_id', required=True)
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
    
    # Ensure required tools are installed
    tools = ["nmap", "lynis"]
    for tool in tools:
        check_tool_cmd = ["pct", "exec", instance_id, "--", "which", tool]
        check_result = run_proxmox_command(check_tool_cmd, check_tool_cmd, config['use_local_only'], host_details)
        
        if check_result.returncode != 0:
            # Try to install the missing tool
            click.secho(f"📦 Installing {tool} in container {instance_id}...", fg='yellow')
            install_cmd = ["pct", "exec", instance_id, "--", "apt-get", "update", "&&", "apt-get", "install", "-y", tool]
            install_result = run_proxmox_command(install_cmd, install_cmd, config['use_local_only'], host_details)
            
            if install_result.returncode != 0:
                click.secho(f"❌ Failed to install {tool}: {install_result.stderr}", fg='red')
                return
    
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
@click.argument('instance_id', required=True)
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
    cpu_limit = None
    memory_limit = None
    
    for line in config_result.stdout.splitlines():
        if line.startswith("cores:"):
            cpu_limit = line.split(":")[1].strip()
        elif line.startswith("memory:"):
            memory_limit = int(line.split(":")[1].strip())
    
    click.secho(f"📌 Resource limits - CPU cores: {cpu_limit}, Memory: {memory_limit} MB", fg='cyan')
    
    # Monitor resource usage over time
    for i in range(count):
        if i > 0:
            time.sleep(interval)
        
        # Get CPU usage
        cpu_cmd = ["pct", "exec", instance_id, "--", "top", "-bn1", "|", "grep", "Cpu"]
        cpu_result = run_proxmox_command(cpu_cmd, cpu_cmd, config['use_local_only'], host_details)
        
        # Get memory usage
        mem_cmd = ["pct", "exec", instance_id, "--", "free", "-m"]
        mem_result = run_proxmox_command(mem_cmd, mem_cmd, config['use_local_only'], host_details)
        
        # Get disk usage
        disk_cmd = ["pct", "exec", instance_id, "--", "df", "-h", "/"]
        disk_result = run_proxmox_command(disk_cmd, disk_cmd, config['use_local_only'], host_details)
        
        # Get running processes count
        proc_cmd = ["pct", "exec", instance_id, "--", "ps", "aux", "|", "wc", "-l"]
        proc_result = run_proxmox_command(proc_cmd, proc_cmd, config['use_local_only'], host_details)
        
        click.secho(f"\n📊 Snapshot {i+1}/{count} at {time.strftime('%H:%M:%S')}", fg='yellow')
        
        # Parse and display CPU usage
        if cpu_result.returncode == 0:
            try:
                cpu_line = cpu_result.stdout.strip()
                if "id," in cpu_line:  # Look for idle percentage
                    # Extract the idle percentage and convert to usage
                    idle_pct = float(cpu_line.split("id,")[0].split()[-1])
                    usage_pct = 100.0 - idle_pct
                    cpu_color = 'green' if usage_pct < 70 else ('yellow' if usage_pct < 90 else 'red')
                    click.secho(f"CPU Usage: {usage_pct:.1f}%", fg=cpu_color)
            except (ValueError, IndexError, KeyError) as e:
                logging.warning(f"Failed to parse CPU usage data: {e}")
                click.secho(f"CPU Usage: Unable to parse", fg='red')
        else:
            click.secho(f"CPU Usage: Unable to retrieve", fg='red')
        
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
                proc_count = int(proc_result.stdout.strip())
                click.secho(f"Running Processes: {proc_count}", fg='cyan')
            except ValueError as e:
                logging.warning(f"Failed to parse process count: {e}")
                click.secho(f"Running Processes: Unable to parse", fg='red')
        else:
            click.secho(f"Running Processes: Unable to retrieve", fg='red')
    
    click.secho(f"\n✅ Resource monitoring for container {instance_id} completed.", fg='green')

@lxc.command('report')
@click.argument('instance_id', required=True)
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
        ps_cmd = ["pct", "exec", instance_id, "--", "ps", "aux", "--sort=-%mem", "|", "head", "-n", "11"]
        ps_result = run_proxmox_command(ps_cmd, ps_cmd, config['use_local_only'], host_details)
        
        if ps_result.returncode == 0:
            proc_lines = ps_result.stdout.strip().split('\n')
            
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
