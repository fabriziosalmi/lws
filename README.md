# lws

**lws** is a Command-Line Interface (CLI) tool designed to streamline the management of Proxmox Virtual Environments (VE), LXC containers, and Docker services through a unified, efficient interface.

[![asciicast](https://asciinema.org/a/8rE7H67VjQ15HQ9KtsJVMRR4O.svg)](https://asciinema.org/a/8rE7H67VjQ15HQ9KtsJVMRR4O)

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Configuration](#configuration)
- [Usage](#usage)
  - [Proxmox Management](#proxmox-management)
  - [LXC Container Management](#lxc-container-management)
  - [Docker Management](#docker-management)
  - [Client Configuration Management](#client-configuration-management)
  - [Managing Instance Profiles](#managing-instance-profiles)
  - [Managing Security Settings](#managing-security-settings)
  - [Managing Scaling Thresholds and Triggers](#managing-scaling-thresholds-and-triggers)
- [Security Considerations](#security-considerations)
- [Best Practices](#best-practices)
- [Contributing](#contributing)
- [Roadmap](#roadmap)
- [License](#license)
- [Acknowledgements](#acknowledgements)

## Introduction

**lws** was created to simplify and unify the management of Proxmox VE, LXC containers, and Docker services using a single command-line tool. Although powerful, **lws** is still in its early stages and was developed primarily for learning and exploration. It should be used with caution, especially in production environments.

## Features

### General
- **Comprehensive Logging**: Supports detailed logging in both standard and JSON formats.
- **Flexible Configuration**: YAML-based configuration for easy setup and management.
- **Secure Operations**: Uses SSH for secure communications, with sensitive information masked in logs.

### Proxmox Management
- **Cluster Management**: Control and monitor Proxmox clusters, including service lifecycle operations.
- **Resource Monitoring**: Monitor CPU, memory, disk, and network usage across Proxmox hosts.
- **Host Operations**: Execute essential operations like rebooting and updating hosts.

### LXC Container Management
- **Lifecycle Management**: Start, stop, reboot, and terminate LXC containers with ease.
- **Resource ng**: Dynamically adjust container resources (CPU, memory, storage).
- **Snapshot Management**: Create, delete, and manage snapshots for containers.
- **Security Group Management**: Implement and manage security groups and rules.

### Docker Management
- **Easy Setup**: Simplified installation and setup of Docker and Docker Compose on LXC containers.
- **Application Deployment**: Deploy, update, and manage Docker Compose applications.
- **Container Operations**: Manage Docker containers, including running, stopping, and fetching logs.
- **Auto-start Configuration**: Configure Docker apps to auto-start on container boot.

## Getting Started

### Prerequisites

Before using **lws**, ensure you have the following:

- **Python 3.6+**: Required to run **lws**.
- **Proxmox VE**: **lws** is designed to work with Proxmox Virtual Environment.
- **SSH Access**: **lws** uses SSH to interact with Proxmox hosts and LXC containers.
- **Pip**: Python's package installer.

### Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/fabriziosalmi/lws.git
   cd lws
   ```

2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Make lws Executable**
   ```bash
   chmod +x lws.py
   ```

4. **Create a Shortcut**
   ```bash
   alias lws='./lws.py'
   ```

5. **Verify Installation**
   ```bash
   lws --help
   ```

### Configuration

**lws** is configured using a `config.yaml` file. This file defines your environment settings, including regions, availability zones (AZs), instance sizes, network settings, security credentials, and ng parameters.

#### Example `config.yaml`

```yaml
use_local_only: false
start_vmid: 10000
default_storage: local-lvm
default_network: vmbr0
minimum_resources:
  cores: 1
  memory_mb: 512
regions:  
  eu-south-1:
    availability_zones:
      az1:
        host: proxmox1.public-fqdn.com     # example: public FQDN (access must be secured)
        user: root
        ssh_password: password
      az2:
        host: 172.23.0.2                   # example: VPN address
        user: root
        ssh_password: password
      az3:
        host: proxmox3.local               # example: local network
        user: root
        ssh_password: password
      az4:
        host: 192.168.0.4                  # example: LAN address
        user: root
        ssh_password: password

  eu-central-1:
    availability_zones:
      pve-rhine:
        host: pve-rhine.mydomain.com
        user: root
        ssh_password: password
      pve-alps:
        host: pve-alps.mydomain.com
        user: root
        ssh_password: password
```

> [!IMPORTANT]
> Secure your `config.yaml` file to prevent exposure of sensitive information. Consider using tools like `ansible-vault` or environment variables for managing sensitive data securely.

## Usage

**lws** offers various commands for managing Proxmox VE, LXC containers, and Docker services. Below are detailed examples for each command set.

### Proxmox Management

Manage your Proxmox hosts and clusters with these commands. Use the `--region` and `--az` options to target specific regions and availability zones.

#### List all Proxmox hosts
```bash
lws px list
```
> [!TIP]
> Use the `list` command to quickly verify which Proxmox hosts are available for management in specific regions.

#### Backup configurations of a Proxmox host in a region
```bash
lws px backup --region eu-south-1
```

#### Backup a specific LXC container
```bash
lws px backup-lxc 101 --region eu-south-1 --az az1
```

#### Restart all cluster services in a specific AZ
```bash
lws px cluster-restart --region eu-central-1 --az pve-rhine
```

#### Create a template image from an LXC container
```bash
lws px image-add 101 --region eu-central-1 --az pve-alps --template-name "my-template"
```

#### Delete a template image from a specific AZ
```bash
lws px image-rm --region eu-central-1 --az pve-rhine --template-name "my-template"
```

> [!WARNING]
> Be careful when deleting images, as this action is irreversible and can result in data loss.

#### Monitor resource usage of a Proxmox host
```bash
lws px status --region eu-south-1 --az az3
```

#### Reboot a Proxmox host in a specific AZ
```bash
lws px reboot --region eu-south-1 --az az2
```

> [!TIP]
> Rebooting a Proxmox host will temporarily affect all services running on it. Ensure you plan this operation during maintenance windows.

### LXC Container Management

Manage LXC containers with these versatile commands. Just specify the container ID and, optionally, the region and AZ.

#### Start an LXC container
```bash
lws lxc start 101 --region eu-central-1 --az pve-alps
```

#### Stop a running LXC container
```bash
lws lxc stop 101 --region eu-central-1 --az pve-alps
```

#### Reboot an LXC container
```bash
lws lxc reboot 101 --region eu-central-1 --az pve-alps
```

#### Terminate (destroy) an LXC container
```bash
lws lxc terminate 101 --region eu-central-1 --az pve-alps
```

> [!WARNING]
> The `terminate` command permanently deletes the LXC container. Use this with caution.

#### Clone an LXC container locally or remotely
```bash
lws lxc clone 101 102 --region eu-central-1 --az pve-alps
```

#### Migrate an LXC container between AZs
```bash
lws lxc migrate 101 --region eu-central-1 --source-az pve-rhine --target-az pve-alps
```

#### Execute a command inside an LXC container
```bash
lws lxc exec 101 --region eu-central-1 --az pve-alps --command "apt-get update"
```

#### Scale resources of an LXC container
```bash
lws lxc scale 101 --region eu-central-1 --az pve-alps --cpu 4 --memory 8192
```

> [!TIP]
> ng resources can help optimize performance but may also increase resource consumption on your host

.

#### Create a snapshot of an LXC container
```bash
lws lxc snapshot-add 101 --region eu-central-1 --az pve-alps --name "pre-update"
```

#### List all snapshots of an LXC container
```bash
lws lxc show-snapshots 101 --region eu-central-1 --az pve-alps
```

#### Attach a storage volume to an LXC container
```bash
lws lxc volume-attach 101 --region eu-central-1 --az pve-alps --volume "my-volume"
```

#### Retrieve the public IP address of an LXC container
```bash
lws lxc show-public-ip 101 --region eu-central-1 --az pve-alps
```

### Docker Management

Manage Docker services within LXC containers using these commands. Specify the container ID along with the region and AZ.

#### Install Docker and Compose on an LXC container
```bash
lws app setup 101 --region eu-south-1 --az az1
```

#### Deploy a Docker Compose application
```bash
lws app deploy 101 --region eu-south-1 --az az1 --compose-file docker-compose.yml
```

> [!TIP]
> Ensure your `docker-compose.yml` file is correctly configured before deployment to avoid runtime issues.

#### List Docker containers in an LXC container
```bash
lws app list 101 --region eu-south-1 --az az1
```

#### Fetch Docker logs from an LXC container
```bash
lws app logs 101 --region eu-south-1 --az az1 --container "my-container"
```

#### Update an app within an LXC container via Compose
```bash
lws app update 101 --region eu-south-1 --az az1
```

> [!TIP]
> Regularly updating your Docker containers ensures they are running the latest versions with security patches.

### Client Configuration Management

Manage your **lws** client configurations with these commands.

#### Backup the current configuration to a file
```bash
lws conf backup --output backup-config.yaml
```

#### Show the current configuration
```bash
lws conf show
```

#### Validate the current configuration
```bash
lws conf validate
```

> [!IMPORTANT]
> Always validate your configuration after making changes to avoid runtime errors.

### Managing Instance Profiles

Instance profiles define the resource allocations (memory, CPU, storage) for different types of workloads. These can be customized for specific applications, ranging from general-purpose to specialized setups.

#### Example Instance Profiles

```yaml
instance_sizes:
  micro:
    memory: 512 
    cpulimit: 1 
    storage: local-lvm:4  
  small:
    memory: 1024 
    cpulimit: 1 
    storage: local-lvm:8   
  mid:
    memory: 2048 
    cpulimit: 2
    storage: local-lvm:16  
  large:
    memory: 4096 
    cpulimit: 2
    storage: local-lvm:32   
  x-large:
    memory: 8192 
    cpulimit: 4 
    storage: local-lvm:64   
  
  # Specialized instance profiles for specific applications
  lws-postgres:
    memory: 4096  # 4 GB
    cpulimit: 2   # 2 vCPUs
    storage: local-lvm:40  # 40 GB of storage
    # Example: PostgreSQL for relational database.

  lws-redis:
    memory: 2048  # 2 GB
    cpulimit: 1   # 1 vCPU
    storage: local-lvm:10  # 10 GB of storage
    # Example: Redis for in-memory caching.
```

> [!TIP]
> Customize instance profiles based on the specific requirements of your applications. For example, databases like PostgreSQL may need more memory and CPU, while caching solutions like Redis can operate efficiently with fewer resources.

### Managing Security Settings

Security settings within **lws** control aspects like SSH timeouts, discovery methods, and the number of parallel workers. These settings help secure your environment while ensuring efficient operations.

#### Example Security Configuration

```yaml
security:
  discovery:
    proxmox_timeout: 2  # Timeout in seconds for Proxmox host discovery
    lxc_timeout: 2  # Timeout in seconds for LXC container discovery
    discovery_methods: ['ping']  # Methods used for discovering resources
    max_parallel_workers: 10  # Maximum number of parallel workers during discovery
```

> [!TIP]
> Adjust the `max_parallel_workers` setting to optimize discovery operations based on your infrastructure's size and complexity.

### Managing Scaling Thresholds and Triggers

Scaling thresholds and triggers allow **lws** to automatically adjust resources (CPU, memory, storage) for LXC containers based on defined conditions met on both the Proxmox host and the LXC container. This feature ensures optimal performance while preventing resource exhaustion.

#### Example Scaling Configuration

```yaml
scaling:
  host_cpu:
    max_threshold: 80  # Maximum percentage of host CPU usage before scaling down
    min_threshold: 30  # Minimum percentage of host CPU usage before scaling up
    step: 1  # Base increment or decrement of CPU cores on the host
    scale_up_multiplier: 1.5  # Multiplier applied to step size when scaling up
    scale_down_multiplier: 0.5  # Multiplier applied to step size when scaling down

  lxc_cpu:
    max_threshold: 80  # Maximum percentage of LXC CPU usage before scaling down
    min_threshold: 30  # Minimum percentage of LXC CPU usage before scaling up
    step: 1  # Base increment or decrement of CPU cores in the LXC
    scale_up_multiplier: 1.5  # Multiplier applied to step size when scaling up
    scale_down_multiplier: 0.5  # Multiplier applied to step size when scaling down

  host_memory:
    max_threshold: 70  # Percentage of total memory on the host before scaling down
    min_threshold: 40  # Percentage of total memory on the host before scaling up
    step_mb: 256  # Base amount of memory in MB to increase or decrease
    scale_up_multiplier: 1.25  # Multiplier applied to step size when scaling up
    scale_down_multiplier: 0.75  # Multiplier applied to step size when scaling down

  lxc_memory:
    max_threshold: 70  # Maximum percentage of LXC memory usage before scaling down
    min_threshold: 40  # Minimum percentage of LXC memory usage before scaling up
    step_mb: 256  # Base amount of memory in MB to increase or decrease
    scale_up_multiplier: 1.25  # Multiplier applied to step size when scaling up
    scale_down_multiplier: 0.75  # Multiplier applied to step size when scaling down

  host_storage:
    max_threshold: 85  # Maximum percentage of storage usage on the host before scaling down
    min_threshold: 50  # Minimum percentage of storage usage on the host before scaling up
    step_gb: 10  # Base increment or decrement of storage in GB
    scale_up_multiplier: 1.5  # Multiplier applied to step size when scaling up
    scale_down_multiplier: 0.5  # Multiplier applied to step size when scaling down

  lxc_storage:
    max_threshold: 85  # Maximum percentage of storage usage in the LXC before scaling down
    min_threshold: 50  # Minimum percentage of storage usage in the LXC before scaling up
    step_gb: 10  # Base increment or decrement of storage in GB
    scale_up_multiplier: 1.5  # Multiplier applied to step size when scaling up
    scale_down_multiplier: 0.5  # Multiplier applied to step size when scaling down

  limits:
    min_memory_mb: 512  # Minimum allowed memory for any LXC container
    max_memory_mb: 32768  # Maximum allowed memory for any LXC container
    min_cpu_cores: 1  # Minimum allowed CPU cores for any LXC container
    max_cpu_cores: 16  # Maximum allowed CPU cores for any LXC container
    min_storage_gb: 10  # Minimum allowed storage for any LXC container
    max_storage_gb: 1024  # Maximum allowed storage for any LXC container

  general:
    scaling_interval: 5  # Interval in minutes to check for resource adjustments
    notify_user: true  # Notify user via CLI output when scaling adjustments are made
    dry_run: false  # If true, simulate scaling adjustments without applying changes
    scaling_log_level: DEBUG  # Log level for scaling operations (DEBUG, INFO, WARN, ERROR)
    use_custom_scaling_algorithms: false  # Enable if custom scaling algorithms are implemented
```

> [!TIP]
> Use `notify_user: true` to get immediate feedback on scaling adjustments, which is especially useful in dynamic environments.

> [!WARNING]
> Be cautious when setting the `dry_run` option to `false`, as real scaling adjustments will be applied. Ensure your thresholds and multipliers are well-tested before applying them in production.

## Security Considerations

Given that **lws** involves sensitive operations and SSH connections, it's important to:

- **Protect Your Configuration**: Ensure your `config.yaml` file is secure.
- **Use in Non-Production Environments**: As **lws** is in its early stages, it's

 safer to use it in test or development environments.
- **Use Secured Connections**: Always protect management communications with a VPN or similar secured connection.

> [!WARNING]
> Misconfigured SSH or insecure usage can lead to unauthorized access to your systems. Always follow best practices for SSH security.

## Best Practices

- **Regular Backups**: Regularly back up your configuration and important data.
- **Testing Before Use**: Thoroughly test **lws** commands in a non-production environment before applying them to critical systems.
- **Keep Updated**: Keep your **lws** installation and dependencies updated to benefit from the latest features and fixes.

## Contributing

**lws** is an open-source project developed for fun and learning. Contributions are welcome! Feel free to submit issues, feature requests, or pull requests.

### How to Contribute

1. **Fork the Repository**
2. **Create a Branch**
   ```bash
   git checkout -b feature-branch
   ```
3. **Make Changes**
4. **Submit a Pull Request**

> [!TIP]
> Include clear commit messages and documentation with your pull requests to make the review process smoother.

## Roadmap

**lws** is still in its infancy. Planned features and improvements include:

- **Improved Error Handling**: More robust error handling and feedback mechanisms.
- **Additional Commands**: Expanding the set of management commands.
- **User Interface Improvements**: Enhanced user experience with better output formatting and additional CLI options.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

## Acknowledgements

- **Proxmox VE**: The powerful virtualization platform that inspired this project.
- **LXC**: For making Linux containers a reality.
- **Docker**: For making container management simpler and more efficient.
- **Open Source Community**: For the tools and libraries that made this project possible.

---

> [!WARNING]
> **Disclaimer**: **lws** is a project created for fun and exploration. It is not intended for production use, and users should exercise caution when using it on live systems. Always test thoroughly in a non-production environment.
