### lws

**lws** is a Command-Line Interface (CLI) tool designed to manage Proxmox Virtual Environments (VE), LXC containers, and Docker services.

```
Usage: lws.py [OPTIONS] COMMAND [ARGS]...

  🐧 linux (containers) web services

Options:
  --help  Show this message and exit.

Commands:
  app   🐳 Manage Docker on LXC containers.
  conf  🛠️ Manage client configuration.
  lxc   ⚙️ Manage LXC containers.
  px    🌐 Manage Proxmox hosts.
Usage: lws.py conf [OPTIONS] COMMAND [ARGS]...

  🛠️ Manage client configuration.

Options:
  --help  Show this message and exit.

Commands:
  backup    💾 Backup the current configuration to a file.
  show      📄 Show current configuration.
  validate  📄 Validate the current configuration.
Usage: lws.py px [OPTIONS] COMMAND [ARGS]...

  🌐 Manage Proxmox hosts.

Options:
  --help  Show this message and exit.

Commands:
  backup                   💾 Backup configurations from all Proxmox hosts.
  backup-lxc               💾 Create a backup of a specific LXC container.
  cluster-restart          🔄 Restart all cluster services on Proxmox hosts.
  cluster-start            🚀 Start all cluster services on Proxmox hosts.
  cluster-stop             🛑 Stop all cluster services on Proxmox hosts.
  clusters                 🔍 List all clusters in the Proxmox environment.
  exec                     👨🏻‍💻 Execute an arbitrary command into a...
  image-add                📦 Create a template image from an LXC container.
  image-rm                 🗑️ Delete a template image from Proxmox host.
  list                     🌐 List all available Proxmox hosts.
  reboot                   🔄 Reboot the Proxmox host.
  security-group-add       🔐 Create security group on Proxmox host.
  security-group-attach    🔗 Attach security group to an LXC container.
  security-group-detach    🔓 Detach security group from an LXC container.
  security-group-rm        🗑️ Delete a security group on Proxmox host.
  security-group-rule-add  ➕ Add a rule to a existing security group.
  security-group-rule-rm   ➖ Remove a rule from an existing security group.
  security-groups          🔐 List all security groups and their rules in...
  status                   📊 Monitor resource usage of a Proxmox host.
  templates                📄 List all available templates in the Proxmox...
  update                   🔄 Update all Proxmox hosts.
  upload                   💽 Upload template to Proxmox host.
Usage: lws.py lxc [OPTIONS] COMMAND [ARGS]...

  ⚙️ Manage LXC containers.

Options:
  --help  Show this message and exit.

Commands:
  clone           🔄 Clone an LXC container locally or remote.
  exec            👨🏻‍💻 Execute an arbitrary command into an LXC container.
  migrate         🔄 Migrate LXC container between hosts.
  net             🌐 Perform simple network checks on LXC containers.
  reboot          🔄 Reboot running LXC containers.
  run             🛠️ Create and start LXC containers.
  scale           📏 Scale resources LXC containers.
  scale-check     ⚖️ Scaling adjustments for an LXC container.
  service         🔧 Manage a service of LXC containers.
  show            🔍 Describe LXC containers.
  show-info       🌐 Retrieve IP address, hostname, DNS servers, and LXC...
  show-public-ip  🌐 Retrieve the public IP address(es) of a given LXC...
  show-snapshots  🗃️ List all snapshots of an LXC container.
  show-storage    🔍 List storage details for LXC container.
  snapshot-add    📸 Create a snapshot of an LXC container.
  snapshot-rm     🗑️ Delete a snapshot of an LXC container.
  start           🚀 Start stopped LXC containers.
  status          📊 Monitor resources of LXC containers.
  stop            🛑 Stop running LXC containers.
  terminate       💥 Terminate (destroy) LXC containers.
  volume-attach   🔗 Attach a storage volume to an LXC container.
  volume-detach   🔓 Detach a storage volume from an LXC container.
Usage: lws.py app [OPTIONS] COMMAND [ARGS]...

  🐳 Manage Docker on LXC containers.

Options:
  --help  Show this message and exit.

Commands:
  deploy  🚀 Manage apps with Compose on LXC containers.
  list    📦 List Docker containers in an LXC container.
  logs    📄 Fetch Docker logs from an LXC container.
  remove  🗑️ Uninstall Docker and Compose from LXC containers.
  run     🚀 Execute docker run inside an LXC container.
  setup   📦 Install Docker and Compose on an LXC container.
  update  🆕 Update app within an LXC container via Compose.
```

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Configuration](#configuration)
  - [Proxmox Management](#proxmox-management)
  - [LXC Container Management](#lxc-container-management)
  - [Docker Management](#docker-management)
- [Security Considerations](#security-considerations)
- [Best Practices](#best-practices)
- [Contributing](#contributing)
- [Roadmap](#roadmap)
- [License](#license)
- [Acknowledgements](#acknowledgements)

## Introduction

**LWS** was created out of a desire to explore the intersection of Proxmox VE, LXC containers, and Docker management through a unified command-line interface. While LWS offers a range of powerful features, it is important to note that this project is in an early stage and was developed primarily for fun. Therefore, it should be used with caution, especially in production environments.

## Features

### General
- **Comprehensive Logging**: Supports detailed logging in both standard and JSON formats.
- **Flexible Configuration**: YAML-based configuration, enabling easy setup and management.
- **Secure Operations**: Uses SSH for secure interactions, with sensitive information masked in logs.

### Proxmox Management
- **Cluster Management**: Control and monitor Proxmox clusters, including starting, stopping, and restarting services.
- **Resource Monitoring**: Monitor key resources such as CPU, memory, disk, and network across Proxmox hosts.
- **Host Management**: Execute critical operations like rebooting and updating hosts.

### LXC Container Management
- **Lifecycle Operations**: Full lifecycle management of LXC containers, including start, stop, reboot, and termination.
- **Resource Scaling**: Dynamically scale container resources (CPU, memory, storage).
- **Snapshot Management**: Create, delete, and manage snapshots for containers.
- **Security Groups**: Implement security group management, including adding, removing, and managing rules.

### Docker Management
- **Easy Docker Setup**: Simplified installation and setup of Docker and Docker Compose on LXC containers.
- **Application Deployment**: Deploy, update, and manage Docker Compose applications within LXC containers.
- **Container Operations**: Manage Docker containers, including running, stopping, and fetching logs.
- **Auto-start Configuration**: Enable and configure Docker applications to auto-start on container boot.

## Getting Started

### Prerequisites

Before using LWS, ensure you have the following prerequisites:

- **Python 3.6+**: LWS is written in Python, and Python 3.6 or later is required.
- **Proxmox VE**: LWS is designed to work with Proxmox Virtual Environment.
- **SSH Access**: LWS uses SSH to interact with Proxmox hosts and LXC containers.
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

3. **Make LWS Executable**
   ```bash
   chmod +x lws.py
   ```

4. **Shorten it!**
   ```bash
   alias lws='./lws.py'
   ```
   
5. **Verify Installation**
   ```bash
   lws
   ```

It should show this help content:

  ```
  Usage: lws.py [OPTIONS] COMMAND [ARGS]...
  
    🐧 Linux (Containers) Web Services
  
  Options:
    --help  Show this message and exit.
  
  Commands:
    app   🐳 Manage Docker on LXC containers.
    conf  🛠️ Manage client configuration.
    lxc   ⚙️ Manage LXC containers.
    px    🌐 Manage Proxmox hosts.
  ```

### Configuration

LWS is configured using a `config.yaml` file. Here the default one that must be change to fit with your setup. This file defines the environment settings, including regions, instance sizes, network settings, and security credentials. You can easily remap regions as locations and availability zones as a Proxmox hosts.

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
        host: changethis.proxmox-dummy.org   # example: public FQDN (access must be secured)
        user: root
        ssh_password: password
      az2:
        host: 172.23.0.2                     # example: VPN address
        user: root
        ssh_password: password
      az3:
        host: proxmox3.local                 # example: local network
        user: root
        ssh_password: password
      dr:
        host: 192.168.0.4                    # example: LAN address
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

scaling:
  host_cpu:
    max_threshold: 80  # Maximum percentage of host CPU usage before considering a decrease
    min_threshold: 30  # Minimum percentage of host CPU usage before considering an increase
    step: 1  # Base increment or decrement of CPU cores on the host
    scale_up_multiplier: 1.5  # Multiplier applied to step size when scaling up
    scale_down_multiplier: 0.5  # Multiplier applied to step size when scaling down

  lxc_cpu:
    max_threshold: 80  # Maximum percentage of LXC CPU usage before considering a decrease
    min_threshold: 30  # Minimum percentage of LXC CPU usage before considering an increase
    step: 1  # Base increment or decrement of CPU cores in the LXC
    scale_up_multiplier: 1.5  # Multiplier applied to step size when scaling up
    scale_down_multiplier: 0.5  # Multiplier applied to step size when scaling down

  host_memory:
    max_threshold: 70  # Percentage of total memory on the host before considering a decrease
    min_threshold: 40  # Percentage of total memory on the host before considering an increase
    step_mb: 256  # Base amount of memory in MB to increase or decrease
    scale_up_multiplier: 1.25  # Multiplier applied to step size when scaling up
    scale_down_multiplier: 0.75  # Multiplier applied to step size when scaling down

  lxc_memory:
    max_threshold: 70  # Maximum percentage of LXC memory usage before considering a decrease
    min_threshold: 40  # Minimum percentage of LXC memory usage before considering an increase
    step_mb: 256  # Base amount of memory in MB to increase or decrease
    scale_up_multiplier: 1.25  # Multiplier applied to step size when scaling up
    scale_down_multiplier: 0.75  # Multiplier applied to step size when scaling down

  host_storage:
    max_threshold: 85  # Maximum percentage of storage usage on the host before considering a decrease
    min_threshold: 50  # Minimum percentage of storage usage on the host before considering an increase
    step_gb: 10  # Base increment or decrement of storage in GB
    scale_up_multiplier: 1.5  # Multiplier applied to step size when scaling up
    scale_down_multiplier: 0.5  # Multiplier applied to step size when scaling down

  lxc_storage:
    max_threshold: 85  # Maximum percentage of storage usage in the LXC before considering a decrease
    min_threshold: 50  # Minimum percentage of storage usage in the LXC before considering an increase
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

security:
  discovery:
    proxmox_timeout: 2
    lxc_timeout: 2
    discovery_methods: ['ping']
    max_parallel_workers: 10  # Maximum number of parallel workers
    
instance_sizes:
  # Generic
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
  xx-large:
    memory: 16384 
    cpulimit: 8 
    storage: local-lvm:128 

  # General Purpose Instances: balance of compute, memory, and networking resources.
  t2-pico:
    memory: 512  # 1 GB
    cpulimit: 1   # 1 vCPU
    storage: local-lvm:8  # 8 GB of storage
  t2-micro:
    memory: 1024  # 1 GB
    cpulimit: 1   # 1 vCPU
    storage: local-lvm:8  # 8 GB of storage
  t2-small:
    memory: 2048  # 2 GB
    cpulimit: 1   # 1 vCPU
    storage: local-lvm:20  # 20 GB of storage
  t2-medium:
    memory: 4096  # 4 GB
    cpulimit: 2   # 2 vCPUs
    storage: local-lvm:40  # 40 GB of storage
  m5-large:
    memory: 8192  # 8 GB
    cpulimit: 2   # 2 vCPUs
    storage: local-lvm:50  # 50 GB of storage
  m5-xlarge:
    memory: 16384  # 16 GB
    cpulimit: 4    # 4 vCPUs
    storage: local-lvm:100  # 100 GB of storage
  m5-2xlarge:
    memory: 32768  # 32 GB
    cpulimit: 8    # 8 vCPUs
    storage: local-lvm:200  # 200 GB of storage

  # Compute Optimized Instances: applications that benefit from high-performance processors.
  c5-large:
    memory: 4096  # 4 GB
    cpulimit: 2   # 2 vCPUs
    storage: local-lvm:50  # 50 GB of storage
  c5-xlarge:
    memory: 8192  # 8 GB
    cpulimit: 4   # 4 vCPUs
    storage: local-lvm:100  # 100 GB of storage
  c5-2xlarge:
    memory: 16384  # 16 GB
    cpulimit: 8    # 8 vCPUs
    storage: local-lvm:200  # 200 GB of storage
  c5-4xlarge:
    memory: 32768  # 32 GB
    cpulimit: 16   # 16 vCPUs
    storage: local-lvm:400  # 400 GB of storage

  # Memory Optimized Instances: memory-intensive applications like databases.
  r5-large:
    memory: 16384  # 16 GB
    cpulimit: 2    # 2 vCPUs
    storage: local-lvm:100  # 100 GB of storage
  r5-xlarge:
    memory: 32768  # 32 GB
    cpulimit: 4    # 4 vCPUs
    storage: local-lvm:200  # 200 GB of storage
  r5-2xlarge:
    memory: 65536  # 64 GB
    cpulimit: 8    # 8 vCPUs
    storage: local-lvm:400  # 400 GB of storage
  x1e-xlarge:
    memory: 65536  # 64 GB
    cpulimit: 4    # 4 vCPUs
    storage: local-lvm:200  # 200 GB of storage
  x1e-2xlarge:
    memory: 131072  # 128 GB
    cpulimit: 8     # 8 vCPUs
    storage: local-lvm:400  # 400 GB of storage
  x1e-4xlarge:
    memory: 262144  # 256 GB
    cpulimit: 16    # 16 vCPUs
    storage: local-lvm:800  # 800 GB of storage

  # Storage Optimized Instances: high, sequential read and write access to very large datasets on local storage.
  i3-large:
    memory: 15360  # 15 GB
    cpulimit: 2    # 2 vCPUs
    storage: local-lvm:500  # 500 GB of storage
  i3-xlarge:
    memory: 30720  # 30 GB
    cpulimit: 4    # 4 vCPUs
    storage: local-lvm:1000  # 1 TB of storage
  i3-2xlarge:
    memory: 61440  # 60 GB
    cpulimit: 8    # 8 vCPUs
    storage: local-lvm:2000  # 2 TB of storage
  i3-4xlarge:
    memory: 122880  # 120 GB
    cpulimit: 16    # 16 vCPUs
    storage: local-lvm:4000  # 4 TB of storage

  # GPU Instances: machine learning, graphics processing, or general-purpose GPU computing.
  p3-large:
    memory: 15360  # 15 GB
    cpulimit: 2    # 2 vCPUs
    storage: local-lvm:100  # 100 GB of storage
  p3-xlarge:
    memory: 30720  # 30 GB
    cpulimit: 4    # 4 vCPUs
    storage: local-lvm:200  # 200 GB of storage
  p3-2xlarge:
    memory: 61440  # 60 GB
    cpulimit: 8    # 8 vCPUs
    storage: local-lvm:400  # 400 GB of storage
  p3-8xlarge:
    memory: 245760  # 240 GB
    cpulimit: 32    # 32 vCPUs
    storage: local-lvm:1600  # 1.6 TB of storage
```

**Note**: Ensure your `config.yaml` file is secured and does not expose sensitive information. Use tools like `ansible-vault` or environment variables to manage sensitive data securely.

> [!TIP]
> **Debugging**
> You can change the log level to `DEBUG` in the `setup_logging` function at the beginning of the `lws.py` file (default is `ERROR`).

## Security Considerations

Given that LWS involves SSH connections and sensitive operations, it's crucial to:

- **Protect Your Configuration**: Ensure your `config.yaml` file is not exposed and is secured using appropriate tools.
- **Use in Non-Production Environments**: As LWS is in its early stages, it is recommended to use it only in test or development environments.
- **Use over Secured Connections**: Always protect the management communications with a VPN like OpenVPN or Wireguard.

## Best Practices

- **Regular Backups**: Always back up your configuration and important data regularly.
- **Testing Before Use**: Thoroughly test LWS commands in a non-production environment before applying them to critical systems.
- **Keep Updated**: Keep your LWS installation and dependencies updated to benefit from the latest features and fixes.

## Contributing

LWS is an open-source project developed for fun and learning. Contributions are welcome! Feel free to submit issues, feature requests, or pull requests.

### How to Contribute

1. **Fork the Repository**
2. **Create a Branch**
   ```bash
   git checkout -b feature-branch
   ```
3. **Make Changes**
4. **Submit a Pull Request**

## Roadmap

LWS is still in its infancy. Planned features and improvements include:

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
> **Disclaimer**: LWS is a project created for fun and exploration. It is not intended for production use, and users should exercise caution when using it on live systems. Always test thoroughly in a non-production environment.

