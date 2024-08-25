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
regions:
  eu-south-1:
    availability_zones:
      az1:
        host: proxmox-host-1
        user: root
        ssh_password: your-password
      az2:
        host: proxmox-host-2
        user: root
        ssh_password: your-password
instance_sizes:
  small:
    memory: 1024
    cpulimit: 1
    storage: 16G
  medium:
    memory: 2048
    cpulimit: 2
    storage: 32G
default_network: vmbr0
default_storage: local-lvm
use_local_only: false
start_vmid: 10000
minimum_resources:
  cores: 1
  memory_mb: 512
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
- **Docker**: For making container management simpler and more efficient.
- **Open Source Community**: For the tools and libraries that made this project possible.

---

> [!WARNING]
> **Disclaimer**: LWS is a project created for fun and exploration. It is not intended for production use, and users should exercise caution when using it on live systems. Always test thoroughly in a non-production environment.

