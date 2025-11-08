"""
Configuration Module

This module handles loading and validating the LWS configuration from config.yaml.
"""

import os
import logging
import yaml
import click


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


# Load configuration immediately when module is imported
# This is safe because config.py doesn't import from other lws_core modules
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

def _ensure_config_loaded():
    """Dummy function for backwards compatibility."""
    return config
