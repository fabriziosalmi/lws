"""
Unit tests for lws_core/config.py

Tests cover:
- Configuration loading from YAML files
- Configuration validation
- Error handling for missing/invalid configurations
- Sensitive information masking
"""

import os
import pytest
import yaml
import tempfile
from unittest.mock import patch, mock_open, MagicMock
from pathlib import Path

# Import the functions to test
from lws_core.config import (
    load_config,
    validate_config,
    mask_sensitive_info,
    _ensure_config_loaded
)


class TestLoadConfig:
    """Tests for the load_config function."""

    @pytest.mark.unit
    def test_load_valid_config(self, tmp_path, sample_config, monkeypatch):
        """Test loading a valid configuration file."""
        # Create a config.yaml in tmp directory
        config_path = tmp_path / "config.yaml"
        with open(config_path, 'w') as f:
            yaml.dump(sample_config, f)
        
        # Change to tmp directory
        monkeypatch.chdir(tmp_path)
        
        # Load config
        config = load_config()
        
        # Assertions
        assert config is not None
        assert isinstance(config, dict)
        assert 'regions' in config
        assert 'instance_sizes' in config
        assert config['default_storage'] == 'local-lvm'

    @pytest.mark.unit
    def test_load_config_file_not_found(self, tmp_path, monkeypatch):
        """Test error handling when config.yaml is missing."""
        # Change to empty tmp directory
        monkeypatch.chdir(tmp_path)
        
        # Should raise FileNotFoundError
        with pytest.raises(FileNotFoundError) as exc_info:
            load_config()
        
        assert "config.yaml" in str(exc_info.value).lower()

    @pytest.mark.unit
    def test_load_config_invalid_yaml(self, tmp_path, monkeypatch):
        """Test error handling for invalid YAML syntax."""
        # Create invalid YAML file
        config_path = tmp_path / "config.yaml"
        with open(config_path, 'w') as f:
            f.write("invalid: yaml: syntax: [\n")
        
        monkeypatch.chdir(tmp_path)
        
        # Should raise YAMLError
        with pytest.raises(yaml.YAMLError):
            load_config()

    @pytest.mark.unit
    def test_load_config_invalid_structure(self, tmp_path, monkeypatch):
        """Test error handling for invalid configuration structure."""
        # Create config with missing required keys
        invalid_config = {'regions': {}}  # Missing instance_sizes
        config_path = tmp_path / "config.yaml"
        with open(config_path, 'w') as f:
            yaml.dump(invalid_config, f)
        
        monkeypatch.chdir(tmp_path)
        
        # Should raise ValueError
        with pytest.raises(ValueError) as exc_info:
            load_config()
        
        assert "instance_sizes" in str(exc_info.value)


class TestValidateConfig:
    """Tests for the validate_config function."""

    @pytest.mark.unit
    def test_validate_valid_config(self, sample_config):
        """Test validation of a valid configuration."""
        # Should not raise any exception
        validate_config(sample_config)

    @pytest.mark.unit
    def test_validate_config_not_dict(self):
        """Test validation fails when config is not a dictionary."""
        with pytest.raises(ValueError) as exc_info:
            validate_config("not a dict")
        
        assert "dictionary" in str(exc_info.value).lower()

    @pytest.mark.unit
    def test_validate_config_missing_regions(self, sample_config):
        """Test validation fails when regions key is missing."""
        config = sample_config.copy()
        del config['regions']
        
        with pytest.raises(ValueError) as exc_info:
            validate_config(config)
        
        assert "regions" in str(exc_info.value).lower()

    @pytest.mark.unit
    def test_validate_config_missing_instance_sizes(self, sample_config):
        """Test validation fails when instance_sizes key is missing."""
        config = sample_config.copy()
        del config['instance_sizes']
        
        with pytest.raises(ValueError) as exc_info:
            validate_config(config)
        
        assert "instance_sizes" in str(exc_info.value).lower()

    @pytest.mark.unit
    def test_validate_config_empty_regions(self, sample_config):
        """Test validation fails when regions is empty."""
        config = sample_config.copy()
        config['regions'] = {}
        
        with pytest.raises(ValueError) as exc_info:
            validate_config(config)
        
        assert "regions" in str(exc_info.value).lower()

    @pytest.mark.unit
    def test_validate_config_invalid_regions_type(self, sample_config):
        """Test validation fails when regions is not a dict."""
        config = sample_config.copy()
        config['regions'] = []
        
        with pytest.raises(ValueError) as exc_info:
            validate_config(config)
        
        assert "regions" in str(exc_info.value).lower()

    @pytest.mark.unit
    def test_validate_config_missing_availability_zones(self, sample_config):
        """Test validation fails when availability_zones is missing."""
        config = sample_config.copy()
        config['regions']['eu-south-1'] = {}
        
        with pytest.raises(ValueError) as exc_info:
            validate_config(config)
        
        assert "availability_zones" in str(exc_info.value).lower()

    @pytest.mark.unit
    def test_validate_config_missing_az_host(self, sample_config):
        """Test validation fails when AZ host is missing."""
        config = sample_config.copy()
        del config['regions']['eu-south-1']['availability_zones']['az1']['host']
        
        with pytest.raises(ValueError) as exc_info:
            validate_config(config)
        
        assert "host" in str(exc_info.value).lower()
        assert "az1" in str(exc_info.value)

    @pytest.mark.unit
    def test_validate_config_missing_az_user(self, sample_config):
        """Test validation fails when AZ user is missing."""
        config = sample_config.copy()
        del config['regions']['eu-south-1']['availability_zones']['az1']['user']
        
        with pytest.raises(ValueError) as exc_info:
            validate_config(config)
        
        assert "user" in str(exc_info.value).lower()

    @pytest.mark.unit
    def test_validate_config_missing_az_password(self, sample_config):
        """Test validation fails when AZ password is missing."""
        config = sample_config.copy()
        del config['regions']['eu-south-1']['availability_zones']['az1']['ssh_password']
        
        with pytest.raises(ValueError) as exc_info:
            validate_config(config)
        
        assert "ssh_password" in str(exc_info.value).lower()

    @pytest.mark.unit
    def test_validate_config_missing_instance_size_memory(self, sample_config):
        """Test validation fails when instance size memory is missing."""
        config = sample_config.copy()
        del config['instance_sizes']['micro']['memory']
        
        with pytest.raises(ValueError) as exc_info:
            validate_config(config)
        
        assert "memory" in str(exc_info.value).lower()
        assert "micro" in str(exc_info.value)

    @pytest.mark.unit
    def test_validate_config_missing_instance_size_cpulimit(self, sample_config):
        """Test validation fails when instance size cpulimit is missing."""
        config = sample_config.copy()
        del config['instance_sizes']['micro']['cpulimit']
        
        with pytest.raises(ValueError) as exc_info:
            validate_config(config)
        
        assert "cpulimit" in str(exc_info.value).lower()

    @pytest.mark.unit
    def test_validate_config_missing_instance_size_storage(self, sample_config):
        """Test validation fails when instance size storage is missing."""
        config = sample_config.copy()
        del config['instance_sizes']['micro']['storage']
        
        with pytest.raises(ValueError) as exc_info:
            validate_config(config)
        
        assert "storage" in str(exc_info.value).lower()

    @pytest.mark.unit
    def test_validate_config_empty_instance_sizes(self, sample_config):
        """Test validation fails when instance_sizes is empty."""
        config = sample_config.copy()
        config['instance_sizes'] = {}
        
        with pytest.raises(ValueError) as exc_info:
            validate_config(config)
        
        assert "instance_sizes" in str(exc_info.value).lower()


class TestMaskSensitiveInfo:
    """Tests for the mask_sensitive_info function."""

    @pytest.mark.unit
    def test_mask_password_field(self):
        """Test that password fields are masked."""
        config = {'ssh_password': 'secret123', 'user': 'root'}
        masked = mask_sensitive_info(config)
        
        assert masked['ssh_password'] == '***'
        assert masked['user'] == 'root'

    @pytest.mark.unit
    def test_mask_secret_field(self):
        """Test that secret fields are masked."""
        config = {'api_secret': 'secret123', 'api_host': 'example.com'}
        masked = mask_sensitive_info(config)
        
        assert masked['api_secret'] == '***'
        assert masked['api_host'] == 'example.com'

    @pytest.mark.unit
    def test_mask_key_field(self):
        """Test that key fields are masked."""
        config = {'api_key': 'key123', 'api_host': 'example.com'}
        masked = mask_sensitive_info(config)
        
        assert masked['api_key'] == '***'
        assert masked['api_host'] == 'example.com'

    @pytest.mark.unit
    def test_mask_nested_dict(self):
        """Test masking in nested dictionaries."""
        config = {
            'regions': {
                'eu-south-1': {
                    'ssh_password': 'secret',
                    'host': 'example.com'
                }
            }
        }
        masked = mask_sensitive_info(config)
        
        assert masked['regions']['eu-south-1']['ssh_password'] == '***'
        assert masked['regions']['eu-south-1']['host'] == 'example.com'

    @pytest.mark.unit
    def test_mask_list_of_dicts(self):
        """Test masking in lists containing dictionaries."""
        config = {
            'servers': [
                {'password': 'secret1', 'name': 'server1'},
                {'password': 'secret2', 'name': 'server2'}
            ]
        }
        masked = mask_sensitive_info(config)
        
        assert masked['servers'][0]['password'] == '***'
        assert masked['servers'][0]['name'] == 'server1'
        assert masked['servers'][1]['password'] == '***'
        assert masked['servers'][1]['name'] == 'server2'

    @pytest.mark.unit
    def test_mask_case_insensitive(self):
        """Test that masking is case-insensitive."""
        config = {
            'Password': 'secret1',
            'API_KEY': 'secret2',
            'Secret': 'secret3'
        }
        masked = mask_sensitive_info(config)
        
        assert masked['Password'] == '***'
        assert masked['API_KEY'] == '***'
        assert masked['Secret'] == '***'

    @pytest.mark.unit
    def test_mask_preserves_non_sensitive(self):
        """Test that non-sensitive data is preserved."""
        config = {
            'host': 'example.com',
            'port': 8080,
            'enabled': True,
            'tags': ['web', 'api']
        }
        masked = mask_sensitive_info(config)
        
        assert masked['host'] == 'example.com'
        assert masked['port'] == 8080
        assert masked['enabled'] is True
        assert masked['tags'] == ['web', 'api']

    @pytest.mark.unit
    def test_mask_primitive_types(self):
        """Test masking with primitive types."""
        assert mask_sensitive_info("string") == "string"
        assert mask_sensitive_info(123) == 123
        assert mask_sensitive_info(True) is True
        assert mask_sensitive_info(None) is None


class TestEnsureConfigLoaded:
    """Tests for the _ensure_config_loaded function."""

    @pytest.mark.unit
    def test_ensure_config_loaded(self):
        """Test that _ensure_config_loaded returns the config."""
        result = _ensure_config_loaded()
        assert result is not None
        assert isinstance(result, dict)


class TestConfigModuleImport:
    """Tests for module-level configuration loading."""

    @pytest.mark.unit
    def test_config_loaded_on_import(self):
        """Test that config is available after module import."""
        from lws_core import config
        
        # config is the dict directly in this implementation
        assert config is not None
        assert isinstance(config, dict)

    @pytest.mark.unit
    def test_fallback_config_structure(self):
        """Test that fallback config has the expected structure."""
        from lws_core import config
        
        # The config should have the basic required keys
        assert config is not None
        assert isinstance(config, dict)
        assert 'regions' in config
        assert 'instance_sizes' in config
