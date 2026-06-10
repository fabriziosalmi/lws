"""
Logging Setup Module

This module provides logging configuration for the LWS tool, including
both standard and JSON logging formats.
"""

import os
import json
import logging
import logging.config


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
    # Extract only the filename to avoid leaking the current working directory in logs
    json_log_filename = os.path.basename(json_log_file) if json_log_file else "not configured"
    logging.debug("🔎 Logging to console, and additional JSON logging to file %s", json_log_filename)


# Initialize logging when module is imported
log_file_path = os.path.join(os.getcwd(), 'lws.log')  # Standard log file path
json_log_file_path = os.path.join(os.getcwd(), 'lws.json.log')  # JSON log file path

# Set up logging: standard logging to console and file, JSON logging to a separate file
setup_logging(log_level=logging.ERROR, log_file=log_file_path, json_log_file=json_log_file_path)
