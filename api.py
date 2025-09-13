#!/usr/bin/env python3

"""
API wrapper for LWS (Linux Web Services)
This module provides a REST API interface to the functionality available in lws.py
"""

import os
import json
import subprocess
import yaml
import logging
import sys
import re
from functools import wraps
import shlex  # Import shlex for safe command splitting

# Import Flask and related extensions
from flask import Flask, request, jsonify, send_from_directory, url_for, abort  # Added abort
from flask_cors import CORS
from werkzeug.exceptions import HTTPException
# Import Swagger UI
from flask_swagger_ui import get_swaggerui_blueprint

# Create Flask application
app = Flask(__name__)
# --- Configuration Loading ---
def load_api_config():
    """Loads configuration from config.yaml."""
    try:
        config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
        if not os.path.exists(config_path):
            logging.error(f"Configuration file not found at {config_path}")
            return None
        with open(config_path, 'r') as file:
            config = yaml.safe_load(file)
        return config
    except Exception as e:
        logging.error(f"Error loading configuration: {e}")
        return None

config = load_api_config()
if not config:
    logging.critical("Failed to load configuration. Exiting.")
    sys.exit(1)

API_KEY = config.get('api_key', None)
API_CONFIG = config.get('api', {})
LWS_SCRIPT_PATH = os.path.join(os.path.dirname(__file__), 'lws.py') # Path to lws.py

# --- CORS Configuration ---
allowed_origins = API_CONFIG.get('allowed_origins', '*') # Default to allow all if not specified
# If allowing specific origins, consider adding 'null' for file:// access during development
# Example: allowed_origins = ["http://localhost:8000", "null"]
CORS(app, origins=allowed_origins) # Apply CORS settings

if not API_KEY:
    logging.warning("API key is not set in config.yaml. API will be insecure.")

# Configure logging
log_level_str = API_CONFIG.get('log_level', 'INFO').upper()
log_level = getattr(logging, log_level_str, logging.INFO)

logging.basicConfig(
    level=log_level,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("api.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logging.info("API starting up...")
logging.info(f"Log level set to {log_level_str}")


# --- Input Validation Functions ---
def validate_instance_id(instance_id):
    """Validate instance ID to prevent command injection."""
    if not isinstance(instance_id, (str, int)):
        return False
    instance_str = str(instance_id)
    return re.match(r'^[0-9]+$', instance_str) is not None


def sanitize_input(input_value, max_length=255):
    """Sanitize input to prevent injection attacks."""
    if not isinstance(input_value, str):
        return None
    # Remove dangerous characters
    sanitized = re.sub(r'[;&|`$(){}[\]<>]', '', input_value)
    return sanitized[:max_length] if len(sanitized) <= max_length else None


# --- Authentication ---
def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if API_KEY: # Only enforce if API_KEY is set
            provided_key = request.headers.get('X-API-Key')
            if not provided_key or provided_key != API_KEY:
                logging.warning(f"Unauthorized access attempt from {request.remote_addr}")
                abort(401, description="Unauthorized: Invalid or missing API key.")
        return f(*args, **kwargs)
    return decorated_function

# --- Error Handling ---
@app.errorhandler(HTTPException)
def handle_exception(e):
    """Return JSON instead of HTML for HTTP errors."""
    response = e.get_response()
    response.data = json.dumps({
        "code": e.code,
        "name": e.name,
        "description": e.description,
    })
    response.content_type = "application/json"
    logging.error(f"HTTP Error {e.code} {e.name}: {e.description} for {request.url}")
    return response

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Not Found", "message": "The requested URL was not found on the server."}), 404

@app.errorhandler(Exception)
def handle_generic_exception(e):
    """Handle unexpected errors."""
    logging.exception(f"An unexpected error occurred: {e}")
    return jsonify({"error": "Internal Server Error", "message": str(e)}), 500


# --- Helper Function to Run lws.py Commands ---
def run_lws_command(command_parts, data=None):
    """
    Executes an lws.py command using subprocess with input validation.

    Args:
        command_parts (list): A list containing the command and its subcommands/arguments
                              (e.g., ['lxc', 'run', '--image-id', 'ubuntu-22.04']).
        data (dict, optional): Data from the request body (for POST/PUT).

    Returns:
        tuple: (output, error, return_code)
    """
    # Validate command parts for security
    if not isinstance(command_parts, list) or not command_parts:
        logging.error("Invalid command_parts provided")
        return None, "Invalid command parameters", 1
    
    # Sanitize command parts
    sanitized_parts = []
    for part in command_parts:
        if not isinstance(part, str):
            logging.error(f"Non-string command part: {part}")
            return None, "Invalid command parameter type", 1
        
        # Basic validation - no shell metacharacters
        if re.search(r'[;&|`$(){}]', part):
            logging.warning(f"Dangerous characters detected in command part: {part}")
            return None, "Invalid characters in command", 1
        
        sanitized_parts.append(part)
    
    base_cmd = [sys.executable, LWS_SCRIPT_PATH]  # Use sys.executable to ensure correct python interpreter
    full_cmd = base_cmd + sanitized_parts

    # Add options from query parameters and JSON body
    options = {}
    if request.args:
        options.update(request.args.to_dict())
    if data:
        options.update(data)

    # Append options as command line arguments
    for key, value in options.items():
        # Handle boolean flags (like --confirm, --purge, --fix)
        if isinstance(value, bool):
            if value:
                full_cmd.append(f"--{key.replace('_', '-')}")
        elif value is not None: # Append only if value is not None
            full_cmd.append(f"--{key.replace('_', '-')}")
            full_cmd.append(str(value)) # Ensure value is string

    # Handle positional arguments if needed (e.g., instance_ids, command for exec)
    # This part needs careful mapping based on specific commands.
    # For simplicity, many commands take IDs/names in the path or specific options.
    # Commands like 'exec' or 'run_docker' might need special handling for their command arguments.

    logging.info(f"Executing command: {' '.join(shlex.quote(str(c)) for c in full_cmd)}") # Log the command safely

    try:
        # Use Popen for potentially long-running commands or streaming output if needed later
        process = subprocess.Popen(full_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate(timeout=300) # 5 minute timeout
        return_code = process.returncode

        logging.debug(f"Command stdout: {stdout.strip()}")
        if return_code != 0:
            logging.error(f"Command stderr: {stderr.strip()}")
            logging.error(f"Command return code: {return_code}")

        return stdout, stderr, return_code

    except subprocess.TimeoutExpired:
        logging.error(f"Command timed out: {' '.join(shlex.quote(str(c)) for c in full_cmd)}")
        return None, "Command execution timed out after 300 seconds.", 124 # Timeout return code
    except Exception as e:
        logging.exception(f"Error executing command: {e}")
        return None, f"Internal error executing command: {str(e)}", 1

def format_response(stdout, stderr, return_code):
    """Formats the command output into a JSON response."""
    if return_code == 0:
        try:
            # Try to parse stdout as JSON if it looks like it
            if stdout and stdout.strip().startswith(("{", "[")):
                return jsonify(json.loads(stdout)), 200
            else:
                 # Otherwise return plain text output
                return jsonify({"output": stdout.strip()}), 200
        except json.JSONDecodeError:
             # If JSON parsing fails, return as plain text
            return jsonify({"output": stdout.strip()}), 200
    else:
        # Return error details
        return jsonify({
            "error": "Command execution failed",
            "details": stderr.strip() if stderr else "No error details provided.",
            "output": stdout.strip() if stdout else "",
            "return_code": return_code
        }), 500 # Use 500 for internal/execution errors

# --- Swagger UI Configuration ---
SWAGGER_URL = '/api/v1/docs'  # URL for exposing Swagger UI (without trailing '/')
API_URL = '/api/v1/swagger.json'  # URL for your OpenAPI spec

# Call factory function to create our blueprint
swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={  # Swagger UI config overrides
        'app_name': "LWS API"
    }
)

# Register blueprint at URL
app.register_blueprint(swaggerui_blueprint)

# --- Minimal OpenAPI Spec ---
@app.route('/api/v1/swagger.json')
def swagger_spec():
    """Serves the OpenAPI specification (dynamically generated skeleton)."""
    # NOTE: This dynamically generates path skeletons but lacks details.
    # Manual completion or using libraries like apispec/flasgger is recommended for full documentation.
    spec = {
        "openapi": "3.0.0",
        "info": {
            "title": "LWS API",
            "version": "1.0.0",
            "description": "API for managing Linux Web Services (LXC on Proxmox)"
        },
        "servers": [
            # Determine server URL dynamically if needed, or keep relative
             {"url": request.host_url.rstrip('/') + url_for('serve_ui').rstrip('/') + '/api/v1'}
             # Or simply use relative: {"url": "/api/v1"}
        ],
        "paths": {}, # Initialize empty paths
        "components": {
            "securitySchemes": {
                "ApiKeyAuth": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-Key"
                }
            }
        },
        "security": [ # Default security for most endpoints
            {"ApiKeyAuth": []}
        ]
    }

    # Dynamically populate paths from Flask routes
    ignore_methods = {"HEAD", "OPTIONS"}
    # Exclude static routes and swagger routes
    excluded_endpoints = ['static', 'swagger_ui.show', 'swagger_spec']

    for rule in app.url_map.iter_rules():
        if rule.endpoint in excluded_endpoints:
            continue

        # Convert path parameters from <type:name> to {name}
        path = rule.rule.replace('<', '{').replace('>', '}').replace('string:', '').replace('int:', '')

        # Ensure path starts relative to /api/v1 if needed, or adjust server URL
        # For simplicity, assuming paths are correctly prefixed or server URL handles it.

        if path not in spec['paths']:
            spec['paths'][path] = {}

        methods = [m for m in rule.methods if m not in ignore_methods]
        for method in methods:
            # Create more detailed API documentation based on endpoint patterns
            endpoint_parts = rule.endpoint.split('.')
            category = endpoint_parts[0] if len(endpoint_parts) > 0 else 'default'
            operation = endpoint_parts[1] if len(endpoint_parts) > 1 else 'operation'
            
            # Generate better descriptions based on endpoint patterns
            if 'health' in rule.endpoint:
                description = "Check API health status"
                summary = "Health Check"
            elif 'lxc' in rule.endpoint and 'list' in rule.endpoint:
                description = "List all LXC containers with their current status"
                summary = "List LXC Containers"
            elif 'lxc' in rule.endpoint and 'show' in rule.endpoint:
                description = "Get detailed information about a specific LXC container"
                summary = "Show LXC Container Details"
            elif 'lxc' in rule.endpoint and 'start' in rule.endpoint:
                description = "Start one or more LXC containers"
                summary = "Start LXC Containers"
            elif 'lxc' in rule.endpoint and 'stop' in rule.endpoint:
                description = "Stop one or more LXC containers"
                summary = "Stop LXC Containers"
            elif 'proxmox' in rule.endpoint:
                description = f"Manage Proxmox host operations for {operation}"
                summary = f"Proxmox {operation.title()}"
            else:
                description = f"Perform {method.upper()} operation on {path}"
                summary = f"{category.title()} {operation.title()}"
            
            # Build parameters list based on path
            parameters = []
            if '{instance_id}' in path:
                parameters.append({
                    "name": "instance_id",
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string", "pattern": "^[0-9]+$"},
                    "description": "Numeric LXC container ID"
                })
            
            # Add common query parameters for certain endpoints
            if method.upper() in ['GET'] and 'list' in rule.endpoint:
                parameters.extend([
                    {"name": "region", "in": "query", "schema": {"type": "string"}, "description": "Region name"},
                    {"name": "az", "in": "query", "schema": {"type": "string"}, "description": "Availability zone"}
                ])
            
            # Build response descriptions
            responses = {
                "200": {"description": f"Successful {operation} operation"},
                "400": {"description": "Bad request - invalid parameters or malformed request"},
                "401": {"description": "Unauthorized - invalid or missing API key"},
                "404": {"description": "Resource not found"},
                "500": {"description": "Internal server error or command execution failed"}
            }
            
            # Add request body for POST/PUT methods
            request_body = None
            if method.upper() in ['POST', 'PUT']:
                request_body = {
                    "description": f"Request body for {operation} operation",
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "region": {"type": "string", "description": "Target region"},
                                    "az": {"type": "string", "description": "Target availability zone"}
                                }
                            }
                        }
                    }
                }
            
            spec['paths'][path][method.lower()] = {
                "summary": summary,
                "description": description,
                "tags": [category],
                "parameters": parameters,
                "responses": responses
            }
            
            if request_body:
                spec['paths'][path][method.lower()]["requestBody"] = request_body
            # Apply default security if not the health check
            if rule.endpoint != 'health_check':
                 spec['paths'][path][method.lower()]['security'] = [{"ApiKeyAuth": []}]


    return jsonify(spec)


# --- API Endpoints ---

# --- Serve UI ---
@app.route('/', methods=['GET'])
def serve_ui():
    """Serves the ui.html file."""
    # Assumes ui.html is in the same directory as api.py
    return send_from_directory(os.path.dirname(__file__), 'ui.html')

# --- Health Check ---
@app.route('/api/v1/health', methods=['GET'])
def health_check():
    """Basic health check endpoint."""
    return jsonify({"status": "ok"}), 200

# --- Configuration Management (`conf`) ---
@app.route('/api/v1/conf', methods=['GET'])
@require_api_key
def conf_show():
    """Show current configuration (masked)."""
    stdout, stderr, rc = run_lws_command(['conf', 'show'])
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/conf/validate', methods=['POST'])
@require_api_key
def conf_validate():
    """Validate the current configuration."""
    stdout, stderr, rc = run_lws_command(['conf', 'validate'])
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/conf/backup', methods=['POST'])
@require_api_key
def conf_backup():
    """Backup the current configuration."""
    data = request.get_json()
    if not data or 'destination_path' not in data:
        return jsonify({"error": "Missing 'destination_path' in request body"}), 400
    
    cmd_parts = ['conf', 'backup', data['destination_path']]
    # Add optional flags from data
    if data.get('timestamp'):
        cmd_parts.append('--timestamp')
    if data.get('compress'):
        cmd_parts.append('--compress')
        
    stdout, stderr, rc = run_lws_command(cmd_parts)
    return format_response(stdout, stderr, rc)

# --- Proxmox Host Management (`px`) ---
@app.route('/api/v1/px/hosts', methods=['GET'])
@require_api_key
def px_list_hosts():
    """List all available Proxmox hosts."""
    cmd_parts = ['px', 'list']
    if 'region' in request.args:
        cmd_parts.extend(['--region', request.args['region']])
    stdout, stderr, rc = run_lws_command(cmd_parts)
    # Special handling for list output if needed (e.g., parse lines)
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/px/reboot', methods=['POST'])
@require_api_key
def px_reboot():
    """Reboot a Proxmox host."""
    data = request.get_json()
    if not data or not data.get('confirm'):
        return jsonify({"error": "Confirmation required. Set 'confirm': true in the request body."}), 400
    
    cmd_parts = ['px', 'reboot', '--confirm']
    if 'region' in data: cmd_parts.extend(['--region', data['region']])
    if 'az' in data: cmd_parts.extend(['--az', data['az']])
    
    stdout, stderr, rc = run_lws_command(cmd_parts)
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/px/upload', methods=['POST'])
@require_api_key
def px_upload_template():
    """Upload template to Proxmox host."""
    data = request.get_json()
    if not data or 'local_path' not in data:
         return jsonify({"error": "Missing 'local_path' in request body"}), 400

    cmd_parts = ['px', 'upload', data['local_path']]
    if 'remote_template_name' in data: cmd_parts.append(data['remote_template_name'])
    
    # Pass other options via run_lws_command's data handling
    stdout, stderr, rc = run_lws_command(cmd_parts, data)
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/px/status', methods=['GET'])
@require_api_key
def px_status():
    """Monitor resource usage of a Proxmox host."""
    cmd_parts = ['px', 'status']
    stdout, stderr, rc = run_lws_command(cmd_parts, request.args.to_dict())
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/px/clusters', methods=['GET'])
@require_api_key
def px_list_clusters():
    """List all clusters in the Proxmox environment."""
    cmd_parts = ['px', 'clusters']
    stdout, stderr, rc = run_lws_command(cmd_parts, request.args.to_dict())
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/px/update', methods=['POST'])
@require_api_key
def px_update_hosts():
    """Update all Proxmox hosts."""
    # Note: lws.py px update doesn't take region/az, it seems to run locally?
    # Clarify if this should target specific hosts or run where API runs.
    # Assuming it runs where the API runs for now.
    stdout, stderr, rc = run_lws_command(['px', 'update'])
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/px/cluster/start', methods=['POST'])
@require_api_key
def px_start_cluster():
    """Start cluster services on a Proxmox host."""
    data = request.get_json() or {}
    cmd_parts = ['px', 'cluster-start']
    stdout, stderr, rc = run_lws_command(cmd_parts, data)
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/px/cluster/stop', methods=['POST'])
@require_api_key
def px_stop_cluster():
    """Stop cluster services on a Proxmox host."""
    data = request.get_json() or {}
    cmd_parts = ['px', 'cluster-stop']
    stdout, stderr, rc = run_lws_command(cmd_parts, data)
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/px/cluster/restart', methods=['POST'])
@require_api_key
def px_restart_cluster():
    """Restart cluster services on a Proxmox host."""
    data = request.get_json() or {}
    cmd_parts = ['px', 'cluster-restart']
    stdout, stderr, rc = run_lws_command(cmd_parts, data)
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/px/backup-lxc', methods=['POST'])
@require_api_key
def px_backup_lxc():
    """Create a backup of a specific LXC container via vzdump."""
    data = request.get_json()
    if not data or 'vmid' not in data or 'storage' not in data:
         return jsonify({"error": "Missing 'vmid' or 'storage' in request body"}), 400
    
    cmd_parts = ['px', 'backup-lxc', data['vmid']]
    stdout, stderr, rc = run_lws_command(cmd_parts, data) # Pass remaining options
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/px/image', methods=['POST'])
@require_api_key
def px_image_add():
    """Create a template image from an LXC container."""
    data = request.get_json()
    if not data or 'instance_id' not in data or 'template_name' not in data:
         return jsonify({"error": "Missing 'instance_id' or 'template_name' in request body"}), 400

    cmd_parts = ['px', 'image-add', data['instance_id'], data['template_name']]
    stdout, stderr, rc = run_lws_command(cmd_parts, data)
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/px/image/<template_name>', methods=['DELETE'])
@require_api_key
def px_image_rm(template_name):
    """Delete a template image from Proxmox host."""
    data = request.args.to_dict() # Get region/az from query params
    cmd_parts = ['px', 'image-rm', template_name]
    stdout, stderr, rc = run_lws_command(cmd_parts, data)
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/px/security-groups', methods=['POST'])
@require_api_key
def px_security_group_add():
    """Create a security group."""
    data = request.get_json()
    if not data or 'group_name' not in data:
         return jsonify({"error": "Missing 'group_name' in request body"}), 400
    
    cmd_parts = ['px', 'security-group-add', data['group_name']]
    stdout, stderr, rc = run_lws_command(cmd_parts, data)
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/px/security-groups/<group_name>', methods=['DELETE'])
@require_api_key
def px_security_group_rm(group_name):
    """Delete a security group."""
    data = request.args.to_dict() # Get region/az from query params
    cmd_parts = ['px', 'security-group-rm', group_name]
    stdout, stderr, rc = run_lws_command(cmd_parts, data)
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/px/security-groups/<group_name>/rules', methods=['POST'])
@require_api_key
def px_security_group_rule_add(group_name):
    """Add a rule to a security group."""
    data = request.get_json()
    if not data or 'direction' not in data:
         return jsonify({"error": "Missing 'direction' in request body"}), 400

    cmd_parts = ['px', 'security-group-rule-add', group_name]
    stdout, stderr, rc = run_lws_command(cmd_parts, data)
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/px/security-groups/<group_name>/rules', methods=['DELETE'])
@require_api_key
def px_security_group_rule_rm(group_name):
    """Remove a rule from a security group."""
    # Rules are complex to identify uniquely via URL path.
    # We pass all rule details in the JSON body for the command to handle.
    data = request.get_json()
    if not data or 'direction' not in data:
         return jsonify({"error": "Missing rule details ('direction', etc.) in request body"}), 400

    cmd_parts = ['px', 'security-group-rule-rm', group_name]
    stdout, stderr, rc = run_lws_command(cmd_parts, data)
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/px/security-groups/attach', methods=['POST'])
@require_api_key
def px_security_group_attach():
    """Attach security group to an LXC container."""
    data = request.get_json()
    if not data or 'group_name' not in data or 'vmid' not in data:
         return jsonify({"error": "Missing 'group_name' or 'vmid' in request body"}), 400

    cmd_parts = ['px', 'security-group-attach', data['group_name'], data['vmid']]
    stdout, stderr, rc = run_lws_command(cmd_parts, data)
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/px/security-groups/detach', methods=['POST'])
@require_api_key
def px_security_group_detach():
    """Detach security group from an LXC container."""
    data = request.get_json()
    if not data or 'group_name' not in data or 'vmid' not in data:
         return jsonify({"error": "Missing 'group_name' or 'vmid' in request body"}), 400

    cmd_parts = ['px', 'security-group-detach', data['group_name'], data['vmid']]
    stdout, stderr, rc = run_lws_command(cmd_parts, data)
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/px/templates', methods=['GET'])
@require_api_key
def px_list_templates():
    """List all available templates."""
    cmd_parts = ['px', 'templates']
    stdout, stderr, rc = run_lws_command(cmd_parts, request.args.to_dict())
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/px/security-groups', methods=['GET'])
@require_api_key
def px_list_security_groups():
    """List all security groups and their rules."""
    cmd_parts = ['px', 'security-groups']
    stdout, stderr, rc = run_lws_command(cmd_parts, request.args.to_dict())
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/px/exec', methods=['POST'])
@require_api_key
def px_exec():
    """Execute an arbitrary command on a Proxmox host."""
    data = request.get_json()
    if not data or 'command' not in data:
         return jsonify({"error": "Missing 'command' in request body"}), 400

    # The command itself might have multiple parts, handle as list or string
    cmd_to_exec = data['command']
    if isinstance(cmd_to_exec, str):
        cmd_to_exec_parts = shlex.split(cmd_to_exec) # Split safely
    elif isinstance(cmd_to_exec, list):
        cmd_to_exec_parts = cmd_to_exec
    else:
        return jsonify({"error": "'command' must be a string or a list of strings"}), 400

    cmd_parts = ['px', 'exec'] + cmd_to_exec_parts
    
    # Pass region/az from data if present
    exec_data = {k: v for k, v in data.items() if k in ['region', 'az']}
    
    stdout, stderr, rc = run_lws_command(cmd_parts, exec_data)
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/px/backup', methods=['POST'])
@require_api_key
def px_backup_host_config():
    """Backup configurations from a Proxmox host."""
    data = request.get_json()
    if not data or 'backup_dir' not in data:
         return jsonify({"error": "Missing 'backup_dir' in request body"}), 400

    cmd_parts = ['px', 'backup', data['backup_dir']]
    stdout, stderr, rc = run_lws_command(cmd_parts, data)
    return format_response(stdout, stderr, rc)


# --- LXC Container Management (`lxc`) ---
@app.route('/api/v1/lxc/instances', methods=['POST'])
@require_api_key
def lxc_run_instance():
    """Create and start LXC containers."""
    data = request.get_json()
    if not data or 'image_id' not in data:
         return jsonify({"error": "Missing 'image_id' in request body"}), 400

    cmd_parts = ['lxc', 'run']
    stdout, stderr, rc = run_lws_command(cmd_parts, data)
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/lxc/instances/stop', methods=['POST'])
@require_api_key
def lxc_stop_instances():
    """Stop running LXC containers."""
    data = request.get_json()
    if not data or 'instance_ids' not in data or not isinstance(data['instance_ids'], list):
         return jsonify({"error": "Missing 'instance_ids' (list) in request body"}), 400

    cmd_parts = ['lxc', 'stop'] + data['instance_ids']
    stdout, stderr, rc = run_lws_command(cmd_parts, data)
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/lxc/instances/terminate', methods=['POST']) # Using POST for multiple IDs
@require_api_key
def lxc_terminate_instances():
    """Terminate (destroy) LXC containers."""
    data = request.get_json()
    if not data or 'instance_ids' not in data or not isinstance(data['instance_ids'], list):
         return jsonify({"error": "Missing 'instance_ids' (list) in request body"}), 400

    cmd_parts = ['lxc', 'terminate'] + data['instance_ids']
    stdout, stderr, rc = run_lws_command(cmd_parts, data)
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/lxc/instances', methods=['GET'])
@require_api_key
def lxc_list_instances():
    """List all LXC containers."""
    cmd_parts = ['lxc', 'show'] # 'lxc show' without IDs lists all
    stdout, stderr, rc = run_lws_command(cmd_parts, request.args.to_dict())
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/lxc/instances/<instance_id>', methods=['GET'])
@require_api_key
def lxc_describe_instance(instance_id):
    """Describe a specific LXC container."""
    cmd_parts = ['lxc', 'show', instance_id]
    stdout, stderr, rc = run_lws_command(cmd_parts, request.args.to_dict())
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/lxc/instances/scale', methods=['POST']) # Using POST for multiple IDs
@require_api_key
def lxc_scale_instances():
    """Scale resources for LXC containers."""
    data = request.get_json()
    if not data or 'instance_ids' not in data or not isinstance(data['instance_ids'], list):
         return jsonify({"error": "Missing 'instance_ids' (list) in request body"}), 400
    if not any(k in data for k in ['memory', 'cpulimit', 'cpucores', 'storage_size', 'net_limit', 'disk_read_limit', 'disk_write_limit']):
        return jsonify({"error": "Missing scaling parameters (memory, cpulimit, etc.)"}), 400

    cmd_parts = ['lxc', 'scale'] + data['instance_ids']
    stdout, stderr, rc = run_lws_command(cmd_parts, data)
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/lxc/instances/<instance_id>/snapshots', methods=['POST'])
@require_api_key
def lxc_snapshot_add(instance_id):
    """Create a snapshot of an LXC container."""
    data = request.get_json()
    if not data or 'snapshot_name' not in data:
         return jsonify({"error": "Missing 'snapshot_name' in request body"}), 400

    cmd_parts = ['lxc', 'snapshot-add', instance_id, data['snapshot_name']]
    stdout, stderr, rc = run_lws_command(cmd_parts, data)
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/lxc/instances/<instance_id>/snapshots/<snapshot_name>', methods=['DELETE'])
@require_api_key
def lxc_snapshot_rm(instance_id, snapshot_name):
    """Delete a snapshot of an LXC container."""
    data = request.args.to_dict() # region/az from query
    cmd_parts = ['lxc', 'snapshot-rm', instance_id, snapshot_name]
    stdout, stderr, rc = run_lws_command(cmd_parts, data)
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/lxc/instances/<instance_id>/snapshots', methods=['GET'])
@require_api_key
def lxc_list_snapshots(instance_id):
    """List all snapshots of an LXC container."""
    cmd_parts = ['lxc', 'snapshots', instance_id]
    stdout, stderr, rc = run_lws_command(cmd_parts, request.args.to_dict())
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/lxc/instances/start', methods=['POST'])
@require_api_key
def lxc_start_instances():
    """Start stopped LXC containers."""
    data = request.get_json()
    if not data or 'instance_ids' not in data or not isinstance(data['instance_ids'], list):
         return jsonify({"error": "Missing 'instance_ids' (list) in request body"}), 400

    cmd_parts = ['lxc', 'start'] + data['instance_ids']
    stdout, stderr, rc = run_lws_command(cmd_parts, data)
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/lxc/instances/reboot', methods=['POST'])
@require_api_key
def lxc_reboot_instances():
    """Reboot running LXC containers."""
    data = request.get_json()
    if not data or 'instance_ids' not in data or not isinstance(data['instance_ids'], list):
         return jsonify({"error": "Missing 'instance_ids' (list) in request body"}), 400

    cmd_parts = ['lxc', 'reboot'] + data['instance_ids']
    stdout, stderr, rc = run_lws_command(cmd_parts, data)
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/lxc/instances/<instance_id>/volumes/attach', methods=['POST'])
@require_api_key
def lxc_volume_attach(instance_id):
    """Attach a storage volume to an LXC container."""
    data = request.get_json()
    if not data or 'volume_name' not in data or 'volume_size' not in data or 'mount_point' not in data:
         return jsonify({"error": "Missing 'volume_name', 'volume_size', or 'mount_point' in request body"}), 400

    cmd_parts = ['lxc', 'volume-attach', instance_id, data['volume_name'], data['volume_size']]
    stdout, stderr, rc = run_lws_command(cmd_parts, data)
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/lxc/instances/<instance_id>/volumes/detach', methods=['POST'])
@require_api_key
def lxc_volume_detach(instance_id):
    """Detach a storage volume from an LXC container."""
    data = request.get_json()
    if not data or 'volume_name' not in data:
         return jsonify({"error": "Missing 'volume_name' in request body"}), 400

    cmd_parts = ['lxc', 'volume-detach', instance_id, data['volume_name']]
    stdout, stderr, rc = run_lws_command(cmd_parts, data)
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/lxc/instances/status', methods=['POST']) # POST for multiple IDs
@require_api_key
def lxc_monitor_instances():
    """Monitor resources of LXC containers."""
    data = request.get_json()
    if not data or 'instance_ids' not in data or not isinstance(data['instance_ids'], list):
         return jsonify({"error": "Missing 'instance_ids' (list) in request body"}), 400

    cmd_parts = ['lxc', 'status'] + data['instance_ids']
    stdout, stderr, rc = run_lws_command(cmd_parts, data)
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/lxc/instances/<instance_id>/service', methods=['POST'])
@require_api_key
def lxc_service(instance_id):
    """Manage a service within an LXC container."""
    data = request.get_json()
    if not data or 'action' not in data or 'service_name' not in data:
         return jsonify({"error": "Missing 'action' or 'service_name' in request body"}), 400
    
    valid_actions = ['status', 'start', 'stop', 'restart', 'reload', 'enable']
    if data['action'] not in valid_actions:
        return jsonify({"error": f"Invalid action. Must be one of: {valid_actions}"}), 400

    cmd_parts = ['lxc', 'service', data['action'], data['service_name'], instance_id]
    stdout, stderr, rc = run_lws_command(cmd_parts, data)
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/lxc/instances/<instance_id>/migrate', methods=['POST'])
@require_api_key
def lxc_migrate(instance_id):
    """Migrate LXC container between hosts."""
    data = request.get_json()
    if not data or 'target_host' not in data:
         return jsonify({"error": "Missing 'target_host' in request body"}), 400

    cmd_parts = ['lxc', 'migrate', instance_id]
    stdout, stderr, rc = run_lws_command(cmd_parts, data)
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/lxc/instances/<instance_id>/storage', methods=['GET'])
@require_api_key
def lxc_show_storage(instance_id):
    """List storage details for an LXC container."""
    cmd_parts = ['lxc', 'show-storage', instance_id]
    stdout, stderr, rc = run_lws_command(cmd_parts, request.args.to_dict())
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/lxc/instances/<instance_id>/scale-check', methods=['GET'])
@require_api_key
def lxc_scale_check(instance_id):
    """Suggest scaling adjustments for an LXC container."""
    cmd_parts = ['lxc', 'scale-check', instance_id]
    stdout, stderr, rc = run_lws_command(cmd_parts, request.args.to_dict())
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/lxc/instances/clone', methods=['POST'])
@require_api_key
def lxc_clone():
    """Clone an LXC container."""
    data = request.get_json()
    if not data or 'source_instance_id' not in data or 'target_instance_id' not in data:
         return jsonify({"error": "Missing 'source_instance_id' or 'target_instance_id' in request body"}), 400

    cmd_parts = ['lxc', 'clone', data['source_instance_id'], data['target_instance_id']]
    stdout, stderr, rc = run_lws_command(cmd_parts, data)
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/lxc/instances/<instance_id>/exec', methods=['POST'])
@require_api_key
def lxc_exec(instance_id):
    """Execute an arbitrary command in an LXC container."""
    data = request.get_json()
    if not data or 'command' not in data:
         return jsonify({"error": "Missing 'command' in request body"}), 400

    # The command itself might have multiple parts
    cmd_to_exec = data['command']
    if isinstance(cmd_to_exec, str):
        cmd_to_exec_parts = shlex.split(cmd_to_exec) # Split safely
    elif isinstance(cmd_to_exec, list):
        cmd_to_exec_parts = cmd_to_exec
    else:
        return jsonify({"error": "'command' must be a string or a list of strings"}), 400

    # The lws command expects the command parts after the instance ID
    cmd_parts = ['lxc', 'exec', instance_id] + cmd_to_exec_parts
    
    # Pass region/az from data if present
    exec_data = {k: v for k, v in data.items() if k in ['region', 'az']}

    stdout, stderr, rc = run_lws_command(cmd_parts, exec_data)
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/lxc/instances/<instance_id>/net-check', methods=['GET'])
@require_api_key
def lxc_net_check(instance_id):
    """Perform simple network checks on an LXC container."""
    args = request.args.to_dict()
    if 'protocol' not in args or 'port' not in args:
        return jsonify({"error": "Missing 'protocol' or 'port' query parameters"}), 400

    cmd_parts = ['lxc', 'net', instance_id, args['protocol'], args['port']]
    stdout, stderr, rc = run_lws_command(cmd_parts, args)
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/lxc/instances/<instance_id>/info', methods=['GET'])
@require_api_key
def lxc_show_info(instance_id):
    """Retrieve IP address, hostname, DNS, and name for an LXC container."""
    cmd_parts = ['lxc', 'show-info', instance_id]
    stdout, stderr, rc = run_lws_command(cmd_parts, request.args.to_dict())
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/lxc/instances/<instance_id>/public-ip', methods=['GET'])
@require_api_key
def lxc_show_public_ip(instance_id):
    """Retrieve the public IP address of an LXC container."""
    cmd_parts = ['lxc', 'show-public-ip', instance_id]
    stdout, stderr, rc = run_lws_command(cmd_parts, request.args.to_dict())
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/lxc/instances/<instance_id>/health-check', methods=['GET'])
@require_api_key
def lxc_health_check(instance_id):
    """Perform health check on an LXC container."""
    cmd_parts = ['lxc', 'health-check', instance_id]
    stdout, stderr, rc = run_lws_command(cmd_parts, request.args.to_dict())
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/lxc/instances/<instance_id>/restore', methods=['POST'])
@require_api_key
def lxc_backup_restore(instance_id):
    """Restore an LXC container from a backup file."""
    data = request.get_json()
    if not data or 'backup_file' not in data:
         return jsonify({"error": "Missing 'backup_file' in request body"}), 400

    cmd_parts = ['lxc', 'backup-restore', instance_id]
    stdout, stderr, rc = run_lws_command(cmd_parts, data)
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/lxc/instances/<instance_id>/backup', methods=['POST'])
@require_api_key
def lxc_backup_create(instance_id):
    """Create a backup of an LXC container."""
    data = request.get_json() or {} # Allow empty body, use defaults
    cmd_parts = ['lxc', 'backup-create', instance_id]
    stdout, stderr, rc = run_lws_command(cmd_parts, data)
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/lxc/instances/<instance_id>/resources', methods=['GET'])
@require_api_key
def lxc_monitor_resources(instance_id):
    """Monitor real-time resource usage of an LXC container."""
    cmd_parts = ['lxc', 'resources', instance_id]
    stdout, stderr, rc = run_lws_command(cmd_parts, request.args.to_dict())
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/lxc/instances/<instance_id>/report', methods=['GET'])
@require_api_key
def lxc_generate_report(instance_id):
    """Generate a comprehensive report about an LXC container."""
    cmd_parts = ['lxc', 'report', instance_id]
    stdout, stderr, rc = run_lws_command(cmd_parts, request.args.to_dict())
    # The command might output JSON directly if --output json is used
    return format_response(stdout, stderr, rc)


# --- Docker Management (`app`) ---
@app.route('/api/v1/lxc/instances/<instance_id>/app/setup', methods=['POST'])
@require_api_key
def app_setup(instance_id):
    """Install Docker and Compose on an LXC container."""
    data = request.get_json() or {}
    package_name = data.get('package_name', 'docker') # Default from lws.py
    cmd_parts = ['app', 'setup', instance_id, package_name]
    stdout, stderr, rc = run_lws_command(cmd_parts, data)
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/lxc/instances/<instance_id>/app/run', methods=['POST'])
@require_api_key
def app_run_docker(instance_id):
    """Execute docker run inside an LXC container."""
    data = request.get_json()
    if not data or 'docker_command' not in data:
         return jsonify({"error": "Missing 'docker_command' (string or list) in request body"}), 400

    docker_cmd_parts = data['docker_command']
    if isinstance(docker_cmd_parts, str):
        docker_cmd_parts = shlex.split(docker_cmd_parts)
    elif not isinstance(docker_cmd_parts, list):
         return jsonify({"error": "'docker_command' must be a string or list"}), 400

    # lws app run <id> -- <docker command parts>
    cmd_parts = ['app', 'run', instance_id] + docker_cmd_parts
    
    # Pass region/az from data if present
    run_data = {k: v for k, v in data.items() if k in ['region', 'az']}

    stdout, stderr, rc = run_lws_command(cmd_parts, run_data)
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/lxc/instances/<instance_id>/app/deploy', methods=['POST'])
@require_api_key
def app_deploy_compose(instance_id):
    """Manage apps with Compose on LXC containers."""
    data = request.get_json()
    if not data or 'action' not in data or 'compose_file' not in data:
         return jsonify({"error": "Missing 'action' or 'compose_file' in request body"}), 400
    
    valid_actions = ['install', 'uninstall', 'start', 'stop', 'restart', 'status']
    if data['action'] not in valid_actions:
        return jsonify({"error": f"Invalid action. Must be one of: {valid_actions}"}), 400

    cmd_parts = ['app', 'deploy', data['action'], instance_id]
    stdout, stderr, rc = run_lws_command(cmd_parts, data)
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/lxc/instances/<instance_id>/app/update', methods=['POST'])
@require_api_key
def app_update_compose(instance_id):
    """Update app within an LXC container via Compose."""
    data = request.get_json()
    if not data or 'compose_file' not in data:
         return jsonify({"error": "Missing 'compose_file' in request body"}), 400

    cmd_parts = ['app', 'update', instance_id]
    stdout, stderr, rc = run_lws_command(cmd_parts, data)
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/lxc/instances/<instance_id>/app/logs/<container_name_or_id>', methods=['GET'])
@require_api_key
def app_logs(instance_id, container_name_or_id):
    """Fetch Docker logs from an LXC container."""
    cmd_parts = ['app', 'logs', instance_id, container_name_or_id]
    stdout, stderr, rc = run_lws_command(cmd_parts, request.args.to_dict())
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/lxc/instances/<instance_id>/app/containers', methods=['GET'])
@require_api_key
def app_list_containers(instance_id):
    """List Docker containers in an LXC container."""
    cmd_parts = ['app', 'list', instance_id]
    stdout, stderr, rc = run_lws_command(cmd_parts, request.args.to_dict())
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/lxc/instances/app/remove', methods=['POST']) # POST for multiple IDs
@require_api_key
def app_remove(instance_ids):
    """Uninstall Docker and Compose from LXC containers."""
    data = request.get_json()
    if not data or 'instance_ids' not in data or not isinstance(data['instance_ids'], list):
         return jsonify({"error": "Missing 'instance_ids' (list) in request body"}), 400

    cmd_parts = ['app', 'remove'] + data['instance_ids']
    stdout, stderr, rc = run_lws_command(cmd_parts, data)
    return format_response(stdout, stderr, rc)


# --- Security (`sec`) ---
@app.route('/api/v1/sec/discovery', methods=['GET'])
@require_api_key
def sec_discovery():
    """Discover reachable hosts."""
    args = request.args.to_dict()
    cmd_parts = ['sec', 'discovery']
    if 'lxc_id' in args:
        cmd_parts.append(args['lxc_id']) # lxc_id is positional if present
        
    stdout, stderr, rc = run_lws_command(cmd_parts, args)
    return format_response(stdout, stderr, rc)

@app.route('/api/v1/lxc/instances/<instance_id>/sec/scan', methods=['GET'])
@require_api_key
def sec_scan(instance_id):
    """Perform a security scan on an LXC container."""
    cmd_parts = ['sec', 'scan', instance_id]
    stdout, stderr, rc = run_lws_command(cmd_parts, request.args.to_dict())
    return format_response(stdout, stderr, rc)


# --- Main Execution ---
if __name__ == '__main__':
    host = API_CONFIG.get('host', '127.0.0.1')
    port = API_CONFIG.get('port', 8080)
    debug = API_CONFIG.get('debug', False)
    logging.info(f"Starting Flask server on {host}:{port} (Debug: {debug})")
    app.run(host=host, port=port, debug=debug)
