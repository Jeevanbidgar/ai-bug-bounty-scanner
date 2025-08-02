"""
Agent Configuration API Routes
Handles agent configuration for vulnerability scan filter toggles
"""

from flask import Blueprint, request, jsonify
import json
import os
from pathlib import Path
from config import get_config

# Create Blueprint
agent_config_bp = Blueprint('agent_config', __name__)

# Get configuration
Config = get_config()

# Agent configurations storage
AGENT_CONFIG_DIR = Path("instance/agent_configs")
AGENT_CONFIG_DIR.mkdir(parents=True, exist_ok=True)

# Default test configurations for each agent
AGENT_TEST_CONFIGURATIONS = {
    'webapp': {
        'available_tests': [
            {
                'id': 'xss_reflected',
                'name': 'Reflected XSS',
                'description': 'Test for reflected cross-site scripting vulnerabilities',
                'severity': 'high',
                'category': 'Client-Side Injection'
            },
            {
                'id': 'xss_stored',
                'name': 'Stored XSS',
                'description': 'Test for stored cross-site scripting vulnerabilities',
                'severity': 'high',
                'category': 'Client-Side Injection'
            },
            {
                'id': 'sql_injection',
                'name': 'SQL Injection',
                'description': 'Test for SQL injection vulnerabilities in forms and parameters',
                'severity': 'critical',
                'category': 'Critical Remote Execution'
            },
            {
                'id': 'path_traversal',
                'name': 'Path Traversal',
                'description': 'Test for directory traversal vulnerabilities',
                'severity': 'high',
                'category': 'Access Control Bypasses'
            },
            {
                'id': 'csrf',
                'name': 'CSRF Protection',
                'description': 'Check for missing CSRF protection on forms',
                'severity': 'medium',
                'category': 'Access Control Bypasses'
            },
            {
                'id': 'open_redirect',
                'name': 'Open Redirect',
                'description': 'Test for open redirect vulnerabilities',
                'severity': 'medium',
                'category': 'Access Control Bypasses'
            },
            {
                'id': 'clickjacking',
                'name': 'Clickjacking',
                'description': 'Check for missing X-Frame-Options header',
                'severity': 'medium',
                'category': 'Client-Side Injection'
            },
            {
                'id': 'file_upload',
                'name': 'File Upload Bypass',
                'description': 'Test file upload functionality for security bypasses',
                'severity': 'high',
                'category': 'Critical Remote Execution'
            },
            {
                'id': 'session_fixation',
                'name': 'Session Fixation',
                'description': 'Test for session fixation vulnerabilities',
                'severity': 'medium',
                'category': 'Access Control Bypasses'
            },
            {
                'id': 'weak_authentication',
                'name': 'Weak Authentication',
                'description': 'Test for weak authentication mechanisms',
                'severity': 'medium',
                'category': 'Access Control Bypasses'
            }
        ]
    },
    'api': {
        'available_tests': [
            {
                'id': 'bola',
                'name': 'BOLA/IDOR',
                'description': 'Test for Broken Object Level Authorization vulnerabilities',
                'severity': 'critical',
                'category': 'Access Control Bypasses'
            },
            {
                'id': 'broken_auth',
                'name': 'Broken Authentication',
                'description': 'Test for authentication bypass vulnerabilities',
                'severity': 'critical',
                'category': 'Access Control Bypasses'
            },
            {
                'id': 'excessive_data',
                'name': 'Excessive Data Exposure',
                'description': 'Check for APIs returning excessive sensitive data',
                'severity': 'medium',
                'category': 'Access Control Bypasses'
            },
            {
                'id': 'rate_limiting',
                'name': 'Rate Limiting',
                'description': 'Test for missing or weak rate limiting',
                'severity': 'medium',
                'category': 'Access Control Bypasses'
            },
            {
                'id': 'function_level_auth',
                'name': 'Function Level Authorization',
                'description': 'Test for broken function level authorization',
                'severity': 'high',
                'category': 'Access Control Bypasses'
            },
            {
                'id': 'mass_assignment',
                'name': 'Mass Assignment',
                'description': 'Test for mass assignment vulnerabilities',
                'severity': 'medium',
                'category': 'Access Control Bypasses'
            },
            {
                'id': 'security_misconfiguration',
                'name': 'Security Misconfiguration',
                'description': 'Check for security misconfigurations',
                'severity': 'medium',
                'category': 'Cryptographic Failures'
            },
            {
                'id': 'injection',
                'name': 'Injection Attacks',
                'description': 'Test for various injection vulnerabilities',
                'severity': 'critical',
                'category': 'Critical Remote Execution'
            },
            {
                'id': 'improper_assets',
                'name': 'Improper Assets Management',
                'description': 'Check for improper API assets management',
                'severity': 'medium',
                'category': 'Access Control Bypasses'
            },
            {
                'id': 'insufficient_logging',
                'name': 'Insufficient Logging',
                'description': 'Check for insufficient logging and monitoring',
                'severity': 'low',
                'category': 'Cryptographic Failures'
            }
        ]
    },
    'network': {
        'available_tests': [
            {
                'id': 'port_scan',
                'name': 'Port Scanning',
                'description': 'Scan for open ports and services',
                'severity': 'info',
                'category': 'Network Discovery'
            },
            {
                'id': 'service_detection',
                'name': 'Service Detection',
                'description': 'Detect running services and versions',
                'severity': 'info',
                'category': 'Network Discovery'
            },
            {
                'id': 'ssl_tls_scan',
                'name': 'SSL/TLS Configuration',
                'description': 'Check SSL/TLS configuration and vulnerabilities',
                'severity': 'high',
                'category': 'Cryptographic Failures'
            },
            {
                'id': 'weak_ciphers',
                'name': 'Weak Ciphers',
                'description': 'Check for weak encryption ciphers',
                'severity': 'medium',
                'category': 'Cryptographic Failures'
            },
            {
                'id': 'certificate_validation',
                'name': 'Certificate Validation',
                'description': 'Validate SSL certificates',
                'severity': 'medium',
                'category': 'Cryptographic Failures'
            },
            {
                'id': 'network_services',
                'name': 'Network Services',
                'description': 'Test network services for vulnerabilities',
                'severity': 'medium',
                'category': 'Network Security'
            },
            {
                'id': 'dns_enumeration',
                'name': 'DNS Enumeration',
                'description': 'Enumerate DNS records and subdomains',
                'severity': 'info',
                'category': 'Network Discovery'
            },
            {
                'id': 'firewall_detection',
                'name': 'Firewall Detection',
                'description': 'Detect firewall and filtering mechanisms',
                'severity': 'info',
                'category': 'Network Security'
            }
        ]
    },
    'recon': {
        'available_tests': [
            {
                'id': 'subdomain_enumeration',
                'name': 'Subdomain Enumeration',
                'description': 'Discover subdomains using multiple techniques',
                'severity': 'info',
                'category': 'Information Gathering'
            },
            {
                'id': 'dns_enumeration',
                'name': 'DNS Enumeration',
                'description': 'Enumerate DNS records and configurations',
                'severity': 'info',
                'category': 'Information Gathering'
            },
            {
                'id': 'whois_lookup',
                'name': 'WHOIS Lookup',
                'description': 'Gather domain registration information',
                'severity': 'info',
                'category': 'Information Gathering'
            },
            {
                'id': 'email_harvesting',
                'name': 'Email Harvesting',
                'description': 'Collect email addresses related to the target',
                'severity': 'info',
                'category': 'Information Gathering'
            },
            {
                'id': 'social_media_osint',
                'name': 'Social Media OSINT',
                'description': 'Gather information from social media platforms',
                'severity': 'info',
                'category': 'Information Gathering'
            },
            {
                'id': 'technology_detection',
                'name': 'Technology Detection',
                'description': 'Identify technologies used by the target',
                'severity': 'info',
                'category': 'Information Gathering'
            },
            {
                'id': 'directory_enumeration',
                'name': 'Directory Enumeration',
                'description': 'Discover hidden directories and files',
                'severity': 'medium',
                'category': 'Information Gathering'
            },
            {
                'id': 'metadata_extraction',
                'name': 'Metadata Extraction',
                'description': 'Extract metadata from documents and files',
                'severity': 'info',
                'category': 'Information Gathering'
            }
        ]
    }
}

def get_agent_config_file(agent_name):
    """Get the configuration file path for an agent"""
    return AGENT_CONFIG_DIR / f"{agent_name}_config.json"

def load_agent_config(agent_name):
    """Load agent configuration from file or return defaults"""
    config_file = get_agent_config_file(agent_name)
    
    if config_file.exists():
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
        except (json.JSONDecodeError, IOError):
            config = {}
    else:
        config = {}
    
    # Get default configuration for this agent
    default_config = AGENT_TEST_CONFIGURATIONS.get(agent_name, {'available_tests': []})
    
    # If no enabled_tests in config, enable all by default
    if 'enabled_tests' not in config:
        config['enabled_tests'] = [test['id'] for test in default_config['available_tests']]
    
    # Merge with defaults
    config['available_tests'] = default_config['available_tests']
    
    return config

def save_agent_config(agent_name, config):
    """Save agent configuration to file"""
    config_file = get_agent_config_file(agent_name)
    
    try:
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        return True
    except IOError:
        return False

@agent_config_bp.route('/api/agents/<agent_name>/config', methods=['GET'])
def get_agent_configuration(agent_name):
    """Get configuration for a specific agent"""
    try:
        # Validate agent name
        valid_agents = ['webapp', 'api', 'network', 'recon']
        if agent_name not in valid_agents:
            return jsonify({
                'error': f'Invalid agent name. Must be one of: {", ".join(valid_agents)}'
            }), 400
        
        config = load_agent_config(agent_name)
        
        return jsonify(config)
        
    except Exception as e:
        return jsonify({
            'error': f'Failed to load agent configuration: {str(e)}'
        }), 500

@agent_config_bp.route('/api/agents/<agent_name>/config', methods=['POST'])
def update_agent_configuration(agent_name):
    """Update configuration for a specific agent"""
    try:
        # Validate agent name
        valid_agents = ['webapp', 'api', 'network', 'recon']
        if agent_name not in valid_agents:
            return jsonify({
                'error': f'Invalid agent name. Must be one of: {", ".join(valid_agents)}'
            }), 400
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Load current config
        current_config = load_agent_config(agent_name)
        
        # Update enabled tests
        if 'enabled_tests' in data:
            # Validate that all enabled tests are available
            available_test_ids = [test['id'] for test in current_config['available_tests']]
            invalid_tests = [test_id for test_id in data['enabled_tests'] if test_id not in available_test_ids]
            
            if invalid_tests:
                return jsonify({
                    'error': f'Invalid test IDs: {", ".join(invalid_tests)}'
                }), 400
            
            current_config['enabled_tests'] = data['enabled_tests']
        
        # Save configuration
        if save_agent_config(agent_name, current_config):
            return jsonify({
                'success': True,
                'message': f'Configuration updated for {agent_name} agent',
                'enabled_tests_count': len(current_config['enabled_tests'])
            })
        else:
            return jsonify({
                'error': 'Failed to save configuration'
            }), 500
            
    except Exception as e:
        return jsonify({
            'error': f'Failed to update agent configuration: {str(e)}'
        }), 500

@agent_config_bp.route('/api/agents/config/summary', methods=['GET'])
def get_all_agents_config_summary():
    """Get a summary of all agent configurations"""
    try:
        valid_agents = ['webapp', 'api', 'network', 'recon']
        summary = {}
        
        for agent_name in valid_agents:
            config = load_agent_config(agent_name)
            summary[agent_name] = {
                'total_tests': len(config['available_tests']),
                'enabled_tests': len(config['enabled_tests']),
                'disabled_tests': len(config['available_tests']) - len(config['enabled_tests'])
            }
        
        return jsonify(summary)
        
    except Exception as e:
        return jsonify({
            'error': f'Failed to load agent configurations: {str(e)}'
        }), 500
