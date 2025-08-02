"""
Agent Configuration Utility
Provides functions for agents to check their configuration settings
"""

import json
from pathlib import Path

def get_enabled_tests(agent_name):
    """
    Get the list of enabled tests for a specific agent
    
    Args:
        agent_name (str): Name of the agent (webapp, api, network, recon)
    
    Returns:
        list: List of enabled test IDs for the agent
    """
    config_dir = Path("instance/agent_configs")
    config_file = config_dir / f"{agent_name}_config.json"
    
    # Default enabled tests if no config exists
    default_enabled_tests = {
        'webapp': [
            'xss_reflected', 'xss_stored', 'sql_injection', 'path_traversal',
            'csrf', 'open_redirect', 'clickjacking', 'file_upload',
            'session_fixation', 'weak_authentication'
        ],
        'api': [
            'bola', 'broken_auth', 'excessive_data', 'rate_limiting',
            'function_level_auth', 'mass_assignment', 'security_misconfiguration',
            'injection', 'improper_assets', 'insufficient_logging'
        ],
        'network': [
            'port_scan', 'service_detection', 'ssl_tls_scan', 'weak_ciphers',
            'certificate_validation', 'network_services', 'dns_enumeration',
            'firewall_detection'
        ],
        'recon': [
            'subdomain_enumeration', 'dns_enumeration', 'whois_lookup',
            'email_harvesting', 'social_media_osint', 'technology_detection',
            'directory_enumeration', 'metadata_extraction'
        ]
    }
    
    if config_file.exists():
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                return config.get('enabled_tests', default_enabled_tests.get(agent_name, []))
        except (json.JSONDecodeError, IOError):
            pass
    
    return default_enabled_tests.get(agent_name, [])

def is_test_enabled(agent_name, test_id):
    """
    Check if a specific test is enabled for an agent
    
    Args:
        agent_name (str): Name of the agent
        test_id (str): ID of the test to check
    
    Returns:
        bool: True if test is enabled, False otherwise
    """
    enabled_tests = get_enabled_tests(agent_name)
    return test_id in enabled_tests

def log_test_execution(agent_name, test_id, executed=True):
    """
    Log test execution for monitoring
    
    Args:
        agent_name (str): Name of the agent
        test_id (str): ID of the test
        executed (bool): Whether the test was executed
    """
    status = "EXECUTED" if executed else "SKIPPED"
    print(f"[{agent_name.upper()}_AGENT] Test {test_id}: {status}")
