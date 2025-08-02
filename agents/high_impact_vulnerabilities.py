# High-Impact Vulnerability Configuration
"""
Configuration for focusing on the most effective and high-impact vulnerability categories.
This configuration prioritizes depth over breadth for better bug bounty success.
"""

from typing import Dict, List, Any
import logging

logger = logging.getLogger(__name__)

# Priority 1: Critical Remote Execution Vulnerabilities (Highest Impact)
CRITICAL_REMOTE_EXECUTION = {
    'name': 'Critical Remote Execution',
    'categories': [
        'Remote Code Execution (RCE)',
        'SQL Injection',
        'Command Injection',
        'Deserialization',
        'XXE (XML External Entity)',
        'Server-Side Template Injection (SSTI)'
    ],
    'scan_depth': 'maximum',
    'priority': 1,
    'description': 'Vulnerabilities that allow direct code execution or system compromise'
}

# Priority 2: Access Control Bypasses (High Impact)
ACCESS_CONTROL_BYPASSES = {
    'name': 'Access Control Bypasses',
    'categories': [
        'Broken Access Control',
        'Authentication Bypass',
        'Privilege Escalation',
        'Account Takeover (ATO)',
        'Identification and Authentication Failures',
        'Authorization Bypass'
    ],
    'scan_depth': 'deep',
    'priority': 2,
    'description': 'Vulnerabilities that bypass security controls and access restrictions'
}

# Priority 3: Server-Side Request Forgery (Medium-High Impact)
SSRF_VULNERABILITIES = {
    'name': 'Server-Side Request Forgery',
    'categories': [
        'Server-Side Request Forgery (SSRF)',
        'Internal Network Access',
        'Cloud Metadata Access',
        'Port Scanning via SSRF',
        'File System Access via SSRF'
    ],
    'scan_depth': 'deep',
    'priority': 3,
    'description': 'Vulnerabilities allowing server-side requests to unintended locations'
}

# Priority 4: Client-Side Injection (Medium Impact but High Frequency)
CLIENT_SIDE_INJECTION = {
    'name': 'Client-Side Injection',
    'categories': [
        'Cross-Site Scripting (XSS)',
        'DOM-based XSS',
        'Stored XSS',
        'Reflected XSS',
        'Cross-Site Request Forgery (CSRF)',
        'HTML Injection'
    ],
    'scan_depth': 'deep',
    'priority': 4,
    'description': 'Client-side vulnerabilities with potential for session hijacking'
}

# Priority 5: Cryptographic and Data Integrity (Medium Impact)
CRYPTO_DATA_INTEGRITY = {
    'name': 'Cryptographic and Data Integrity',
    'categories': [
        'Cryptographic Failures',
        'Software and Data Integrity Failures',
        'Weak Encryption',
        'Key Management Issues',
        'Certificate Validation Bypass',
        'Hash Collision'
    ],
    'scan_depth': 'medium',
    'priority': 5,
    'description': 'Vulnerabilities affecting data confidentiality and integrity'
}

# Define the focused scan configuration
FOCUSED_VULNERABILITY_CONFIG = [
    CRITICAL_REMOTE_EXECUTION,
    ACCESS_CONTROL_BYPASSES,
    SSRF_VULNERABILITIES,
    CLIENT_SIDE_INJECTION,
    CRYPTO_DATA_INTEGRITY
]

# Detailed scan techniques for each category
SCAN_TECHNIQUES = {
    'Remote Code Execution (RCE)': {
        'techniques': [
            'Command injection payloads',
            'Template injection testing',
            'File upload exploitation',
            'Deserialization attacks',
            'Expression language injection'
        ],
        'depth_level': 'maximum',
        'test_count': 50
    },
    
    'SQL Injection': {
        'techniques': [
            'Union-based injection',
            'Boolean-based blind injection',
            'Time-based blind injection',
            'Error-based injection',
            'Second-order injection'
        ],
        'depth_level': 'maximum',
        'test_count': 40
    },
    
    'Broken Access Control': {
        'techniques': [
            'Horizontal privilege escalation',
            'Vertical privilege escalation',
            'Direct object references',
            'Function-level access control',
            'File path manipulation'
        ],
        'depth_level': 'deep',
        'test_count': 30
    },
    
    'Server-Side Request Forgery (SSRF)': {
        'techniques': [
            'Internal network scanning',
            'Cloud metadata exploitation',
            'Protocol smuggling',
            'Blind SSRF detection',
            'DNS rebinding attacks'
        ],
        'depth_level': 'deep',
        'test_count': 25
    },
    
    'Cross-Site Scripting (XSS)': {
        'techniques': [
            'Reflected XSS testing',
            'Stored XSS validation',
            'DOM-based XSS analysis',
            'Content-type confusion',
            'Filter bypass techniques'
        ],
        'depth_level': 'deep',
        'test_count': 35
    },
    
    'Account Takeover (ATO)': {
        'techniques': [
            'Password reset exploitation',
            'Session fixation',
            'JWT token manipulation',
            'OAuth flow abuse',
            'Cookie hijacking'
        ],
        'depth_level': 'deep',
        'test_count': 20
    }
}

def get_focused_scan_config(scan_mode: str = 'focused') -> Dict[str, Any]:
    """
    Get configuration for focused, high-impact vulnerability scanning
    
    Args:
        scan_mode: Type of focused scan ('focused', 'critical_only', 'comprehensive')
    
    Returns:
        Dictionary with scan configuration
    """
    
    if scan_mode == 'critical_only':
        # Only scan for RCE and direct access control bypasses
        return {
            'categories': [CRITICAL_REMOTE_EXECUTION, ACCESS_CONTROL_BYPASSES],
            'max_scan_time': 1800,  # 30 minutes
            'depth': 'maximum',
            'test_count_multiplier': 2.0
        }
    
    elif scan_mode == 'comprehensive':
        # Scan all priority categories with high depth
        return {
            'categories': FOCUSED_VULNERABILITY_CONFIG,
            'max_scan_time': 7200,  # 2 hours
            'depth': 'deep',
            'test_count_multiplier': 1.5
        }
    
    else:  # focused (default)
        # Balanced approach - top 4 categories
        return {
            'categories': FOCUSED_VULNERABILITY_CONFIG[:4],
            'max_scan_time': 3600,  # 1 hour
            'depth': 'deep',
            'test_count_multiplier': 1.2
        }

def should_scan_vulnerability_category(category: str, scan_config: Dict[str, Any]) -> bool:
    """
    Determine if a vulnerability category should be scanned based on configuration
    
    Args:
        category: Vulnerability category name
        scan_config: Scan configuration from get_focused_scan_config
    
    Returns:
        bool: True if category should be scanned
    """
    for config_category in scan_config['categories']:
        if category in config_category['categories']:
            return True
    return False

def get_scan_depth_for_category(category: str) -> str:
    """
    Get the recommended scan depth for a vulnerability category
    
    Args:
        category: Vulnerability category name
    
    Returns:
        str: Scan depth ('maximum', 'deep', 'medium', 'surface')
    """
    if category in SCAN_TECHNIQUES:
        return SCAN_TECHNIQUES[category]['depth_level']
    
    # Default depth based on category priority
    for config in FOCUSED_VULNERABILITY_CONFIG:
        if category in config['categories']:
            return config['scan_depth']
    
    return 'surface'  # Default for unlisted categories

def get_test_techniques_for_category(category: str) -> List[str]:
    """
    Get specific test techniques for a vulnerability category
    
    Args:
        category: Vulnerability category name
    
    Returns:
        List of test techniques to employ
    """
    return SCAN_TECHNIQUES.get(category, {}).get('techniques', [])

def get_vulnerability_priority_score(vuln_category: str) -> int:
    """
    Get priority score for a vulnerability category (1 = highest priority)
    
    Args:
        vuln_category: Vulnerability category name
    
    Returns:
        int: Priority score (1-5, lower is higher priority)
    """
    for config in FOCUSED_VULNERABILITY_CONFIG:
        if vuln_category in config['categories']:
            return config['priority']
    
    return 10  # Lowest priority for uncategorized vulnerabilities

def filter_vulnerabilities_by_impact(vulnerabilities: List[Dict[str, Any]], 
                                   min_priority: int = 5) -> List[Dict[str, Any]]:
    """
    Filter vulnerabilities to only include high-impact categories
    
    Args:
        vulnerabilities: List of vulnerability findings
        min_priority: Maximum priority number to include (1-5)
    
    Returns:
        List of filtered high-impact vulnerabilities
    """
    filtered = []
    
    for vuln in vulnerabilities:
        category = vuln.get('category', vuln.get('type', 'Unknown'))
        priority = get_vulnerability_priority_score(category)
        
        if priority <= min_priority:
            vuln['priority_score'] = priority
            filtered.append(vuln)
        else:
            logger.debug(f"🔕 Excluded low-priority vulnerability: {vuln.get('title', 'Unknown')} (priority {priority})")
    
    # Sort by priority score (lower numbers = higher priority)
    filtered.sort(key=lambda x: (x.get('priority_score', 10), x.get('cvss', 0)), reverse=True)
    
    return filtered

def get_scan_statistics() -> Dict[str, Any]:
    """
    Get statistics about the focused vulnerability configuration
    
    Returns:
        Dictionary with configuration statistics
    """
    total_categories = sum(len(config['categories']) for config in FOCUSED_VULNERABILITY_CONFIG)
    technique_count = sum(len(techniques.get('techniques', [])) for techniques in SCAN_TECHNIQUES.values())
    
    return {
        'priority_groups': len(FOCUSED_VULNERABILITY_CONFIG),
        'total_categories': total_categories,
        'total_techniques': technique_count,
        'focus_areas': [config['name'] for config in FOCUSED_VULNERABILITY_CONFIG],
        'estimated_scan_time': {
            'critical_only': '30 minutes',
            'focused': '1 hour',
            'comprehensive': '2 hours'
        }
    }
