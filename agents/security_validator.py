# Security Validator - Target Validation and Safety Checks
"""
Validates targets to prevent scanning unauthorized systems and implements safety measures.
"""

import socket
import ipaddress
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)

class SecurityValidator:
    """Validates targets to prevent scanning unauthorized systems"""
    
    # Blocked domains and IP ranges
    BLOCKED_DOMAINS = [
        'localhost', '127.0.0.1', '::1', 'internal', 'local',
        'intranet', 'corp', 'corporate', 'private'
    ]
    
    # Common internal TLDs
    INTERNAL_TLDS = ['.local', '.internal', '.corp', '.lan', '.intranet']
    
    @staticmethod
    def validate_target(target_url: str) -> bool:
        """
        Validate that target is safe to scan
        
        Args:
            target_url: The target URL to validate
            
        Returns:
            bool: True if target is safe to scan
            
        Raises:
            ValueError: If target is not safe to scan
        """
        try:
            # Parse URL
            parsed = urlparse(target_url)
            hostname = parsed.hostname
            
            if not hostname:
                raise ValueError("Invalid URL - no hostname found")
            
            # Check for blocked domains
            SecurityValidator._check_blocked_domains(hostname)
            
            # Check for internal TLDs
            SecurityValidator._check_internal_tlds(hostname)
            
            # Resolve IP address and validate
            ip = SecurityValidator._resolve_and_validate_ip(hostname)
            
            logger.info(f"✅ Target validation passed: {target_url} -> {ip}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Target validation failed: {e}")
            raise
    
    @staticmethod
    def _check_blocked_domains(hostname: str):
        """Check if hostname contains blocked domains"""
        hostname_lower = hostname.lower()
        
        for blocked in SecurityValidator.BLOCKED_DOMAINS:
            if blocked in hostname_lower:
                raise ValueError(f"Blocked domain detected: {hostname}")
    
    @staticmethod
    def _check_internal_tlds(hostname: str):
        """Check for internal TLDs"""
        hostname_lower = hostname.lower()
        
        for tld in SecurityValidator.INTERNAL_TLDS:
            if hostname_lower.endswith(tld):
                raise ValueError(f"Internal TLD not allowed: {hostname}")
    
    @staticmethod
    def _resolve_and_validate_ip(hostname: str) -> str:
        """Resolve hostname and validate IP address"""
        try:
            ip = socket.gethostbyname(hostname)
        except socket.gaierror:
            raise ValueError(f"Cannot resolve hostname: {hostname}")
        
        # Validate IP address
        SecurityValidator._validate_ip_address(ip, hostname)
        
        return ip
    
    @staticmethod
    def _validate_ip_address(ip: str, hostname: str):
        """Validate that IP address is not private/internal"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check for private IP ranges
            if ip_obj.is_private:
                raise ValueError(f"Cannot scan private IP address: {ip} ({hostname})")
            
            # Check for loopback
            if ip_obj.is_loopback:
                raise ValueError(f"Cannot scan loopback address: {ip} ({hostname})")
            
            # Check for link-local
            if ip_obj.is_link_local:
                raise ValueError(f"Cannot scan link-local address: {ip} ({hostname})")
            
            # Check for multicast
            if ip_obj.is_multicast:
                raise ValueError(f"Cannot scan multicast address: {ip} ({hostname})")
            
            # Additional checks for specific ranges
            SecurityValidator._check_special_ip_ranges(ip_obj, hostname)
            
        except ipaddress.AddressValueError:
            raise ValueError(f"Invalid IP address: {ip}")
    
    @staticmethod
    def _check_special_ip_ranges(ip_obj: ipaddress.IPv4Address, hostname: str):
        """Check for additional special IP ranges"""
        ip_str = str(ip_obj)
        
        # Block additional ranges
        blocked_ranges = [
            '0.0.0.0/8',      # "This" network
            '169.254.0.0/16', # Link-local
            '224.0.0.0/4',    # Multicast
            '240.0.0.0/4',    # Reserved
        ]
        
        for range_str in blocked_ranges:
            network = ipaddress.ip_network(range_str)
            if ip_obj in network:
                raise ValueError(f"Cannot scan IP in blocked range {range_str}: {ip_str} ({hostname})")
    
    @staticmethod
    def validate_scan_permission(target_url: str, user_consent: bool = False) -> bool:
        """
        Validate that user has permission to scan target
        
        Args:
            target_url: Target URL to scan
            user_consent: Whether user has given explicit consent
            
        Returns:
            bool: True if scan is permitted
            
        Raises:
            ValueError: If scan is not permitted
        """
        if not user_consent:
            raise ValueError("Explicit user consent required for security scanning")
        
        # Additional permission checks could be added here
        # e.g., domain ownership verification, whitelist checks, etc.
        
        return True
    
    @staticmethod
    def get_safe_scan_config() -> dict:
        """
        Get safe scanning configuration parameters
        
        Returns:
            dict: Safe scanning configuration
        """
        return {
            'max_scan_time': 3600,  # 1 hour maximum
            'max_concurrent_requests': 10,
            'request_delay': 1.0,  # 1 second between requests
            'timeout': 30,  # 30 second timeout
            'max_redirects': 5,
            'user_agent': 'AI-Bug-Bounty-Scanner/1.0 (Security Research)',
            'respect_robots_txt': True,
            'max_depth': 3,  # Maximum crawl depth
            'max_pages': 100  # Maximum pages to scan
        }
    
    @staticmethod
    def log_scan_attempt(target_url: str, user_ip: str, scan_type: str):
        """
        Log scan attempt for audit purposes
        
        Args:
            target_url: Target being scanned
            user_ip: IP address of user initiating scan
            scan_type: Type of scan being performed
        """
        logger.info(f"SCAN_AUDIT: {scan_type} scan initiated against {target_url} by {user_ip}")
