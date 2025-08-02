# Recon Agent - Advanced Network Reconnaissance and Asset Discovery
"""
Enhanced reconnaissance agent with comprehensive discovery capabilities:
- Advanced subdomain enumeration with multiple techniques
- Web crawling and endpoint discovery
- Directory and file brute-forcing
- API endpoint discovery
- DNS wildcard detection
- Technology fingerprinting
- Integration-ready for external tools (amass, subfinder, etc.)
"""

# Optional nmap import
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    nmap = None

import socket
import dns.resolver
import asyncio
import time
import json
import re
import subprocess
import os
import threading

import requests
from urllib.parse import urlparse, urljoin, urlunparse
from urllib.robotparser import RobotFileParser
from typing import Dict, List, Any, Set, Optional, Tuple
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
import ssl
import itertools

from .security_validator import SecurityValidator
from .agent_config_utils import is_test_enabled, log_test_execution
from config import Config

logger = logging.getLogger(__name__)

class ReconAgent:
    """Advanced reconnaissance agent with comprehensive discovery capabilities"""
    
    def __init__(self):
        # Try to initialize nmap, fall back to socket scanning if not available
        if NMAP_AVAILABLE:
            try:
                self.nm = nmap.PortScanner()
                self.nmap_available = True
                logger.info("âœ… Nmap available for advanced port scanning")
            except Exception as e:
                self.nm = None
                self.nmap_available = False
                logger.warning(f"âš ï¸ Nmap initialization failed, using socket-based scanning: {e}")
        else:
            self.nm = None
            self.nmap_available = False
            logger.warning("âš ï¸ Nmap not installed, using socket-based scanning")

        self.session = requests.Session()
        self.config = SecurityValidator.get_safe_scan_config()

        # Configure session with safe defaults
        self.session.headers.update({
            'User-Agent': self.config['user_agent']
        })
        self.session.timeout = self.config['timeout']
        
        # Advanced discovery configurations
        self.discovered_endpoints = set()
        self.discovered_directories = set()
        self.discovered_files = set()
        self.discovered_apis = set()
        self.subdomains_found = set()
        
        # Common wordlists for discovery
        self.common_directories = [
            'admin', 'administrator', 'api', 'app', 'apps', 'backup', 'backups',
            'bin', 'blog', 'cache', 'cgi', 'cgi-bin', 'config', 'configs',
            'content', 'css', 'data', 'database', 'db', 'debug', 'dev',
            'development', 'docs', 'documentation', 'download', 'downloads',
            'etc', 'files', 'ftp', 'help', 'home', 'html', 'images', 'img',
            'include', 'includes', 'js', 'json', 'lib', 'library', 'log',
            'logs', 'mail', 'media', 'old', 'portal', 'private', 'public',
            'resources', 'scripts', 'search', 'secure', 'security', 'server',
            'service', 'services', 'sql', 'src', 'static', 'stats', 'status',
            'storage', 'temp', 'templates', 'test', 'testing', 'tmp', 'tools',
            'upload', 'uploads', 'user', 'users', 'var', 'web', 'webmail',
            'wp', 'wp-admin', 'wp-content', 'wp-includes', 'www', 'xml'
        ]
        
        self.common_files = [
            'robots.txt', 'sitemap.xml', 'sitemap_index.xml', '.htaccess',
            'web.config', 'crossdomain.xml', 'clientaccesspolicy.xml',
            'config.php', 'configuration.php', 'settings.php', 'database.php',
            'db.php', 'connect.php', 'connection.php', 'config.json',
            'settings.json', 'package.json', 'composer.json', 'webpack.config.js',
            'gulpfile.js', 'gruntfile.js', '.env', '.env.local', '.env.production',
            'readme.txt', 'README.md', 'CHANGELOG.md', 'LICENSE', 'version.txt',
            'info.php', 'phpinfo.php', 'test.php', 'index.php~', 'backup.sql',
            'database.sql', 'dump.sql', '.git/config', '.svn/entries',
            '.DS_Store', 'thumbs.db', 'desktop.ini', 'error_log', 'access_log'
        ]
        
        self.api_endpoints = [
            'api', 'api/v1', 'api/v2', 'api/v3', 'rest', 'restapi', 'graphql',
            'webhook', 'webhooks', 'oauth', 'auth', 'login', 'register',
            'users', 'user', 'profile', 'account', 'admin', 'dashboard',
            'search', 'upload', 'download', 'file', 'files', 'data',
            'json', 'xml', 'rss', 'feed', 'status', 'health', 'ping'
        ]
        
        # Extended subdomain wordlist
        self.extended_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging',
            'blog', 'shop', 'store', 'support', 'help', 'docs', 'cdn',
            'static', 'assets', 'img', 'images', 'media', 'files', 'portal',
            'secure', 'vpn', 'remote', 'access', 'login', 'account', 'user',
            'users', 'client', 'customer', 'demo', 'beta', 'alpha', 'preview',
            'mobile', 'm', 'wap', 'old', 'new', 'v1', 'v2', 'v3', 'backup',
            'mirror', 'copy', 'archive', 'temp', 'tmp', 'cache', 'proxy',
            'lb', 'loadbalancer', 'dns', 'ns', 'ns1', 'ns2', 'mx', 'mx1',
            'smtp', 'pop', 'imap', 'webmail', 'exchange', 'owa', 'autodiscover',
            'ldap', 'ad', 'dc', 'pdc', 'bdc', 'sql', 'db', 'database',
            'mysql', 'oracle', 'mssql', 'postgres', 'redis', 'mongo',
            'elasticsearch', 'kibana', 'grafana', 'jenkins', 'gitlab',
            'github', 'svn', 'git', 'repository', 'repo', 'source', 'code'
        ]
        
    async def scan_target(self, target_url: str) -> Dict[str, Any]:
        """
        Enhanced main scanning function for comprehensive reconnaissance
        
        Args:
            target_url: Target URL to scan
            
        Returns:
            Dict containing comprehensive scan results and vulnerabilities
        """
        try:
            # Validate target first
            SecurityValidator.validate_target(target_url)
            
            # Extract domain from URL
            domain = self._extract_domain(target_url)
            logger.info(f"ðŸ” Starting enhanced reconnaissance scan for: {domain}")
            
            results = {
                'target': target_url,
                'domain': domain,
                'timestamp': time.time(),
                'scan_type': 'enhanced_reconnaissance',
                'vulnerabilities': [],
                'discovery_stats': {}
            }
            
            # Clear previous discoveries
            self._clear_discovery_cache()
            
            # Perform comprehensive reconnaissance tasks
            try:
                # DNS enumeration if enabled
                if is_test_enabled('recon', 'dns_enumeration'):
                    logger.info("ðŸ“¡ Performing enhanced DNS enumeration...")
                    dns_info = await self._enhanced_dns_enumeration(domain)
                    results['dns_info'] = dns_info
                    log_test_execution('recon', 'dns_enumeration', True)
                else:
                    results['dns_info'] = {'records': []}
                    log_test_execution('recon', 'dns_enumeration', False)
                
                logger.info("ðŸ”Œ Performing comprehensive port scan...")
                port_info = await self._comprehensive_port_scan(domain)
                results['port_info'] = port_info
                
                # Subdomain enumeration if enabled
                if is_test_enabled('recon', 'subdomain_enumeration'):
                    logger.info("ðŸŒ Performing advanced subdomain enumeration...")
                    subdomains = await self._advanced_subdomain_enumeration(domain)
                    results['subdomains'] = list(subdomains)
                    log_test_execution('recon', 'subdomain_enumeration', True)
                else:
                    results['subdomains'] = []
                    log_test_execution('recon', 'subdomain_enumeration', False)
                
                logger.info("ï¿½ï¸ Performing web crawling and endpoint discovery...")
                web_discovery = await self._web_discovery(target_url)
                results['web_discovery'] = web_discovery
                
                logger.info("ðŸ“ Performing directory and file brute-forcing...")
                directory_discovery = await self._directory_bruteforce(target_url)
                results['directory_discovery'] = directory_discovery
                
                logger.info("ðŸ”— Performing API endpoint discovery...")
                api_discovery = await self._api_discovery(target_url)
                results['api_discovery'] = api_discovery
                
                logger.info("ðŸ”§ Performing advanced technology detection...")
                tech_info = await self._advanced_technology_detection(target_url)
                results['technologies'] = tech_info
                
                logger.info("ï¿½ï¸ Checking for security misconfigurations...")
                security_checks = await self._security_misconfiguration_checks(target_url)
                results['security_checks'] = security_checks

                logger.info(" Running external tool integrations...")
                external_integrations = await self.run_external_tool_integrations(target_url, domain)
                results['external_integrations'] = external_integrations

                logger.info(" Analyzing comprehensive findings...")
                vulnerabilities = self._analyze_enhanced_findings(results)
                results['vulnerabilities'] = vulnerabilities
                
                # Update discovery statistics
                results['discovery_stats'] = {
                    'total_subdomains': len(self.subdomains_found),
                    'total_endpoints': len(self.discovered_endpoints),
                    'total_directories': len(self.discovered_directories),
                    'total_files': len(self.discovered_files),
                    'total_apis': len(self.discovered_apis),
                    'total_vulnerabilities': len(vulnerabilities)
                }
                
                logger.info(f"âœ… Enhanced reconnaissance completed:")
                logger.info(f"   ðŸ“Š {len(self.subdomains_found)} subdomains discovered")
                logger.info(f"   ðŸ”— {len(self.discovered_endpoints)} endpoints found")
                logger.info(f"   ðŸ“ {len(self.discovered_directories)} directories found")
                logger.info(f"   ðŸ“„ {len(self.discovered_files)} files discovered")
                logger.info(f"   ðŸ”Œ {len(self.discovered_apis)} API endpoints found")
                logger.info(f"   âš ï¸ {len(vulnerabilities)} potential security issues identified")
                
            except Exception as scan_error:
                logger.error(f"âŒ Enhanced scan error: {scan_error}")
                results['error'] = str(scan_error)
            
            return results
            
        except Exception as e:
            logger.error(f"âŒ Enhanced reconnaissance scan failed: {e}")
            raise
    
    def _clear_discovery_cache(self):
        """Clear previous discovery results"""
        self.discovered_endpoints.clear()
        self.discovered_directories.clear()
        self.discovered_files.clear()
        self.discovered_apis.clear()
        self.subdomains_found.clear()
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        parsed = urlparse(url)
        return parsed.netloc or parsed.path.split('/')[0]
    
    async def _enhanced_dns_enumeration(self, domain: str) -> Dict[str, Any]:
        """Perform comprehensive DNS enumeration with wildcard detection"""
        dns_info = {
            'a_records': [],
            'aaaa_records': [],
            'mx_records': [],
            'ns_records': [],
            'txt_records': [],
            'cname_records': [],
            'soa_record': None,
            'srv_records': [],
            'ptr_records': [],
            'wildcard_detection': {},
            'zone_transfer_attempt': None
        }
        
        record_types = [
            ('A', 'a_records'),
            ('AAAA', 'aaaa_records'),
            ('MX', 'mx_records'),
            ('NS', 'ns_records'),
            ('TXT', 'txt_records'),
            ('CNAME', 'cname_records'),
            ('SOA', 'soa_record'),
            ('SRV', 'srv_records'),
            ('PTR', 'ptr_records')
        ]
        
        for record_type, key in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                if record_type == 'SOA':
                    dns_info[key] = str(answers[0]) if answers else None
                else:
                    dns_info[key] = [str(rdata) for rdata in answers]
                    
                # Rate limiting
                await asyncio.sleep(0.1)
                
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, Exception):
                pass
        
        # Wildcard detection
        dns_info['wildcard_detection'] = await self._detect_dns_wildcards(domain)
        
        # Attempt zone transfer (ethical testing only)
        dns_info['zone_transfer_attempt'] = await self._attempt_zone_transfer(domain)
        
        return dns_info
    
    async def _detect_dns_wildcards(self, domain: str) -> Dict[str, Any]:
        """Detect DNS wildcard configurations"""
        wildcard_info = {
            'has_wildcard': False,
            'wildcard_ip': None,
            'test_results': []
        }
        
        # Test with random subdomains
        random_tests = [
            f"nonexistent{int(time.time())}.{domain}",
            f"random{hash(domain) % 10000}.{domain}",
            f"test{int(time.time()) % 1000}.{domain}"
        ]
        
        for test_domain in random_tests:
            try:
                result = socket.gethostbyname(test_domain)
                wildcard_info['test_results'].append({
                    'domain': test_domain,
                    'resolves_to': result
                })
                wildcard_info['has_wildcard'] = True
                wildcard_info['wildcard_ip'] = result
                
            except socket.gaierror:
                wildcard_info['test_results'].append({
                    'domain': test_domain,
                    'resolves_to': None
                })
            
            await asyncio.sleep(0.2)
        
        return wildcard_info
    
    async def _attempt_zone_transfer(self, domain: str) -> Dict[str, Any]:
        """Attempt DNS zone transfer (for educational purposes)"""
        zone_transfer_info = {
            'attempted': False,
            'successful': False,
            'name_servers': [],
            'error': None
        }
        
        try:
            # Get name servers
            ns_answers = dns.resolver.resolve(domain, 'NS')
            name_servers = [str(ns) for ns in ns_answers]
            zone_transfer_info['name_servers'] = name_servers
            zone_transfer_info['attempted'] = True
            
            # Note: We don't actually perform zone transfer for ethical reasons
            # This is just to identify if zone transfer might be possible
            zone_transfer_info['note'] = 'Zone transfer not attempted for ethical reasons'
            
        except Exception as e:
            zone_transfer_info['error'] = str(e)
        
        return zone_transfer_info
    
    async def _comprehensive_port_scan(self, domain: str) -> Dict[str, Any]:
        """Perform comprehensive port scan with service detection"""
        port_info = {
            'open_ports': [],
            'services': {},
            'scan_method': 'socket_fallback' if not self.nmap_available else 'nmap',
            'port_ranges': {
                'common': [],
                'extended': [],
                'all_scanned': []
            }
        }

        if self.nmap_available:
            try:
                # Comprehensive port ranges
                common_ports = '21,22,23,25,53,80,110,143,443,993,995,8080,8443,3389,5432,3306,1433,6379,27017'
                extended_ports = '1-1000,8000-8999,9000-9999'

                logger.info(f"ðŸ”Œ Scanning ports for {domain} using nmap")

                # Scan common ports first
                scan_args = '-sS -T3 --max-retries 2 --host-timeout 60s --max-rate 50 -sV'
                common_scan = self.nm.scan(domain, common_ports, arguments=scan_args)
                
                if domain in common_scan['scan']:
                    host_info = common_scan['scan'][domain]
                    if 'tcp' in host_info:
                        for port, port_detail in host_info['tcp'].items():
                            if port_detail['state'] == 'open':
                                port_info['open_ports'].append(port)
                                port_info['port_ranges']['common'].append(port)
                                port_info['services'][port] = {
                                    'service': port_detail.get('name', 'unknown'),
                                    'version': port_detail.get('version', 'unknown'),
                                    'product': port_detail.get('product', 'unknown'),
                                    'extrainfo': port_detail.get('extrainfo', ''),
                                    'state': port_detail['state'],
                                    'reason': port_detail.get('reason', 'unknown')
                                }

                # If common ports found open services, scan extended range
                if port_info['open_ports']:
                    logger.info(f"ðŸ”Œ Found {len(port_info['open_ports'])} open ports, scanning extended range...")
                    extended_scan = self.nm.scan(domain, extended_ports, arguments='-sS -T2 --max-retries 1')
                    
                    if domain in extended_scan['scan'] and 'tcp' in extended_scan['scan'][domain]:
                        for port, port_detail in extended_scan['scan'][domain]['tcp'].items():
                            if port_detail['state'] == 'open' and port not in port_info['open_ports']:
                                port_info['open_ports'].append(port)
                                port_info['port_ranges']['extended'].append(port)
                                port_info['services'][port] = {
                                    'service': port_detail.get('name', 'unknown'),
                                    'version': port_detail.get('version', 'unknown'),
                                    'product': port_detail.get('product', 'unknown'),
                                    'state': port_detail['state']
                                }

                port_info['port_ranges']['all_scanned'] = port_info['open_ports']
                return port_info

            except Exception as e:
                logger.warning(f"âš ï¸ Nmap comprehensive scan failed, falling back to socket check: {e}")

        # Fallback to enhanced socket-based scanning
        logger.info(f"ðŸ”Œ Scanning ports for {domain} using enhanced socket method")
        
        # Extended port list for socket scanning
        critical_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 8080, 8443]
        extended_ports = [1433, 3306, 5432, 6379, 27017, 5672, 11211, 9200, 9300]
        web_ports = [8000, 8001, 8008, 8888, 9000, 9090, 9999]
        
        all_ports = critical_ports + extended_ports + web_ports
        
        # Use threading for faster socket scanning
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_port = {
                executor.submit(self._check_port_socket, domain, port): port 
                for port in all_ports
            }
            
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    if future.result():
                        port_info['open_ports'].append(port)
                        service_name = self._get_service_name(port)
                        banner = await self._grab_banner(domain, port)
                        port_info['services'][port] = {
                            'service': service_name,
                            'state': 'open',
                            'method': 'socket',
                            'banner': banner
                        }
                except Exception:
                    pass

        port_info['port_ranges']['all_scanned'] = port_info['open_ports']
        return port_info
    
    def _check_port_socket(self, domain: str, port: int) -> bool:
        """Check if a port is open using socket"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((domain, port))
            sock.close()
            return result == 0
        except:
            return False
    
    async def _grab_banner(self, domain: str, port: int) -> str:
        """Attempt to grab service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((domain, port))
            sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner[:200]  # Limit banner length
        except:
            return ''
    
    def _get_service_name(self, port: int) -> str:
        """Get common service name for port"""
        common_services = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
            53: 'dns', 80: 'http', 110: 'pop3', 143: 'imap',
            443: 'https', 993: 'imaps', 995: 'pop3s',
            8080: 'http-alt', 8443: 'https-alt'
        }
        return common_services.get(port, 'unknown')
    
    async def _advanced_subdomain_enumeration(self, domain: str) -> Set[str]:
        """Advanced subdomain enumeration with multiple techniques"""
        logger.info(f"ðŸŒ Starting advanced subdomain enumeration for {domain}")
        
        # Use dictionary-based enumeration
        dict_subdomains = await self._dictionary_subdomain_enum(domain)
        self.subdomains_found.update(dict_subdomains)
        
        # Try certificate transparency logs
        ct_subdomains = await self._certificate_transparency_enum(domain)
        self.subdomains_found.update(ct_subdomains)
        
        # Try DNS brute-forcing with permutations
        perm_subdomains = await self._permutation_subdomain_enum(domain)
        self.subdomains_found.update(perm_subdomains)
        
        # Try reverse DNS lookups
        reverse_subdomains = await self._reverse_dns_enum(domain)
        self.subdomains_found.update(reverse_subdomains)
        
        logger.info(f"âœ… Found {len(self.subdomains_found)} unique subdomains")
        return self.subdomains_found
    
    async def _dictionary_subdomain_enum(self, domain: str) -> Set[str]:
        """Dictionary-based subdomain enumeration"""
        subdomains = set()
        
        # Use threading for faster DNS resolution
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_subdomain = {
                executor.submit(self._check_subdomain, f"{sub}.{domain}"): f"{sub}.{domain}"
                for sub in self.extended_subdomains
            }
            
            for future in as_completed(future_to_subdomain):
                subdomain = future_to_subdomain[future]
                try:
                    if future.result():
                        subdomains.add(subdomain)
                        logger.info(f"âœ… Found subdomain: {subdomain}")
                except Exception:
                    pass
        
        return subdomains
    
    def _check_subdomain(self, subdomain: str) -> bool:
        """Check if subdomain exists"""
        try:
            socket.gethostbyname(subdomain)
            return True
        except socket.gaierror:
            return False
    
    async def _certificate_transparency_enum(self, domain: str) -> Set[str]:
        """Enumerate subdomains using Certificate Transparency logs"""
        subdomains = set()
        
        try:
            # Query crt.sh for certificate transparency data
            ct_url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = self.session.get(ct_url, timeout=15)
            
            if response.status_code == 200:
                certificates = response.json()
                for cert in certificates:
                    if 'name_value' in cert:
                        names = cert['name_value'].split('\n')
                        for name in names:
                            name = name.strip()
                            if name.endswith(f'.{domain}') or name == domain:
                                # Validate the subdomain exists
                                if self._check_subdomain(name):
                                    subdomains.add(name)
                                    logger.info(f"âœ… Found CT subdomain: {name}")
                                    
                                    # Limit to prevent overwhelming
                                    if len(subdomains) > 100:
                                        break
                        
                        if len(subdomains) > 100:
                            break
                            
        except Exception as e:
            logger.warning(f"âš ï¸ Certificate transparency lookup failed: {e}")
        
        return subdomains
    
    async def _permutation_subdomain_enum(self, domain: str) -> Set[str]:
        """Generate subdomain permutations and test them"""
        subdomains = set()
        
        # Generate permutations based on found subdomains
        base_words = ['dev', 'test', 'staging', 'prod', 'api', 'admin']
        suffixes = ['01', '02', '1', '2', 'new', 'old']
        
        permutations = []
        for base in base_words:
            permutations.append(base)
            for suffix in suffixes:
                permutations.extend([f"{base}{suffix}", f"{base}-{suffix}", f"{base}_{suffix}"])
        
        # Test permutations
        with ThreadPoolExecutor(max_workers=30) as executor:
            future_to_subdomain = {
                executor.submit(self._check_subdomain, f"{perm}.{domain}"): f"{perm}.{domain}"
                for perm in permutations[:100]  # Limit permutations
            }
            
            for future in as_completed(future_to_subdomain):
                subdomain = future_to_subdomain[future]
                try:
                    if future.result():
                        subdomains.add(subdomain)
                        logger.info(f"âœ… Found permutation subdomain: {subdomain}")
                except Exception:
                    pass
        
        return subdomains
    
    async def _reverse_dns_enum(self, domain: str) -> Set[str]:
        """Attempt reverse DNS enumeration"""
        subdomains = set()
        
        try:
            # Get IP addresses for the main domain
            ip_addresses = socket.gethostbyname_ex(domain)[2]
            
            for ip in ip_addresses[:5]:  # Limit to first 5 IPs
                try:
                    # Get IP network range (simple approach)
                    ip_parts = ip.split('.')
                    network_base = '.'.join(ip_parts[:3])
                    
                    # Check a few IPs in the same subnet
                    for i in range(max(1, int(ip_parts[3]) - 5), min(255, int(ip_parts[3]) + 5)):
                        check_ip = f"{network_base}.{i}"
                        try:
                            hostname = socket.gethostbyaddr(check_ip)[0]
                            if domain in hostname:
                                subdomains.add(hostname)
                                logger.info(f"âœ… Found reverse DNS subdomain: {hostname}")
                        except socket.herror:
                            pass
                        
                        # Rate limiting
                        await asyncio.sleep(0.1)
                        
                except Exception:
                    pass
        
        except Exception as e:
            logger.warning(f"âš ï¸ Reverse DNS enumeration failed: {e}")
        
        return subdomains
    
    async def _web_discovery(self, target_url: str) -> Dict[str, Any]:
        """Comprehensive web discovery including crawling and robots.txt analysis"""
        web_discovery = {
            'robots_txt': {},
            'sitemap_xml': {},
            'crawled_endpoints': [],
            'forms_found': [],
            'js_files': [],
            'css_files': [],
            'external_links': [],
            'email_addresses': []
        }
        
        # Check robots.txt
        web_discovery['robots_txt'] = await self._analyze_robots_txt(target_url)
        
        # Check sitemap.xml
        web_discovery['sitemap_xml'] = await self._analyze_sitemap(target_url)
        
        # Perform web crawling
        crawl_results = await self._web_crawl(target_url, max_pages=20)
        web_discovery.update(crawl_results)
        
        return web_discovery
    
    async def _analyze_robots_txt(self, target_url: str) -> Dict[str, Any]:
        """Analyze robots.txt for discovery opportunities"""
        robots_info = {
            'exists': False,
            'disallowed_paths': [],
            'allowed_paths': [],
            'sitemaps': [],
            'crawl_delay': None,
            'user_agents': []
        }
        
        try:
            robots_url = urljoin(target_url, '/robots.txt')
            response = self.session.get(robots_url, timeout=10)
            
            if response.status_code == 200:
                robots_info['exists'] = True
                content = response.text
                
                # Parse robots.txt
                for line in content.split('\n'):
                    line = line.strip().lower()
                    if line.startswith('disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path and path != '/':
                            robots_info['disallowed_paths'].append(path)
                            self.discovered_endpoints.add(urljoin(target_url, path))
                    
                    elif line.startswith('allow:'):
                        path = line.split(':', 1)[1].strip()
                        if path:
                            robots_info['allowed_paths'].append(path)
                            self.discovered_endpoints.add(urljoin(target_url, path))
                    
                    elif line.startswith('sitemap:'):
                        sitemap_url = line.split(':', 1)[1].strip()
                        robots_info['sitemaps'].append(sitemap_url)
                    
                    elif line.startswith('crawl-delay:'):
                        delay = line.split(':', 1)[1].strip()
                        robots_info['crawl_delay'] = delay
                    
                    elif line.startswith('user-agent:'):
                        ua = line.split(':', 1)[1].strip()
                        robots_info['user_agents'].append(ua)
                
                logger.info(f"âœ… Analyzed robots.txt: {len(robots_info['disallowed_paths'])} disallowed paths found")
                
        except Exception as e:
            logger.warning(f"âš ï¸ Could not analyze robots.txt: {e}")
        
        return robots_info
    
    async def _analyze_sitemap(self, target_url: str) -> Dict[str, Any]:
        """Analyze sitemap.xml for URL discovery"""
        sitemap_info = {
            'exists': False,
            'urls_found': [],
            'total_urls': 0
        }
        
        sitemap_urls = [
            '/sitemap.xml',
            '/sitemap_index.xml',
            '/sitemaps.xml',
            '/sitemap.txt'
        ]
        
        for sitemap_path in sitemap_urls:
            try:
                sitemap_url = urljoin(target_url, sitemap_path)
                response = self.session.get(sitemap_url, timeout=10)
                
                if response.status_code == 200:
                    sitemap_info['exists'] = True
                    
                    # Parse XML sitemap
                    if sitemap_path.endswith('.xml'):
                        try:
                            from xml.etree import ElementTree as ET
                            root = ET.fromstring(response.text)
                            
                            # Extract URLs from sitemap
                            for url_element in root.iter():
                                if url_element.tag.endswith('loc'):
                                    url = url_element.text
                                    if url:
                                        sitemap_info['urls_found'].append(url)
                                        self.discovered_endpoints.add(url)
                                        
                                        # Limit to prevent overwhelming
                                        if len(sitemap_info['urls_found']) > 200:
                                            break
                            
                        except Exception as parse_error:
                            logger.warning(f"âš ï¸ Could not parse sitemap XML: {parse_error}")
                    
                    # Parse text sitemap
                    else:
                        for line in response.text.split('\n'):
                            url = line.strip()
                            if url.startswith('http'):
                                sitemap_info['urls_found'].append(url)
                                self.discovered_endpoints.add(url)
                    
                    sitemap_info['total_urls'] = len(sitemap_info['urls_found'])
                    logger.info(f"âœ… Analyzed sitemap: {sitemap_info['total_urls']} URLs found")
                    break
                    
            except Exception as e:
                logger.warning(f"âš ï¸ Could not analyze sitemap {sitemap_path}: {e}")
        
        return sitemap_info
    
    async def _web_crawl(self, target_url: str, max_pages: int = 20) -> Dict[str, Any]:
        """Perform limited web crawling to discover endpoints"""
        crawl_results = {
            'crawled_endpoints': [],
            'forms_found': [],
            'js_files': [],
            'css_files': [],
            'external_links': [],
            'email_addresses': []
        }
        
        visited_urls = set()
        urls_to_visit = [target_url]
        pages_crawled = 0
        
        domain = self._extract_domain(target_url)
        
        while urls_to_visit and pages_crawled < max_pages:
            current_url = urls_to_visit.pop(0)
            
            if current_url in visited_urls:
                continue
                
            try:
                response = self.session.get(current_url, timeout=10, allow_redirects=True)
                
                if response.status_code == 200 and 'text/html' in response.headers.get('content-type', ''):
                    visited_urls.add(current_url)
                    crawl_results['crawled_endpoints'].append(current_url)
                    self.discovered_endpoints.add(current_url)
                    pages_crawled += 1
                    
                    # Parse HTML content
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Find links
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        full_url = urljoin(current_url, href)
                        parsed_url = urlparse(full_url)
                        
                        # Add internal links to crawl queue
                        if domain in parsed_url.netloc and full_url not in visited_urls:
                            urls_to_visit.append(full_url)
                        elif domain not in parsed_url.netloc and parsed_url.netloc:
                            crawl_results['external_links'].append(full_url)
                    
                    # Find forms
                    for form in soup.find_all('form'):
                        form_info = {
                            'action': form.get('action', ''),
                            'method': form.get('method', 'GET').upper(),
                            'inputs': []
                        }
                        
                        for input_tag in form.find_all('input'):
                            form_info['inputs'].append({
                                'name': input_tag.get('name', ''),
                                'type': input_tag.get('type', 'text'),
                                'value': input_tag.get('value', '')
                            })
                        
                        crawl_results['forms_found'].append(form_info)
                    
                    # Find JavaScript files
                    for script in soup.find_all('script', src=True):
                        js_url = urljoin(current_url, script['src'])
                        crawl_results['js_files'].append(js_url)
                        self.discovered_endpoints.add(js_url)
                    
                    # Find CSS files
                    for link in soup.find_all('link', rel='stylesheet', href=True):
                        css_url = urljoin(current_url, link['href'])
                        crawl_results['css_files'].append(css_url)
                        self.discovered_endpoints.add(css_url)
                    
                    # Find email addresses
                    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                    emails = re.findall(email_pattern, response.text)
                    crawl_results['email_addresses'].extend(emails)
                    
                    # Rate limiting
                    await asyncio.sleep(1)
                
            except Exception as e:
                logger.warning(f"âš ï¸ Error crawling {current_url}: {e}")
        
        # Remove duplicates
        crawl_results['js_files'] = list(set(crawl_results['js_files']))
        crawl_results['css_files'] = list(set(crawl_results['css_files']))
        crawl_results['external_links'] = list(set(crawl_results['external_links']))
        crawl_results['email_addresses'] = list(set(crawl_results['email_addresses']))
        
        logger.info(f"âœ… Web crawling completed: {pages_crawled} pages crawled")
        return crawl_results
    
    async def _directory_bruteforce(self, target_url: str) -> Dict[str, Any]:
        """Perform directory and file brute-forcing"""
        directory_discovery = {
            'directories_found': [],
            'files_found': [],
            'interesting_files': [],
            'total_requests': 0,
            'response_codes': {}
        }
        
        # Directory brute-forcing
        logger.info("ðŸ“ Starting directory brute-force...")
        dir_results = await self._bruteforce_directories(target_url)
        directory_discovery.update(dir_results)
        
        # File brute-forcing
        logger.info("ðŸ“„ Starting file brute-force...")
        file_results = await self._bruteforce_files(target_url)
        directory_discovery['files_found'].extend(file_results['files_found'])
        directory_discovery['interesting_files'].extend(file_results['interesting_files'])
        directory_discovery['total_requests'] += file_results['total_requests']
        
        return directory_discovery
    
    async def _bruteforce_directories(self, target_url: str) -> Dict[str, Any]:
        """Brute-force directories"""
        results = {
            'directories_found': [],
            'total_requests': 0,
            'response_codes': {}
        }
        
        # Use threading for faster directory checking
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_dir = {
                executor.submit(self._check_directory, target_url, directory): directory
                for directory in self.common_directories[:50]  # Limit for safety
            }
            
            for future in as_completed(future_to_dir):
                directory = future_to_dir[future]
                results['total_requests'] += 1
                
                try:
                    result = future.result()
                    if result:
                        status_code, full_url = result
                        results['directories_found'].append({
                            'url': full_url,
                            'status_code': status_code,
                            'directory': directory
                        })
                        self.discovered_directories.add(full_url)
                        self.discovered_endpoints.add(full_url)
                        
                        # Update response code statistics
                        results['response_codes'][status_code] = results['response_codes'].get(status_code, 0) + 1
                        
                        logger.info(f"âœ… Found directory: {full_url} ({status_code})")
                        
                except Exception:
                    pass
        
        return results
    
    def _check_directory(self, base_url: str, directory: str) -> Optional[Tuple[int, str]]:
        """Check if a directory exists"""
        try:
            # Try both with and without trailing slash
            for dir_path in [f"/{directory}", f"/{directory}/"]:
                full_url = urljoin(base_url, dir_path)
                
                response = self.session.get(
                    full_url, 
                    timeout=5, 
                    allow_redirects=False,
                    stream=True
                )
                
                # Consider these status codes as "found"
                if response.status_code in [200, 301, 302, 403, 401]:
                    return response.status_code, full_url
        except:
            pass
        
        return None
    
    async def _bruteforce_files(self, target_url: str) -> Dict[str, Any]:
        """Brute-force common files"""
        results = {
            'files_found': [],
            'interesting_files': [],
            'total_requests': 0
        }
        
        # Use threading for faster file checking
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_file = {
                executor.submit(self._check_file, target_url, filename): filename
                for filename in self.common_files[:30]  # Limit for safety
            }
            
            for future in as_completed(future_to_file):
                filename = future_to_file[future]
                results['total_requests'] += 1
                
                try:
                    result = future.result()
                    if result:
                        status_code, full_url, is_interesting = result
                        file_info = {
                            'url': full_url,
                            'status_code': status_code,
                            'filename': filename,
                            'interesting': is_interesting
                        }
                        
                        results['files_found'].append(file_info)
                        self.discovered_files.add(full_url)
                        self.discovered_endpoints.add(full_url)
                        
                        if is_interesting:
                            results['interesting_files'].append(file_info)
                        
                        logger.info(f"âœ… Found file: {full_url} ({status_code})" + 
                                  (" - INTERESTING!" if is_interesting else ""))
                        
                except Exception:
                    pass
        
        return results
    
    def _check_file(self, base_url: str, filename: str) -> Optional[Tuple[int, str, bool]]:
        """Check if a file exists"""
        try:
            full_url = urljoin(base_url, f"/{filename}")
            
            response = self.session.get(
                full_url, 
                timeout=5, 
                allow_redirects=False,
                stream=True
            )
            
            # Consider these status codes as "found"
            if response.status_code in [200, 301, 302]:
                # Determine if file is interesting
                interesting_files = [
                    '.env', 'config.php', 'database.php', 'web.config',
                    '.htaccess', 'phpinfo.php', 'info.php', 'backup.sql',
                    'database.sql', '.git/config', 'readme.txt'
                ]
                
                is_interesting = any(interesting in filename.lower() for interesting in interesting_files)
                
                return response.status_code, full_url, is_interesting
                
        except:
            pass
        
        return None
    
    async def _api_discovery(self, target_url: str) -> Dict[str, Any]:
        """Discover API endpoints and documentation"""
        api_discovery = {
            'api_endpoints': [],
            'api_documentation': [],
            'graphql_endpoints': [],
            'swagger_docs': [],
            'openapi_specs': [],
            'total_apis_found': 0
        }
        
        # Check common API paths
        api_results = await self._check_api_endpoints(target_url)
        api_discovery.update(api_results)
        
        # Check for API documentation
        doc_results = await self._check_api_documentation(target_url)
        api_discovery['api_documentation'].extend(doc_results)
        
        # Check for GraphQL endpoints
        graphql_results = await self._check_graphql_endpoints(target_url)
        api_discovery['graphql_endpoints'].extend(graphql_results)
        
        api_discovery['total_apis_found'] = (
            len(api_discovery['api_endpoints']) + 
            len(api_discovery['graphql_endpoints'])
        )
        
        return api_discovery
    
    async def _check_api_endpoints(self, target_url: str) -> Dict[str, Any]:
        """Check for common API endpoints"""
        results = {
            'api_endpoints': [],
            'swagger_docs': [],
            'openapi_specs': []
        }
        
        # Use threading for faster API endpoint checking
        with ThreadPoolExecutor(max_workers=15) as executor:
            future_to_endpoint = {
                executor.submit(self._check_api_endpoint, target_url, endpoint): endpoint
                for endpoint in self.api_endpoints
            }
            
            for future in as_completed(future_to_endpoint):
                endpoint = future_to_endpoint[future]
                
                try:
                    result = future.result()
                    if result:
                        status_code, full_url, content_type, response_size = result
                        
                        api_info = {
                            'url': full_url,
                            'endpoint': endpoint,
                            'status_code': status_code,
                            'content_type': content_type,
                            'response_size': response_size
                        }
                        
                        results['api_endpoints'].append(api_info)
                        self.discovered_apis.add(full_url)
                        self.discovered_endpoints.add(full_url)
                        
                        logger.info(f"âœ… Found API endpoint: {full_url} ({status_code})")
                        
                        # Check if it's API documentation
                        if any(doc_keyword in endpoint.lower() for doc_keyword in ['swagger', 'docs', 'documentation']):
                            if 'swagger' in endpoint.lower():
                                results['swagger_docs'].append(api_info)
                            else:
                                results['openapi_specs'].append(api_info)
                        
                except Exception:
                    pass
        
        return results
    
    def _check_api_endpoint(self, base_url: str, endpoint: str) -> Optional[Tuple[int, str, str, int]]:
        """Check if an API endpoint exists"""
        try:
            full_url = urljoin(base_url, f"/{endpoint}")
            
            response = self.session.get(
                full_url, 
                timeout=8, 
                allow_redirects=True,
                headers={'Accept': 'application/json, application/xml, text/plain, */*'}
            )
            
            # Consider these status codes as valid API responses
            if response.status_code in [200, 401, 403, 405]:
                content_type = response.headers.get('content-type', 'unknown')
                response_size = len(response.content)
                
                # Additional validation for API endpoints
                if (response.status_code == 200 and 
                    ('json' in content_type.lower() or 
                     'xml' in content_type.lower() or
                     response_size > 0)):
                    return response.status_code, full_url, content_type, response_size
                elif response.status_code in [401, 403, 405]:
                    # These codes often indicate a valid API endpoint
                    return response.status_code, full_url, content_type, response_size
                    
        except:
            pass
        
        return None
    
    async def _check_api_documentation(self, target_url: str) -> List[Dict[str, Any]]:
        """Check for API documentation"""
        documentation = []
        
        doc_paths = [
            '/docs', '/documentation', '/api-docs', '/swagger', '/swagger-ui',
            '/swagger/index.html', '/api/docs', '/api/swagger', '/redoc',
            '/openapi.json', '/swagger.json', '/api.json', '/v1/swagger.json'
        ]
        
        for doc_path in doc_paths:
            try:
                full_url = urljoin(target_url, doc_path)
                response = self.session.get(full_url, timeout=8)
                
                if response.status_code == 200:
                    documentation.append({
                        'url': full_url,
                        'type': 'api_documentation',
                        'path': doc_path,
                        'content_type': response.headers.get('content-type', 'unknown')
                    })
                    
                    self.discovered_endpoints.add(full_url)
                    logger.info(f"âœ… Found API documentation: {full_url}")
                    
            except Exception:
                pass
        
        return documentation
    
    async def _check_graphql_endpoints(self, target_url: str) -> List[Dict[str, Any]]:
        """Check for GraphQL endpoints"""
        graphql_endpoints = []
        
        graphql_paths = ['/graphql', '/api/graphql', '/v1/graphql', '/query', '/api/query']
        
        for graphql_path in graphql_paths:
            try:
                full_url = urljoin(target_url, graphql_path)
                
                # Try introspection query
                introspection_query = {
                    "query": "{ __schema { types { name } } }"
                }
                
                response = self.session.post(
                    full_url, 
                    json=introspection_query, 
                    timeout=8,
                    headers={'Content-Type': 'application/json'}
                )
                
                if response.status_code in [200, 400, 405]:
                    graphql_endpoints.append({
                        'url': full_url,
                        'type': 'graphql',
                        'path': graphql_path,
                        'status_code': response.status_code,
                        'introspection_enabled': response.status_code == 200
                    })
                    
                    self.discovered_apis.add(full_url)
                    self.discovered_endpoints.add(full_url)
                    logger.info(f"âœ… Found GraphQL endpoint: {full_url}")
                    
            except Exception:
                pass
        
        return graphql_endpoints

    async def _advanced_technology_detection(self, url: str) -> Dict[str, Any]:
        """Advanced technology detection from HTTP headers, content, and fingerprinting"""
        tech_info = {
            'server': 'unknown',
            'technologies': [],
            'cms': 'unknown',
            'frameworks': [],
            'programming_languages': [],
            'web_servers': [],
            'databases': [],
            'javascript_libraries': [],
            'security_headers': {},
            'headers': {},
            'ssl_info': {},
            'cookies': []
        }
        
        try:
            response = self.session.get(url, timeout=10, allow_redirects=True)
            
            # Store relevant headers
            relevant_headers = ['Server', 'X-Powered-By', 'X-Generator', 'X-Framework', 
                              'X-AspNet-Version', 'X-Drupal-Cache', 'X-Pingback']
            for header in relevant_headers:
                if header in response.headers:
                    tech_info['headers'][header] = response.headers[header]
            
            # Server detection and analysis
            server_header = response.headers.get('Server', 'unknown')
            tech_info['server'] = server_header
            
            # Web server identification
            if 'apache' in server_header.lower():
                tech_info['web_servers'].append('Apache')
            elif 'nginx' in server_header.lower():
                tech_info['web_servers'].append('Nginx')
            elif 'iis' in server_header.lower():
                tech_info['web_servers'].append('Microsoft IIS')
            elif 'cloudflare' in server_header.lower():
                tech_info['web_servers'].append('Cloudflare')
            
            # Technology detection from headers
            if 'X-Powered-By' in response.headers:
                powered_by = response.headers['X-Powered-By']
                tech_info['technologies'].append(powered_by)
                
                # Programming language detection
                if 'php' in powered_by.lower():
                    tech_info['programming_languages'].append('PHP')
                elif 'asp.net' in powered_by.lower():
                    tech_info['programming_languages'].append('ASP.NET')
                    tech_info['frameworks'].append('ASP.NET')
            
            # Security headers analysis
            security_headers = {
                'X-Frame-Options': response.headers.get('X-Frame-Options'),
                'X-XSS-Protection': response.headers.get('X-XSS-Protection'),
                'X-Content-Type-Options': response.headers.get('X-Content-Type-Options'),
                'Strict-Transport-Security': response.headers.get('Strict-Transport-Security'),
                'Content-Security-Policy': response.headers.get('Content-Security-Policy'),
                'X-Content-Security-Policy': response.headers.get('X-Content-Security-Policy')
            }
            tech_info['security_headers'] = {k: v for k, v in security_headers.items() if v}
            
            # Cookie analysis
            if 'Set-Cookie' in response.headers:
                cookies = response.headers.get('Set-Cookie', '').split(',')
                for cookie in cookies:
                    cookie_info = {
                        'name': cookie.split('=')[0].strip() if '=' in cookie else cookie.strip(),
                        'secure': 'Secure' in cookie,
                        'httponly': 'HttpOnly' in cookie,
                        'samesite': 'SameSite' in cookie
                    }
                    tech_info['cookies'].append(cookie_info)
            
            # Content-based detection
            content = response.text.lower()
            
            # Enhanced CMS detection
            cms_signatures = {
                'wordpress': ['wp-content', 'wp-includes', 'wordpress', 'wp-json'],
                'drupal': ['drupal', 'sites/default', 'drupal.js', '/core/'],
                'joomla': ['joomla', 'option=com_', 'joomla!', '/components/com_'],
                'magento': ['magento', 'mage/', 'var/magento', 'skin/frontend'],
                'shopify': ['shopify', 'cdn.shopify.com', 'shopify-features'],
                'django': ['__admin/static/', 'django', 'csrfmiddlewaretoken'],
                'rails': ['rails', 'ruby on rails', '_rails_'],
                'laravel': ['laravel', 'laravel_session', '/vendor/laravel/']
            }
            
            for cms, signatures in cms_signatures.items():
                if any(sig in content for sig in signatures):
                    tech_info['cms'] = cms
                    tech_info['frameworks'].append(cms.title())
                    break
            
            # JavaScript library detection
            js_libraries = {
                'jquery': ['jquery', '$.', 'jquery.min.js'],
                'react': ['react', 'react.min.js', 'react-dom'],
                'angular': ['angular', 'ng-', 'angularjs'],
                'vue': ['vue.js', 'vue.min.js', '__vue__'],
                'bootstrap': ['bootstrap', 'bootstrap.min.css', 'bootstrap.js'],
                'fontawesome': ['font-awesome', 'fontawesome', 'fa-'],
                'd3': ['d3.js', 'd3.min.js', 'd3.'],
                'lodash': ['lodash', 'underscore', '_.']
            }
            
            for lib, signatures in js_libraries.items():
                if any(sig in content for sig in signatures):
                    tech_info['javascript_libraries'].append(lib)
            
            # Database detection from error messages or content
            db_signatures = {
                'mysql': ['mysql', 'mysqld', 'mysql_connect'],
                'postgresql': ['postgresql', 'postgres', 'psql'],
                'mongodb': ['mongodb', 'mongo', 'mongod'],
                'redis': ['redis', 'redis-server'],
                'sqlite': ['sqlite', 'sqlite3'],
                'oracle': ['oracle', 'oci8', 'tns:'],
                'mssql': ['mssql', 'sqlserver', 'microsoft sql']
            }
            
            for db, signatures in db_signatures.items():
                if any(sig in content for sig in signatures):
                    tech_info['databases'].append(db)
            
            # SSL/TLS information
            if url.startswith('https://'):
                tech_info['ssl_info'] = await self._analyze_ssl_certificate(url)
                
        except Exception as e:
            logger.warning(f"âš ï¸ Advanced technology detection error: {e}")
        
        # Remove duplicates
        tech_info['technologies'] = list(set(tech_info['technologies']))
        tech_info['frameworks'] = list(set(tech_info['frameworks']))
        tech_info['programming_languages'] = list(set(tech_info['programming_languages']))
        tech_info['web_servers'] = list(set(tech_info['web_servers']))
        tech_info['databases'] = list(set(tech_info['databases']))
        tech_info['javascript_libraries'] = list(set(tech_info['javascript_libraries']))
        
        return tech_info
    
    async def _analyze_ssl_certificate(self, url: str) -> Dict[str, Any]:
        """Analyze SSL certificate information"""
        ssl_info = {
            'certificate_valid': False,
            'issuer': 'unknown',
            'subject': 'unknown',
            'version': 'unknown',
            'expires': 'unknown',
            'signature_algorithm': 'unknown'
        }
        
        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            port = parsed_url.port or 443
            
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    ssl_info['certificate_valid'] = True
                    ssl_info['issuer'] = dict(x[0] for x in cert.get('issuer', []))
                    ssl_info['subject'] = dict(x[0] for x in cert.get('subject', []))
                    ssl_info['version'] = cert.get('version', 'unknown')
                    ssl_info['expires'] = cert.get('notAfter', 'unknown')
                    ssl_info['signature_algorithm'] = cert.get('signatureAlgorithm', 'unknown')
                    
        except Exception as e:
            logger.warning(f"âš ï¸ SSL certificate analysis failed: {e}")
        
        return ssl_info
    
    async def _security_misconfiguration_checks(self, target_url: str) -> Dict[str, Any]:
        """Check for common security misconfigurations"""
        security_checks = {
            'directory_listing': False,
            'backup_files_exposed': [],
            'debug_mode_enabled': False,
            'verbose_error_messages': False,
            'insecure_http_methods': [],
            'missing_security_headers': [],
            'weak_ssl_configuration': False,
            'exposed_git_directory': False,
            'exposed_svn_directory': False,
            'admin_interfaces': []
        }
        
        try:
            # Check for directory listing
            response = self.session.get(target_url, timeout=10)
            if 'index of' in response.text.lower() or 'directory listing' in response.text.lower():
                security_checks['directory_listing'] = True
            
            # Check for exposed version control directories
            vc_paths = ['/.git/', '/.svn/', '/.hg/']
            for vc_path in vc_paths:
                try:
                    vc_url = urljoin(target_url, vc_path)
                    vc_response = self.session.get(vc_url, timeout=5)
                    if vc_response.status_code in [200, 301, 403]:
                        if '.git' in vc_path:
                            security_checks['exposed_git_directory'] = True
                        elif '.svn' in vc_path:
                            security_checks['exposed_svn_directory'] = True
                except:
                    pass
            
            # Check for backup files
            backup_extensions = ['.bak', '.backup', '.old', '.orig', '.tmp', '~']
            common_files = ['index', 'config', 'database', 'db', 'admin']
            
            for file_base in common_files:
                for ext in backup_extensions:
                    backup_file = f"{file_base}{ext}"
                    try:
                        backup_url = urljoin(target_url, f"/{backup_file}")
                        backup_response = self.session.get(backup_url, timeout=5)
                        if backup_response.status_code == 200:
                            security_checks['backup_files_exposed'].append(backup_url)
                    except:
                        pass
            
            # Check for insecure HTTP methods
            methods_to_test = ['PUT', 'DELETE', 'TRACE', 'OPTIONS', 'PATCH']
            for method in methods_to_test:
                try:
                    method_response = self.session.request(method, target_url, timeout=5)
                    if method_response.status_code not in [404, 405, 501]:
                        security_checks['insecure_http_methods'].append(method)
                except:
                    pass
            
            # Check for admin interfaces
            admin_paths = ['/admin', '/administrator', '/wp-admin', '/admin.php', '/admin/', 
                          '/management', '/manager', '/dashboard', '/control', '/panel']
            
            for admin_path in admin_paths:
                try:
                    admin_url = urljoin(target_url, admin_path)
                    admin_response = self.session.get(admin_url, timeout=5)
                    if admin_response.status_code in [200, 401, 403]:
                        security_checks['admin_interfaces'].append(admin_url)
                except:
                    pass
            
            # Check for missing security headers
            required_headers = [
                'X-Frame-Options', 'X-XSS-Protection', 'X-Content-Type-Options',
                'Strict-Transport-Security', 'Content-Security-Policy'
            ]
            
            for header in required_headers:
                if header not in response.headers:
                    security_checks['missing_security_headers'].append(header)
            
        except Exception as e:
            logger.warning(f"âš ï¸ Security misconfiguration checks failed: {e}")
        
        return security_checks
    
    def _analyze_enhanced_findings(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze enhanced reconnaissance results and generate comprehensive security findings"""
        vulnerabilities = []
        
        # Analyze open ports
        if 'port_info' in scan_results:
            vulnerabilities.extend(self._analyze_enhanced_ports(scan_results))
        
        # Analyze subdomains
        if 'subdomains' in scan_results:
            vulnerabilities.extend(self._analyze_enhanced_subdomains(scan_results))
        
        # Analyze web discovery findings
        if 'web_discovery' in scan_results:
            vulnerabilities.extend(self._analyze_web_discovery(scan_results))
        
        # Analyze directory brute-force results
        if 'directory_discovery' in scan_results:
            vulnerabilities.extend(self._analyze_directory_findings(scan_results))
        
        # Analyze API discovery results
        if 'api_discovery' in scan_results:
            vulnerabilities.extend(self._analyze_api_findings(scan_results))
        
        # Analyze technologies
        if 'technologies' in scan_results:
            vulnerabilities.extend(self._analyze_enhanced_technologies(scan_results))
        
        # Analyze security misconfigurations
        if 'security_checks' in scan_results:
            vulnerabilities.extend(self._analyze_security_misconfigurations(scan_results))
        
        # Analyze DNS information
        if 'dns_info' in scan_results:
            vulnerabilities.extend(self._analyze_enhanced_dns(scan_results))
        
        return vulnerabilities
    
    def _analyze_enhanced_ports(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Enhanced analysis of open ports for potential security issues"""
        vulnerabilities = []
        port_info = scan_results['port_info']
        open_ports = port_info.get('open_ports', [])
        services = port_info.get('services', {})
        
        # Check for potentially risky ports with enhanced analysis
        risky_ports = {
            21: ('FTP Service Detected', 'Medium', 'FTP services may be vulnerable to attacks and often allow plaintext authentication'),
            22: ('SSH Service Detected', 'Low', 'SSH service exposed - ensure strong authentication and key management'),
            23: ('Telnet Service Detected', 'High', 'Telnet transmits data in plaintext including credentials'),
            25: ('SMTP Service Detected', 'Low', 'SMTP service may be misconfigured for mail relay'),
            53: ('DNS Service Detected', 'Low', 'DNS service exposed externally may reveal internal structure'),
            135: ('Microsoft RPC Detected', 'Medium', 'Microsoft RPC service exposed'),
            139: ('NetBIOS Session Detected', 'Medium', 'NetBIOS service may leak system information'),
            445: ('SMB Service Detected', 'Medium', 'SMB service exposed may be vulnerable to known attacks'),
            1433: ('Microsoft SQL Server Detected', 'High', 'Database service directly exposed to internet'),
            3306: ('MySQL Database Detected', 'High', 'MySQL database service directly exposed'),
            5432: ('PostgreSQL Database Detected', 'High', 'PostgreSQL database service directly exposed'),
            6379: ('Redis Database Detected', 'High', 'Redis database exposed without authentication by default'),
            27017: ('MongoDB Database Detected', 'High', 'MongoDB database service directly exposed')
        }
        
        # Database services - high priority
        database_ports = [1433, 3306, 5432, 6379, 27017, 5984, 9200]
        exposed_databases = [port for port in open_ports if port in database_ports]
        
        if exposed_databases:
            vulnerabilities.append({
                'title': 'Database Services Directly Exposed',
                'severity': 'Critical',
                'cvss': 9.0,
                'description': f'Database services found on ports: {exposed_databases}. Direct database exposure is a critical security risk.',
                'url': scan_results['target'],
                'parameter': f'ports_{",".join(map(str, exposed_databases))}',
                'remediation': 'Move database services behind firewall, use VPN access, implement strong authentication',
                'discovered_by': 'Enhanced Recon Agent'
            })
        
        # Analyze individual risky ports
        for port in open_ports:
            if port in risky_ports:
                title, severity, description = risky_ports[port]
                
                # Enhanced description with service details
                if port in services:
                    service_info = services[port]
                    enhanced_desc = f"{description}. Service: {service_info.get('service', 'unknown')}"
                    if 'version' in service_info and service_info['version'] != 'unknown':
                        enhanced_desc += f", Version: {service_info['version']}"
                    if 'banner' in service_info and service_info['banner']:
                        enhanced_desc += f", Banner: {service_info['banner'][:100]}..."
                else:
                    enhanced_desc = description
                
                vulnerabilities.append({
                    'title': title,
                    'severity': severity,
                    'cvss': 8.0 if severity == 'Critical' else (7.0 if severity == 'High' else (5.0 if severity == 'Medium' else 3.0)),
                    'description': enhanced_desc,
                    'url': scan_results['target'],
                    'parameter': f'port_{port}',
                    'remediation': f'Review necessity of service on port {port}, ensure proper security controls, consider firewall restrictions',
                    'discovered_by': 'Enhanced Recon Agent'
                })
        
        # Check for large number of open ports
        if len(open_ports) > 20:
            vulnerabilities.append({
                'title': 'Excessive Open Ports Detected',
                'severity': 'Medium',
                'cvss': 6.0,
                'description': f'{len(open_ports)} open ports discovered, indicating a large attack surface',
                'url': scan_results['target'],
                'parameter': 'multiple_ports',
                'remediation': 'Review all open services and close unnecessary ports, implement principle of least privilege',
                'discovered_by': 'Enhanced Recon Agent'
            })
        
        return vulnerabilities
    
    def _analyze_enhanced_subdomains(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Enhanced analysis of subdomain findings"""
        vulnerabilities = []
        subdomains = scan_results.get('subdomains', [])
        
        # Categorize subdomains by risk level
        high_risk_patterns = ['admin', 'test', 'dev', 'staging', 'debug', 'backup']
        medium_risk_patterns = ['api', 'mail', 'ftp', 'old', 'beta', 'vpn']
        
        high_risk_subdomains = []
        medium_risk_subdomains = []
        
        for subdomain in subdomains:
            subdomain_lower = subdomain.lower()
            if any(pattern in subdomain_lower for pattern in high_risk_patterns):
                high_risk_subdomains.append(subdomain)
            elif any(pattern in subdomain_lower for pattern in medium_risk_patterns):
                medium_risk_subdomains.append(subdomain)
        
        # High-risk subdomains
        if high_risk_subdomains:
            vulnerabilities.append({
                'title': 'High-Risk Subdomains Discovered',
                'severity': 'Medium',
                'cvss': 6.0,
                'description': f'Found potentially sensitive subdomains: {", ".join(high_risk_subdomains[:5])}{"..." if len(high_risk_subdomains) > 5 else ""}',
                'url': scan_results['target'],
                'parameter': 'high_risk_subdomains',
                'remediation': 'Review access controls for development/admin subdomains, ensure they are not publicly accessible',
                'discovered_by': 'Enhanced Recon Agent'
            })
        
        # Large subdomain footprint
        if len(subdomains) > 50:
            vulnerabilities.append({
                'title': 'Large Subdomain Attack Surface',
                'severity': 'Low',
                'cvss': 4.0,
                'description': f'Discovered {len(subdomains)} subdomains, indicating a large attack surface',
                'url': scan_results['target'],
                'parameter': 'subdomain_count',
                'remediation': 'Review all subdomains for necessity, implement proper access controls and monitoring',
                'discovered_by': 'Enhanced Recon Agent'
            })
        
        return vulnerabilities
    
    def _analyze_web_discovery(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze web discovery findings"""
        vulnerabilities = []
        web_discovery = scan_results['web_discovery']
        
        # Analyze robots.txt findings
        robots_info = web_discovery.get('robots_txt', {})
        if robots_info.get('exists') and robots_info.get('disallowed_paths'):
            sensitive_paths = [path for path in robots_info['disallowed_paths'] 
                             if any(keyword in path.lower() for keyword in ['admin', 'private', 'secret', 'backup', 'config'])]
            
            if sensitive_paths:
                vulnerabilities.append({
                    'title': 'Sensitive Paths Disclosed in robots.txt',
                    'severity': 'Low',
                    'cvss': 3.0,
                    'description': f'robots.txt reveals potentially sensitive paths: {", ".join(sensitive_paths[:3])}',
                    'url': scan_results['target'],
                    'parameter': 'robots_txt',
                    'remediation': 'Review robots.txt for information disclosure, consider removing sensitive path references',
                    'discovered_by': 'Enhanced Recon Agent'
                })
        
        # Analyze forms
        forms = web_discovery.get('forms_found', [])
        if forms:
            vulnerabilities.append({
                'title': 'Input Forms Discovered',
                'severity': 'Info',
                'cvss': 1.0,
                'description': f'Found {len(forms)} forms that may be targets for injection attacks',
                'url': scan_results['target'],
                'parameter': 'web_forms',
                'remediation': 'Test forms for injection vulnerabilities, implement proper input validation',
                'discovered_by': 'Enhanced Recon Agent'
            })
        
        # Analyze email addresses
        emails = web_discovery.get('email_addresses', [])
        if emails:
            vulnerabilities.append({
                'title': 'Email Addresses Exposed',
                'severity': 'Low',
                'cvss': 2.0,
                'description': f'Found {len(emails)} email addresses that could be used for social engineering',
                'url': scan_results['target'],
                'parameter': 'email_disclosure',
                'remediation': 'Consider obfuscating email addresses or using contact forms instead',
                'discovered_by': 'Enhanced Recon Agent'
            })
        
        return vulnerabilities
    
    def _analyze_directory_findings(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze directory brute-force findings"""
        vulnerabilities = []
        directory_discovery = scan_results['directory_discovery']
        
        # Analyze interesting files
        interesting_files = directory_discovery.get('interesting_files', [])
        for file_info in interesting_files:
            severity = 'High' if any(keyword in file_info['filename'].lower() 
                                   for keyword in ['.env', 'config', 'database', 'backup']) else 'Medium'
            
            vulnerabilities.append({
                'title': f'Sensitive File Exposed: {file_info["filename"]}',
                'severity': severity,
                'cvss': 7.0 if severity == 'High' else 5.0,
                'description': f'Potentially sensitive file accessible: {file_info["url"]}',
                'url': file_info['url'],
                'parameter': 'exposed_file',
                'remediation': 'Remove or restrict access to sensitive files, implement proper access controls',
                'discovered_by': 'Enhanced Recon Agent'
            })
        
        # Analyze directory access
        directories = directory_discovery.get('directories_found', [])
        admin_dirs = [d for d in directories if any(keyword in d['directory'].lower() 
                                                  for keyword in ['admin', 'administrator', 'management'])]
        
        if admin_dirs:
            vulnerabilities.append({
                'title': 'Administrative Directories Accessible',
                'severity': 'Medium',
                'cvss': 6.0,
                'description': f'Found {len(admin_dirs)} potentially administrative directories',
                'url': scan_results['target'],
                'parameter': 'admin_directories',
                'remediation': 'Restrict access to administrative interfaces, implement authentication',
                'discovered_by': 'Enhanced Recon Agent'
            })
        
        return vulnerabilities
    
    def _analyze_api_findings(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze API discovery findings"""
        vulnerabilities = []
        api_discovery = scan_results['api_discovery']
        
        # API endpoints found
        api_endpoints = api_discovery.get('api_endpoints', [])
        if api_endpoints:
            vulnerabilities.append({
                'title': 'API Endpoints Discovered',
                'severity': 'Info',
                'cvss': 2.0,
                'description': f'Found {len(api_endpoints)} API endpoints that should be tested for vulnerabilities',
                'url': scan_results['target'],
                'parameter': 'api_endpoints',
                'remediation': 'Test API endpoints for authentication bypass, injection, and data exposure',
                'discovered_by': 'Enhanced Recon Agent'
            })
        
        # GraphQL endpoints
        graphql_endpoints = api_discovery.get('graphql_endpoints', [])
        for endpoint in graphql_endpoints:
            if endpoint.get('introspection_enabled'):
                vulnerabilities.append({
                    'title': 'GraphQL Introspection Enabled',
                    'severity': 'Medium',
                    'cvss': 5.0,
                    'description': f'GraphQL introspection is enabled at {endpoint["url"]}, allowing schema enumeration',
                    'url': endpoint['url'],
                    'parameter': 'graphql_introspection',
                    'remediation': 'Disable GraphQL introspection in production environments',
                    'discovered_by': 'Enhanced Recon Agent'
                })
        
        # API documentation exposed
        api_docs = api_discovery.get('api_documentation', [])
        if api_docs:
            vulnerabilities.append({
                'title': 'API Documentation Publicly Accessible',
                'severity': 'Low',
                'cvss': 3.0,
                'description': f'Found {len(api_docs)} API documentation endpoints that may reveal implementation details',
                'url': scan_results['target'],
                'parameter': 'api_documentation',
                'remediation': 'Review if API documentation should be publicly accessible',
                'discovered_by': 'Enhanced Recon Agent'
            })
        
        return vulnerabilities
    
    def _analyze_enhanced_technologies(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Enhanced analysis of technology stack - only high-impact findings"""
        vulnerabilities = []
        tech_info = scan_results.get('technologies', {})
        
        # Only report security headers if there's a demonstrated exploit path
        # Removed: Generic missing security headers without impact
        
        # Only report server information if it reveals exploitable versions
        server_header = tech_info.get('server', 'unknown')
        if server_header != 'unknown':
            # Check for known vulnerable versions only
            vulnerable_patterns = [
                'apache/2.2', 'apache/2.0', 'nginx/1.0', 'nginx/0.',
                'iis/6.0', 'iis/7.0', 'php/5.', 'php/4.'
            ]
            
            if any(pattern in server_header.lower() for pattern in vulnerable_patterns):
                vulnerabilities.append({
                    'title': 'Potentially Vulnerable Server Version Detected',
                    'severity': 'Medium',
                    'cvss': 6.0,
                    'description': f'Server running potentially vulnerable version: {server_header}',
                    'url': scan_results['target'],
                    'parameter': 'server_version',
                    'remediation': 'Update server software to latest stable version',
                    'discovered_by': 'Enhanced Recon Agent'
                })
        
        # Only report insecure cookies if they contain sensitive data
        cookies = tech_info.get('cookies', [])
        sensitive_cookie_names = ['session', 'auth', 'token', 'login', 'user', 'admin']
        
        insecure_sensitive_cookies = [
            cookie for cookie in cookies 
            if (not cookie.get('secure') or not cookie.get('httponly')) and
            any(sensitive in cookie.get('name', '').lower() for sensitive in sensitive_cookie_names)
        ]
        
        if insecure_sensitive_cookies:
            vulnerabilities.append({
                'title': 'Sensitive Cookies Without Security Flags',
                'severity': 'Medium',
                'cvss': 5.0,
                'description': f'Found {len(insecure_sensitive_cookies)} sensitive cookies without proper security flags',
                'url': scan_results['target'],
                'parameter': 'sensitive_cookie_security',
                'remediation': 'Configure sensitive cookies with Secure and HttpOnly flags',
                'discovered_by': 'Enhanced Recon Agent'
            })
        
        return vulnerabilities
    
    def _analyze_security_misconfigurations(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze security misconfiguration findings"""
        vulnerabilities = []
        security_checks = scan_results['security_checks']
        
        # Directory listing enabled
        if security_checks.get('directory_listing'):
            vulnerabilities.append({
                'title': 'Directory Listing Enabled',
                'severity': 'Medium',
                'cvss': 5.0,
                'description': 'Directory listing is enabled, potentially exposing sensitive files',
                'url': scan_results['target'],
                'parameter': 'directory_listing',
                'remediation': 'Disable directory listing in web server configuration',
                'discovered_by': 'Enhanced Recon Agent'
            })
        
        # Exposed version control directories
        if security_checks.get('exposed_git_directory'):
            vulnerabilities.append({
                'title': 'Git Directory Exposed',
                'severity': 'High',
                'cvss': 8.0,
                'description': '.git directory is accessible, potentially exposing source code and sensitive information',
                'url': scan_results['target'],
                'parameter': 'git_exposure',
                'remediation': 'Remove .git directory from web-accessible location or block access via web server config',
                'discovered_by': 'Enhanced Recon Agent'
            })
        
        # Backup files exposed
        backup_files = security_checks.get('backup_files_exposed', [])
        if backup_files:
            vulnerabilities.append({
                'title': 'Backup Files Exposed',
                'severity': 'High',
                'cvss': 7.0,
                'description': f'Found {len(backup_files)} exposed backup files that may contain sensitive data',
                'url': scan_results['target'],
                'parameter': 'backup_files',
                'remediation': 'Remove backup files from web-accessible directories',
                'discovered_by': 'Enhanced Recon Agent'
            })
        
        # Insecure HTTP methods
        insecure_methods = security_checks.get('insecure_http_methods', [])
        if insecure_methods:
            vulnerabilities.append({
                'title': 'Insecure HTTP Methods Enabled',
                'severity': 'Medium',
                'cvss': 6.0,
                'description': f'Potentially dangerous HTTP methods enabled: {", ".join(insecure_methods)}',
                'url': scan_results['target'],
                'parameter': 'http_methods',
                'remediation': 'Disable unnecessary HTTP methods (PUT, DELETE, TRACE, etc.)',
                'discovered_by': 'Enhanced Recon Agent'
            })
        
        # Admin interfaces exposed
        admin_interfaces = security_checks.get('admin_interfaces', [])
        if admin_interfaces:
            vulnerabilities.append({
                'title': 'Administrative Interfaces Accessible',
                'severity': 'Medium',
                'cvss': 6.0,
                'description': f'Found {len(admin_interfaces)} administrative interfaces',
                'url': scan_results['target'],
                'parameter': 'admin_interfaces',
                'remediation': 'Restrict access to administrative interfaces, implement strong authentication',
                'discovered_by': 'Enhanced Recon Agent'
            })
        
        return vulnerabilities
    
    def _analyze_enhanced_dns(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Enhanced analysis of DNS configuration - only exploitable findings"""
        vulnerabilities = []
        dns_info = scan_results.get('dns_info', {})
        
        # Only report DNS wildcard if it creates exploitable conditions
        wildcard_info = dns_info.get('wildcard_detection', {})
        if wildcard_info.get('has_wildcard'):
            # Check if wildcard resolves to internal/sensitive services
            wildcard_ip = wildcard_info.get('wildcard_ip', '')
            if wildcard_ip and (wildcard_ip.startswith('10.') or 
                               wildcard_ip.startswith('192.168.') or 
                               wildcard_ip.startswith('172.')):
                vulnerabilities.append({
                    'title': 'DNS Wildcard Exposes Internal Network',
                    'severity': 'Medium',
                    'cvss': 5.0,
                    'description': f'DNS wildcard resolves to internal IP: {wildcard_ip}',
                    'url': scan_results['target'],
                    'parameter': 'dns_wildcard_internal',
                    'remediation': 'Configure DNS wildcard to avoid exposing internal network information',
                    'discovered_by': 'Enhanced Recon Agent'
                })
        
        # Only report missing SPF/DMARC if domain is actually used for email
        mx_records = dns_info.get('mx_records', [])
        if mx_records:  # Only check if domain has mail servers
            txt_records = dns_info.get('txt_records', [])
            has_spf = any('spf' in record.lower() for record in txt_records)
            has_dmarc = any('dmarc' in record.lower() for record in txt_records)
            
            if not has_spf:
                vulnerabilities.append({
                    'title': 'Missing SPF Record on Mail Domain',
                    'severity': 'Medium',
                    'cvss': 4.0,
                    'description': 'Domain has MX records but no SPF record, enabling email spoofing',
                    'url': scan_results['target'],
                    'parameter': 'dns_spf_mail',
                    'remediation': 'Implement SPF records to prevent email spoofing',
                    'discovered_by': 'Enhanced Recon Agent'
                })
            
            if not has_dmarc:
                vulnerabilities.append({
                    'title': 'Missing DMARC Record on Mail Domain',
                    'severity': 'Medium',
                    'cvss': 4.0,
                    'description': 'Domain has MX records but no DMARC record, reducing email security',
                    'url': scan_results['target'],
                    'parameter': 'dns_dmarc_mail',
                    'remediation': 'Implement DMARC policy for email authentication',
                    'discovered_by': 'Enhanced Recon Agent'
                })
        
        return vulnerabilities
    
    # External tool integration methods
    async def integrate_with_amass(self, domain: str) -> Dict[str, Any]:
        """Integration with Amass for advanced subdomain enumeration"""
        integration_result = {
            'tool_available': False,
            'subdomains_found': [],
            'execution_successful': False,
            'error': None
        }
        
        try:
            # Check if amass is available
            result = subprocess.run(['amass', 'enum', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                integration_result['tool_available'] = True
                logger.info("âœ… Amass detected, attempting integration...")
                
                # Run amass enum with safe parameters
                amass_cmd = [
                    'amass', 'enum', '-d', domain, 
                    '-timeout', '5', '-max-dns-queries', '1000'
                ]
                
                result = subprocess.run(amass_cmd, capture_output=True, 
                                      text=True, timeout=300)  # 5 minute timeout
                
                if result.returncode == 0:
                    subdomains = [line.strip() for line in result.stdout.split('\n') 
                                if line.strip() and domain in line]
                    integration_result['subdomains_found'] = subdomains
                    integration_result['execution_successful'] = True
                    
                    # Add to discovered subdomains
                    self.subdomains_found.update(subdomains)
                    
                    logger.info(f"âœ… Amass integration successful: {len(subdomains)} subdomains found")
                else:
                    integration_result['error'] = result.stderr
                    
        except subprocess.TimeoutExpired:
            integration_result['error'] = 'Amass execution timed out'
        except FileNotFoundError:
            integration_result['error'] = 'Amass not found in PATH'
        except Exception as e:
            integration_result['error'] = str(e)
        
        return integration_result
    
    async def integrate_with_subfinder(self, domain: str) -> Dict[str, Any]:
        """Integration with Subfinder for subdomain enumeration"""
        integration_result = {
            'tool_available': False,
            'subdomains_found': [],
            'execution_successful': False,
            'error': None
        }
        
        try:
            # Check if subfinder is available
            result = subprocess.run([Config.SUBFINDER_PATH, '-version'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                integration_result['tool_available'] = True
                logger.info("✅ Subfinder detected, attempting integration...")
                
                # Run subfinder with safe parameters
                subfinder_cmd = [
                    Config.SUBFINDER_PATH, '-d', domain, '-silent', '-timeout', '10'
                ]
                
                result = subprocess.run(subfinder_cmd, capture_output=True, 
                                      text=True, timeout=120)  # 2 minute timeout
                
                if result.returncode == 0:
                    subdomains = [line.strip() for line in result.stdout.split('\n') 
                                if line.strip() and domain in line]
                    integration_result['subdomains_found'] = subdomains
                    integration_result['execution_successful'] = True
                    
                    # Add to discovered subdomains
                    self.subdomains_found.update(subdomains)
                    
                    logger.info(f"âœ… Subfinder integration successful: {len(subdomains)} subdomains found")
                else:
                    integration_result['error'] = result.stderr
                    
        except subprocess.TimeoutExpired:
            integration_result['error'] = 'Subfinder execution timed out'
        except FileNotFoundError:
            integration_result['error'] = 'Subfinder not found in PATH'
        except Exception as e:
            integration_result['error'] = str(e)
        
        return integration_result
    
    async def integrate_with_nuclei(self, target_url: str) -> Dict[str, Any]:
        """Integration with Nuclei for vulnerability scanning"""
        integration_result = {
            'tool_available': False,
            'vulnerabilities_found': [],
            'execution_successful': False,
            'error': None
        }
        
        try:
            # Check if nuclei is available
            result = subprocess.run(['nuclei', '-version'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                integration_result['tool_available'] = True
                logger.info("âœ… Nuclei detected, attempting integration...")
                
                # Run nuclei with safe templates
                nuclei_cmd = [
                    'nuclei', '-u', target_url, '-t', 'exposures/', 
                    '-t', 'misconfiguration/', '-silent', '-nc'
                ]
                
                result = subprocess.run(nuclei_cmd, capture_output=True, 
                                      text=True, timeout=300)  # 5 minute timeout
                
                if result.returncode == 0:
                    # Parse nuclei output
                    for line in result.stdout.split('\n'):
                        if line.strip() and '[' in line:
                            integration_result['vulnerabilities_found'].append(line.strip())
                    
                    integration_result['execution_successful'] = True
                    logger.info(f"âœ… Nuclei integration successful: {len(integration_result['vulnerabilities_found'])} findings")
                else:
                    integration_result['error'] = result.stderr
                    
        except subprocess.TimeoutExpired:
            integration_result['error'] = 'Nuclei execution timed out'
        except FileNotFoundError:
            integration_result['error'] = 'Nuclei not found in PATH'
        except Exception as e:
            integration_result['error'] = str(e)
        
        return integration_result
    
    async def integrate_with_zap(self, target_url: str) -> Dict[str, Any]:
        """Integration with OWASP ZAP for automated web application security scanning"""
        integration_result = {
            'tool_available': False,
            'scan_id': None,
            'vulnerabilities_found': [],
            'scan_status': None,
            'execution_successful': False,
            'error': None
        }
        
        try:
            # Check if ZAP is running and API is accessible
            zap_url = Config.ZAP_API_URL
            zap_key = Config.ZAP_API_KEY
            
            # Test ZAP connection
            response = requests.get(f"{zap_url}/JSON/core/view/version/", 
                                  params={'apikey': zap_key}, timeout=10)
            
            if response.status_code == 200:
                integration_result['tool_available'] = True
                zap_version = response.json().get('version', 'Unknown')
                logger.info(f"✅ OWASP ZAP detected (v{zap_version}), attempting integration...")
                
                # Start a spider scan
                spider_response = requests.get(f"{zap_url}/JSON/spider/action/scan/",
                                             params={'apikey': zap_key, 'url': target_url}, 
                                             timeout=30)
                
                if spider_response.status_code == 200:
                    scan_id = spider_response.json().get('scan')
                    integration_result['scan_id'] = scan_id
                    
                    # Wait for spider to complete (with timeout)
                    max_wait = 120  # 2 minutes max
                    wait_time = 0
                    
                    while wait_time < max_wait:
                        status_response = requests.get(f"{zap_url}/JSON/spider/view/status/",
                                                     params={'apikey': zap_key, 'scanId': scan_id},
                                                     timeout=10)
                        
                        if status_response.status_code == 200:
                            status = status_response.json().get('status', '0')
                            if status == '100':  # Complete
                                break
                        
                        await asyncio.sleep(5)
                        wait_time += 5
                    
                    # Start active scan
                    active_scan_response = requests.get(f"{zap_url}/JSON/ascan/action/scan/",
                                                       params={'apikey': zap_key, 'url': target_url},
                                                       timeout=30)
                    
                    if active_scan_response.status_code == 200:
                        active_scan_id = active_scan_response.json().get('scan')
                        
                        # Wait for active scan to progress (limited time)
                        max_scan_wait = 300  # 5 minutes max
                        scan_wait_time = 0
                        
                        while scan_wait_time < max_scan_wait:
                            scan_status_response = requests.get(f"{zap_url}/JSON/ascan/view/status/",
                                                               params={'apikey': zap_key, 'scanId': active_scan_id},
                                                               timeout=10)
                            
                            if scan_status_response.status_code == 200:
                                scan_status = scan_status_response.json().get('status', '0')
                                integration_result['scan_status'] = f"{scan_status}%"
                                
                                # Stop after reasonable progress or completion
                                if int(scan_status) >= 25 or scan_status == '100':
                                    break
                            
                            await asyncio.sleep(10)
                            scan_wait_time += 10
                        
                        # Get scan results
                        alerts_response = requests.get(f"{zap_url}/JSON/core/view/alerts/",
                                                     params={'apikey': zap_key, 'baseurl': target_url},
                                                     timeout=30)
                        
                        if alerts_response.status_code == 200:
                            alerts = alerts_response.json().get('alerts', [])
                            
                            for alert in alerts:
                                vulnerability = {
                                    'name': alert.get('name', 'Unknown'),
                                    'risk': alert.get('risk', 'Unknown'),
                                    'confidence': alert.get('confidence', 'Unknown'),
                                    'description': alert.get('description', ''),
                                    'url': alert.get('url', ''),
                                    'param': alert.get('param', ''),
                                    'solution': alert.get('solution', '')
                                }
                                integration_result['vulnerabilities_found'].append(vulnerability)
                            
                            integration_result['execution_successful'] = True
                            logger.info(f"✅ ZAP integration successful: {len(alerts)} findings, scan {integration_result['scan_status']} complete")
                        else:
                            integration_result['error'] = f"Failed to retrieve ZAP alerts: {alerts_response.status_code}"
                    else:
                        integration_result['error'] = f"Failed to start ZAP active scan: {active_scan_response.status_code}"
                else:
                    integration_result['error'] = f"Failed to start ZAP spider scan: {spider_response.status_code}"
            else:
                integration_result['error'] = f"ZAP API not accessible: {response.status_code}"
                
        except requests.exceptions.RequestException as e:
            integration_result['error'] = f'ZAP connection failed: {str(e)}'
        except Exception as e:
            integration_result['error'] = f'ZAP integration error: {str(e)}'
        
        return integration_result

    async def run_external_tool_integrations(self, target_url: str, domain: str) -> Dict[str, Any]:
        """Run all available external tool integrations"""
        integrations = {
            'amass_integration': None,
            'subfinder_integration': None,
            'nuclei_integration': None,
            'zap_integration': None,
            'total_external_subdomains': 0,
            'total_external_vulnerabilities': 0
        }
        
        # Run external tool integrations if available
        logger.info("ðŸ”§ Checking for external tool integrations...")
        
        # Amass integration
        try:
            amass_result = await self.integrate_with_amass(domain)
            integrations['amass_integration'] = amass_result
            if amass_result['execution_successful']:
                integrations['total_external_subdomains'] += len(amass_result['subdomains_found'])
        except Exception as e:
            logger.warning(f"âš ï¸ Amass integration failed: {e}")
        
        # Subfinder integration
        try:
            subfinder_result = await self.integrate_with_subfinder(domain)
            integrations['subfinder_integration'] = subfinder_result
            if subfinder_result['execution_successful']:
                integrations['total_external_subdomains'] += len(subfinder_result['subdomains_found'])
        except Exception as e:
            logger.warning(f"âš ï¸ Subfinder integration failed: {e}")
        
        # Nuclei integration
        try:
            nuclei_result = await self.integrate_with_nuclei(target_url)
            integrations['nuclei_integration'] = nuclei_result
            if nuclei_result['execution_successful']:
                integrations['total_external_vulnerabilities'] += len(nuclei_result['vulnerabilities_found'])
        except Exception as e:
            logger.warning(f"âš ï¸ Nuclei integration failed: {e}")
        
        # OWASP ZAP integration
        try:
            zap_result = await self.integrate_with_zap(target_url)
            integrations['zap_integration'] = zap_result
            if zap_result['execution_successful']:
                integrations['total_external_vulnerabilities'] += len(zap_result['vulnerabilities_found'])
        except Exception as e:
            logger.warning(f" ZAP integration failed: {e}")
        if integrations['total_external_subdomains'] > 0 or integrations['total_external_vulnerabilities'] > 0:
            logger.info(f"âœ… External tool integrations completed:")
            logger.info(f"   ðŸŒ {integrations['total_external_subdomains']} additional subdomains from external tools")
            logger.info(f"   ðŸ” {integrations['total_external_vulnerabilities']} additional findings from external tools")
        else:
            logger.info("â„¹ï¸ No external tools available or no additional findings from external tools")
        
        return integrations


