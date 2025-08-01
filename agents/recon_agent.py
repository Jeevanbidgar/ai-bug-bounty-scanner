# Recon Agent - Network Reconnaissance and Asset Discovery
"""
Real reconnaissance agent for subdomain enumeration, port scanning, and DNS analysis.
Performs actual network reconnaissance using legitimate security tools.
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
import requests
import asyncio
import time
from urllib.parse import urlparse
from typing import Dict, List, Any
import logging

from .security_validator import SecurityValidator

logger = logging.getLogger(__name__)

class ReconAgent:
    """Real reconnaissance agent for network discovery and asset enumeration"""
    
    def __init__(self):
        # Try to initialize nmap, fall back to socket scanning if not available
        if NMAP_AVAILABLE:
            try:
                self.nm = nmap.PortScanner()
                self.nmap_available = True
                logger.info("✅ Nmap available for advanced port scanning")
            except Exception as e:
                self.nm = None
                self.nmap_available = False
                logger.warning(f"⚠️ Nmap initialization failed, using socket-based scanning: {e}")
        else:
            self.nm = None
            self.nmap_available = False
            logger.warning("⚠️ Nmap not installed, using socket-based scanning")

        self.session = requests.Session()
        self.config = SecurityValidator.get_safe_scan_config()

        # Configure session with safe defaults
        self.session.headers.update({
            'User-Agent': self.config['user_agent']
        })
        self.session.timeout = self.config['timeout']
        
    async def scan_target(self, target_url: str) -> Dict[str, Any]:
        """
        Main scanning function for reconnaissance
        
        Args:
            target_url: Target URL to scan
            
        Returns:
            Dict containing scan results and vulnerabilities
        """
        try:
            # Validate target first
            SecurityValidator.validate_target(target_url)
            
            # Extract domain from URL
            domain = self._extract_domain(target_url)
            logger.info(f"🔍 Starting reconnaissance scan for: {domain}")
            
            results = {
                'target': target_url,
                'domain': domain,
                'timestamp': time.time(),
                'scan_type': 'reconnaissance',
                'vulnerabilities': []
            }
            
            # Perform reconnaissance tasks
            try:
                logger.info("📡 Performing DNS enumeration...")
                dns_info = await self._dns_enumeration(domain)
                results['dns_info'] = dns_info
                
                logger.info("🔌 Performing port scan...")
                port_info = await self._safe_port_scan(domain)
                results['port_info'] = port_info
                
                logger.info("🌐 Performing subdomain enumeration...")
                subdomains = await self._subdomain_enumeration(domain)
                results['subdomains'] = subdomains
                
                logger.info("🔧 Detecting technologies...")
                tech_info = await self._technology_detection(target_url)
                results['technologies'] = tech_info
                
                logger.info("🔍 Analyzing findings...")
                vulnerabilities = self._analyze_recon_findings(results)
                results['vulnerabilities'] = vulnerabilities
                
                logger.info(f"✅ Reconnaissance completed: found {len(vulnerabilities)} potential issues")
                
            except Exception as scan_error:
                logger.error(f"❌ Scan error: {scan_error}")
                results['error'] = str(scan_error)
            
            return results
            
        except Exception as e:
            logger.error(f"❌ Reconnaissance scan failed: {e}")
            raise
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        parsed = urlparse(url)
        return parsed.netloc or parsed.path.split('/')[0]
    
    async def _dns_enumeration(self, domain: str) -> Dict[str, Any]:
        """Perform comprehensive DNS enumeration"""
        dns_info = {
            'a_records': [],
            'aaaa_records': [],
            'mx_records': [],
            'ns_records': [],
            'txt_records': [],
            'cname_records': [],
            'soa_record': None
        }
        
        record_types = [
            ('A', 'a_records'),
            ('AAAA', 'aaaa_records'),
            ('MX', 'mx_records'),
            ('NS', 'ns_records'),
            ('TXT', 'txt_records'),
            ('CNAME', 'cname_records'),
            ('SOA', 'soa_record')
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
        
        return dns_info
    
    async def _safe_port_scan(self, domain: str) -> Dict[str, Any]:
        """Perform safe port scan on common ports only"""
        port_info = {
            'open_ports': [],
            'services': {},
            'scan_method': 'socket_fallback' if not self.nmap_available else 'nmap'
        }

        if self.nmap_available:
            try:
                # Only scan common web and service ports for safety
                common_ports = '21,22,23,25,53,80,110,143,443,993,995,8080,8443'

                logger.info(f"🔌 Scanning common ports for {domain} using nmap")

                # Use safe nmap options
                scan_args = '-sS -T2 --max-retries 1 --host-timeout 30s --max-rate 10'
                scan_result = self.nm.scan(domain, common_ports, arguments=scan_args)

                if domain in scan_result['scan']:
                    host_info = scan_result['scan'][domain]

                    if 'tcp' in host_info:
                        for port, port_detail in host_info['tcp'].items():
                            if port_detail['state'] == 'open':
                                port_info['open_ports'].append(port)
                                port_info['services'][port] = {
                                    'service': port_detail.get('name', 'unknown'),
                                    'version': port_detail.get('version', 'unknown'),
                                    'product': port_detail.get('product', 'unknown'),
                                    'state': port_detail['state']
                                }

                return port_info

            except Exception as e:
                logger.warning(f"⚠️ Nmap scan failed, falling back to socket check: {e}")

        # Fallback to socket-based scanning
        logger.info(f"🔌 Scanning common ports for {domain} using socket method")
        critical_ports = [21, 22, 25, 53, 80, 443, 8080, 8443]

        for port in critical_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((domain, port))
                if result == 0:
                    port_info['open_ports'].append(port)
                    service_name = self._get_service_name(port)
                    port_info['services'][port] = {
                        'service': service_name,
                        'state': 'open',
                        'method': 'socket'
                    }
                sock.close()

                # Rate limiting
                await asyncio.sleep(0.2)

            except Exception:
                pass

        return port_info
    
    def _get_service_name(self, port: int) -> str:
        """Get common service name for port"""
        common_services = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
            53: 'dns', 80: 'http', 110: 'pop3', 143: 'imap',
            443: 'https', 993: 'imaps', 995: 'pop3s',
            8080: 'http-alt', 8443: 'https-alt'
        }
        return common_services.get(port, 'unknown')
    
    async def _subdomain_enumeration(self, domain: str) -> List[str]:
        """Safe subdomain enumeration using common subdomains"""
        subdomains = []
        
        # Common subdomain list (limited for safety)
        common_subs = [
            'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging',
            'blog', 'shop', 'store', 'support', 'help', 'docs', 'cdn',
            'static', 'assets', 'img', 'images', 'media', 'files'
        ]
        
        for sub in common_subs:
            subdomain = f"{sub}.{domain}"
            try:
                socket.gethostbyname(subdomain)
                subdomains.append(subdomain)
                logger.info(f"✅ Found subdomain: {subdomain}")
            except socket.gaierror:
                pass
            
            # Rate limiting to be respectful
            await asyncio.sleep(0.2)
        
        return subdomains
    
    async def _technology_detection(self, url: str) -> Dict[str, Any]:
        """Basic technology detection from HTTP headers and content"""
        tech_info = {
            'server': 'unknown',
            'technologies': [],
            'cms': 'unknown',
            'frameworks': [],
            'headers': {}
        }
        
        try:
            response = self.session.get(url, timeout=10, allow_redirects=True)
            
            # Store relevant headers
            relevant_headers = ['Server', 'X-Powered-By', 'X-Generator', 'X-Framework']
            for header in relevant_headers:
                if header in response.headers:
                    tech_info['headers'][header] = response.headers[header]
            
            # Server detection
            tech_info['server'] = response.headers.get('Server', 'unknown')
            
            # Technology detection from headers
            if 'X-Powered-By' in response.headers:
                tech_info['technologies'].append(response.headers['X-Powered-By'])
            
            # Basic CMS detection
            content = response.text.lower()
            cms_signatures = {
                'wordpress': ['wp-content', 'wp-includes', 'wordpress'],
                'drupal': ['drupal', 'sites/default'],
                'joomla': ['joomla', 'option=com_'],
                'magento': ['magento', 'mage/'],
                'shopify': ['shopify', 'cdn.shopify.com']
            }
            
            for cms, signatures in cms_signatures.items():
                if any(sig in content for sig in signatures):
                    tech_info['cms'] = cms
                    break
            
        except Exception as e:
            logger.warning(f"⚠️ Technology detection error: {e}")
        
        return tech_info
    
    def _analyze_recon_findings(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze reconnaissance results and generate security findings"""
        vulnerabilities = []
        
        # Analyze open ports
        if 'port_info' in scan_results:
            vulnerabilities.extend(self._analyze_ports(scan_results))
        
        # Analyze subdomains
        if 'subdomains' in scan_results:
            vulnerabilities.extend(self._analyze_subdomains(scan_results))
        
        # Analyze technologies
        if 'technologies' in scan_results:
            vulnerabilities.extend(self._analyze_technologies(scan_results))
        
        # Analyze DNS information
        if 'dns_info' in scan_results:
            vulnerabilities.extend(self._analyze_dns(scan_results))
        
        return vulnerabilities
    
    def _analyze_ports(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze open ports for potential security issues"""
        vulnerabilities = []
        open_ports = scan_results['port_info'].get('open_ports', [])
        
        # Check for potentially risky ports
        risky_ports = {
            21: ('FTP Service Detected', 'Medium', 'FTP services may be vulnerable to attacks'),
            23: ('Telnet Service Detected', 'High', 'Telnet transmits data in plaintext'),
            25: ('SMTP Service Detected', 'Low', 'SMTP service may be misconfigured'),
            53: ('DNS Service Detected', 'Low', 'DNS service exposed externally')
        }
        
        for port in open_ports:
            if port in risky_ports:
                title, severity, description = risky_ports[port]
                vulnerabilities.append({
                    'title': title,
                    'severity': severity,
                    'cvss': 5.0 if severity == 'Medium' else (7.0 if severity == 'High' else 3.0),
                    'description': description,
                    'url': scan_results['target'],
                    'parameter': f'port_{port}',
                    'remediation': f'Review necessity of service on port {port} and ensure proper security controls',
                    'discovered_by': 'Recon Agent'
                })
        
        return vulnerabilities
    
    def _analyze_subdomains(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze subdomain findings"""
        vulnerabilities = []
        subdomains = scan_results.get('subdomains', [])
        
        if len(subdomains) > 10:
            vulnerabilities.append({
                'title': 'Large Attack Surface - Multiple Subdomains',
                'severity': 'Low',
                'cvss': 3.0,
                'description': f'Found {len(subdomains)} subdomains which increases attack surface',
                'url': scan_results['target'],
                'parameter': 'subdomains',
                'remediation': 'Review all subdomains and ensure they are properly secured and necessary',
                'discovered_by': 'Recon Agent'
            })
        
        return vulnerabilities
    
    def _analyze_technologies(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze technology stack for information disclosure"""
        vulnerabilities = []
        tech_info = scan_results.get('technologies', {})
        
        if tech_info.get('server') and tech_info['server'] != 'unknown':
            vulnerabilities.append({
                'title': 'Server Information Disclosure',
                'severity': 'Low',
                'cvss': 2.0,
                'description': f'Server header reveals: {tech_info["server"]}',
                'url': scan_results['target'],
                'parameter': 'server_header',
                'remediation': 'Consider hiding or obfuscating server version information',
                'discovered_by': 'Recon Agent'
            })
        
        return vulnerabilities
    
    def _analyze_dns(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze DNS configuration for potential issues"""
        vulnerabilities = []
        dns_info = scan_results.get('dns_info', {})
        
        # Check for missing SPF records
        txt_records = dns_info.get('txt_records', [])
        has_spf = any('spf' in record.lower() for record in txt_records)
        
        if not has_spf:
            vulnerabilities.append({
                'title': 'Missing SPF Record',
                'severity': 'Low',
                'cvss': 2.0,
                'description': 'No SPF record found, which may allow email spoofing',
                'url': scan_results['target'],
                'parameter': 'dns_spf',
                'remediation': 'Implement SPF records to prevent email spoofing',
                'discovered_by': 'Recon Agent'
            })
        
        return vulnerabilities
