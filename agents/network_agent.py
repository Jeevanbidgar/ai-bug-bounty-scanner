# Network Agent - Network Security Testing
"""
Real network security testing agent.
Performs network-level security assessments including advanced port scanning,
service enumeration, and network protocol testing.
"""

import nmap
import socket
import asyncio
import time
from typing import Dict, List, Any
import logging
import subprocess
import platform

from .security_validator import SecurityValidator

logger = logging.getLogger(__name__)

class NetworkAgent:
    """Real network security testing agent"""
    
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.config = SecurityValidator.get_safe_scan_config()
        
    async def scan_target(self, target_url: str) -> Dict[str, Any]:
        """
        Main network scanning function
        
        Args:
            target_url: Target URL to scan
            
        Returns:
            Dict containing scan results and vulnerabilities
        """
        try:
            # Validate target
            SecurityValidator.validate_target(target_url)
            
            # Extract hostname/IP
            hostname = self._extract_hostname(target_url)
            logger.info(f"🌐 Starting network scan for: {hostname}")
            
            results = {
                'target': target_url,
                'hostname': hostname,
                'timestamp': time.time(),
                'scan_type': 'network',
                'vulnerabilities': []
            }
            
            try:
                # Comprehensive port scan
                logger.info("🔌 Performing comprehensive port scan...")
                port_scan_results = await self._comprehensive_port_scan(hostname)
                results['port_scan'] = port_scan_results
                
                # Service enumeration
                logger.info("🔍 Performing service enumeration...")
                service_results = await self._service_enumeration(hostname, port_scan_results)
                results['services'] = service_results
                
                # Network protocol testing
                logger.info("📡 Testing network protocols...")
                protocol_results = await self._test_network_protocols(hostname)
                results['protocols'] = protocol_results
                
                # SSL/TLS testing
                logger.info("🔒 Testing SSL/TLS configuration...")
                ssl_results = await self._test_ssl_configuration(hostname)
                results['ssl_tls'] = ssl_results
                
                # Analyze findings
                logger.info("🔍 Analyzing network findings...")
                vulnerabilities = self._analyze_network_findings(results)
                results['vulnerabilities'] = vulnerabilities
                
                logger.info(f"✅ Network scan completed: found {len(vulnerabilities)} vulnerabilities")
                
            except Exception as scan_error:
                logger.error(f"❌ Network scan error: {scan_error}")
                results['error'] = str(scan_error)
            
            return results
            
        except Exception as e:
            logger.error(f"❌ Network scan failed: {e}")
            raise
    
    def _extract_hostname(self, target_url: str) -> str:
        """Extract hostname from URL"""
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        return parsed.hostname or parsed.netloc or target_url
    
    async def _comprehensive_port_scan(self, hostname: str) -> Dict[str, Any]:
        """Perform comprehensive port scanning"""
        scan_results = {
            'tcp_ports': {},
            'udp_ports': {},
            'scan_stats': {}
        }
        
        try:
            # TCP scan - comprehensive but safe
            logger.info("🔌 Scanning TCP ports...")
            tcp_ports = '1-1000,1433,1521,3306,3389,5432,5900,8080,8443,9090'
            
            # Use safe nmap options
            tcp_args = '-sS -T3 --max-retries 2 --host-timeout 60s --max-rate 50'
            tcp_scan = self.nm.scan(hostname, tcp_ports, arguments=tcp_args)
            
            if hostname in tcp_scan['scan']:
                host_info = tcp_scan['scan'][hostname]
                if 'tcp' in host_info:
                    scan_results['tcp_ports'] = host_info['tcp']
            
            # UDP scan - limited ports for safety and speed
            logger.info("📡 Scanning UDP ports...")
            udp_ports = '53,67,68,69,123,161,162,514,1194'
            udp_args = '-sU -T3 --max-retries 1 --host-timeout 30s'
            
            try:
                udp_scan = self.nm.scan(hostname, udp_ports, arguments=udp_args)
                if hostname in udp_scan['scan'] and 'udp' in udp_scan['scan'][hostname]:
                    scan_results['udp_ports'] = udp_scan['scan'][hostname]['udp']
            except Exception as udp_error:
                logger.warning(f"⚠️ UDP scan failed: {udp_error}")
            
            # Scan statistics
            scan_results['scan_stats'] = {
                'tcp_ports_scanned': len(tcp_ports.split(',')),
                'tcp_open_ports': len([p for p, info in scan_results['tcp_ports'].items() if info['state'] == 'open']),
                'udp_ports_scanned': len(udp_ports.split(',')),
                'udp_open_ports': len([p for p, info in scan_results['udp_ports'].items() if info['state'] == 'open'])
            }
            
        except Exception as e:
            logger.error(f"❌ Port scan error: {e}")
            # Fallback to basic socket scan
            scan_results = await self._fallback_socket_scan(hostname)
        
        return scan_results
    
    async def _fallback_socket_scan(self, hostname: str) -> Dict[str, Any]:
        """Fallback socket-based port scan"""
        scan_results = {
            'tcp_ports': {},
            'udp_ports': {},
            'scan_stats': {},
            'method': 'socket_fallback'
        }
        
        # Common ports to check
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443]
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((hostname, port))
                
                if result == 0:
                    scan_results['tcp_ports'][port] = {
                        'state': 'open',
                        'name': self._get_service_name(port),
                        'method': 'socket'
                    }
                sock.close()
                
                # Rate limiting
                await asyncio.sleep(0.1)
                
            except Exception:
                pass
        
        scan_results['scan_stats'] = {
            'tcp_ports_scanned': len(common_ports),
            'tcp_open_ports': len(scan_results['tcp_ports'])
        }
        
        return scan_results
    
    def _get_service_name(self, port: int) -> str:
        """Get service name for common ports"""
        services = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 143: 'imap', 443: 'https',
            993: 'imaps', 995: 'pop3s', 1433: 'mssql', 3306: 'mysql',
            3389: 'rdp', 5432: 'postgresql', 8080: 'http-alt', 8443: 'https-alt'
        }
        return services.get(port, 'unknown')
    
    async def _service_enumeration(self, hostname: str, port_scan: Dict[str, Any]) -> Dict[str, Any]:
        """Enumerate services on open ports"""
        services = {}
        
        tcp_ports = port_scan.get('tcp_ports', {})
        
        for port, port_info in tcp_ports.items():
            if port_info.get('state') == 'open':
                try:
                    service_info = await self._enumerate_service(hostname, port, port_info)
                    services[port] = service_info
                    
                    # Rate limiting
                    await asyncio.sleep(0.5)
                    
                except Exception as e:
                    logger.warning(f"⚠️ Service enumeration error for port {port}: {e}")
        
        return services
    
    async def _enumerate_service(self, hostname: str, port: int, port_info: Dict[str, Any]) -> Dict[str, Any]:
        """Enumerate specific service"""
        service_info = {
            'port': port,
            'service': port_info.get('name', 'unknown'),
            'version': port_info.get('version', 'unknown'),
            'product': port_info.get('product', 'unknown'),
            'banner': None,
            'vulnerabilities': []
        }
        
        # Try to grab banner
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((hostname, port))
            
            # Send appropriate probe based on service
            if port in [21, 22, 23, 25]:  # Services that send banner immediately
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                service_info['banner'] = banner
            elif port in [80, 8080]:  # HTTP services
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                service_info['banner'] = response.split('\r\n')[0] if response else None
            
            sock.close()
            
        except Exception as e:
            logger.debug(f"Banner grab failed for {hostname}:{port}: {e}")
        
        return service_info
    
    async def _test_network_protocols(self, hostname: str) -> Dict[str, Any]:
        """Test various network protocols"""
        protocol_results = {}
        
        # Test ICMP (ping)
        try:
            ping_result = await self._test_icmp(hostname)
            protocol_results['icmp'] = ping_result
        except Exception as e:
            logger.warning(f"⚠️ ICMP test error: {e}")
        
        # Test DNS
        try:
            dns_result = await self._test_dns_server(hostname)
            protocol_results['dns'] = dns_result
        except Exception as e:
            logger.warning(f"⚠️ DNS test error: {e}")
        
        return protocol_results
    
    async def _test_icmp(self, hostname: str) -> Dict[str, Any]:
        """Test ICMP connectivity"""
        icmp_result = {
            'reachable': False,
            'response_time': None
        }
        
        try:
            # Use ping command
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '1', hostname]
            
            start_time = time.time()
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            end_time = time.time()
            
            if result.returncode == 0:
                icmp_result['reachable'] = True
                icmp_result['response_time'] = round((end_time - start_time) * 1000, 2)
            
        except Exception as e:
            logger.debug(f"ICMP test failed: {e}")
        
        return icmp_result
    
    async def _test_dns_server(self, hostname: str) -> Dict[str, Any]:
        """Test if target is running DNS server"""
        dns_result = {
            'is_dns_server': False,
            'responds_to_queries': False
        }
        
        try:
            # Check if port 53 is open
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((hostname, 53))
            sock.close()
            
            if result == 0:
                dns_result['is_dns_server'] = True
                
                # Try a simple DNS query
                try:
                    import dns.resolver
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = [hostname]
                    resolver.timeout = 5
                    
                    # Try to resolve a common domain
                    answers = resolver.resolve('google.com', 'A')
                    if answers:
                        dns_result['responds_to_queries'] = True
                        
                except Exception:
                    pass
        
        except Exception as e:
            logger.debug(f"DNS server test failed: {e}")
        
        return dns_result
    
    async def _test_ssl_configuration(self, hostname: str) -> Dict[str, Any]:
        """Test SSL/TLS configuration"""
        ssl_results = {
            'ssl_enabled': False,
            'certificate_info': {},
            'vulnerabilities': []
        }
        
        # Check common SSL ports
        ssl_ports = [443, 8443, 993, 995]
        
        for port in ssl_ports:
            try:
                import ssl
                
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                
                ssl_sock = context.wrap_socket(sock, server_hostname=hostname)
                ssl_sock.connect((hostname, port))
                
                ssl_results['ssl_enabled'] = True
                
                # Get certificate info
                cert = ssl_sock.getpeercert()
                if cert:
                    ssl_results['certificate_info'][port] = {
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'version': cert.get('version'),
                        'serial_number': cert.get('serialNumber'),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter')
                    }
                
                ssl_sock.close()
                
                # Rate limiting
                await asyncio.sleep(0.5)
                
            except Exception as e:
                logger.debug(f"SSL test failed for {hostname}:{port}: {e}")
        
        return ssl_results
    
    def _analyze_network_findings(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze network scan results for vulnerabilities"""
        vulnerabilities = []
        
        # Analyze open ports
        vulnerabilities.extend(self._analyze_open_ports(scan_results))
        
        # Analyze services
        vulnerabilities.extend(self._analyze_services(scan_results))
        
        # Analyze SSL/TLS
        vulnerabilities.extend(self._analyze_ssl_tls(scan_results))
        
        return vulnerabilities
    
    def _analyze_open_ports(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze open ports for security issues"""
        vulnerabilities = []
        
        tcp_ports = scan_results.get('port_scan', {}).get('tcp_ports', {})
        
        # High-risk ports
        high_risk_ports = {
            21: ('FTP Service', 'FTP may allow anonymous access or be vulnerable to attacks'),
            23: ('Telnet Service', 'Telnet transmits credentials in plaintext'),
            135: ('RPC Service', 'Windows RPC service may be vulnerable to attacks'),
            139: ('NetBIOS Service', 'NetBIOS may expose system information'),
            445: ('SMB Service', 'SMB service may be vulnerable to various attacks'),
            1433: ('MSSQL Service', 'Database service exposed to network'),
            3389: ('RDP Service', 'Remote Desktop may be vulnerable to brute force attacks')
        }
        
        for port, port_info in tcp_ports.items():
            if port_info.get('state') == 'open' and port in high_risk_ports:
                service_name, description = high_risk_ports[port]
                
                vulnerabilities.append({
                    'title': f'High-Risk Service: {service_name} on Port {port}',
                    'severity': 'High',
                    'cvss': 7.0,
                    'description': description,
                    'url': f"{scan_results['target']}:{port}",
                    'parameter': f'port_{port}',
                    'remediation': f'Review necessity of {service_name} and implement proper security controls',
                    'discovered_by': 'Network Agent'
                })
        
        return vulnerabilities
    
    def _analyze_services(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze service enumeration results"""
        vulnerabilities = []
        
        services = scan_results.get('services', {})
        
        for port, service_info in services.items():
            # Check for version disclosure
            if (service_info.get('version') and 
                service_info['version'] != 'unknown' and 
                service_info['version']):
                
                vulnerabilities.append({
                    'title': f'Service Version Disclosure on Port {port}',
                    'severity': 'Low',
                    'cvss': 2.0,
                    'description': f'Service version disclosed: {service_info["version"]}',
                    'url': f"{scan_results['target']}:{port}",
                    'parameter': 'service_version',
                    'remediation': 'Consider hiding service version information',
                    'discovered_by': 'Network Agent'
                })
            
            # Check for banner disclosure
            if service_info.get('banner'):
                vulnerabilities.append({
                    'title': f'Service Banner Disclosure on Port {port}',
                    'severity': 'Low',
                    'cvss': 1.0,
                    'description': f'Service banner disclosed: {service_info["banner"][:100]}...',
                    'url': f"{scan_results['target']}:{port}",
                    'parameter': 'service_banner',
                    'remediation': 'Consider customizing or hiding service banners',
                    'discovered_by': 'Network Agent'
                })
        
        return vulnerabilities
    
    def _analyze_ssl_tls(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze SSL/TLS configuration"""
        vulnerabilities = []
        
        ssl_results = scan_results.get('ssl_tls', {})
        
        if ssl_results.get('ssl_enabled'):
            cert_info = ssl_results.get('certificate_info', {})
            
            for port, cert_data in cert_info.items():
                # Check certificate expiration (basic check)
                if 'not_after' in cert_data:
                    vulnerabilities.append({
                        'title': f'SSL Certificate Information Disclosure on Port {port}',
                        'severity': 'Low',
                        'cvss': 1.0,
                        'description': f'SSL certificate details exposed',
                        'url': f"{scan_results['target']}:{port}",
                        'parameter': 'ssl_certificate',
                        'remediation': 'Ensure SSL certificate is properly configured and up to date',
                        'discovered_by': 'Network Agent'
                    })
        
        return vulnerabilities
