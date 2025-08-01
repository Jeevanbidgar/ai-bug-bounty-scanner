# Network Agent - Network Security Testing
"""
Real network security testing agent.
Performs network-level security assessments including advanced port scanning,
service enumeration, and network protocol testing.
"""

# Try to import nmap, fall back to socket-based scanning if not available
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    nmap = None

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
        # Try to initialize nmap, fall back to socket scanning if not available
        if NMAP_AVAILABLE:
            try:
                self.nm = nmap.PortScanner()
                
                # Check if nmap executable is accessible
                try:
                    # Test if nmap can be found
                    self.nm.nmap_version()
                    self.nmap_available = True
                    logger.info("✅ Nmap available for advanced port scanning")
                except Exception as path_error:
                    # Try to set the nmap path for Windows
                    nmap_paths = [
                        r"C:\Program Files (x86)\Nmap",
                        r"C:\Program Files\Nmap",
                    ]
                    
                    nmap_found = False
                    for nmap_search_path in nmap_paths:
                        try:
                            import os
                            nmap_exe = os.path.join(nmap_search_path, "nmap.exe")
                            if os.path.exists(nmap_exe):
                                # Initialize with the directory path
                                self.nm = nmap.PortScanner(nmap_search_path=[nmap_search_path])
                                self.nm.nmap_version()
                                self.nmap_available = True
                                nmap_found = True
                                logger.info(f"✅ Nmap found at: {nmap_exe}")
                                break
                        except Exception as e:
                            logger.debug(f"Failed to initialize with path {nmap_search_path}: {e}")
                            continue
                    
                    # If manual paths failed, try with PATH environment
                    if not nmap_found:
                        try:
                            # Try to add Nmap to current PATH and reinitialize
                            import os
                            current_path = os.environ.get('PATH', '')
                            nmap_dir = r"C:\Program Files (x86)\Nmap"
                            if nmap_dir not in current_path:
                                os.environ['PATH'] = current_path + os.pathsep + nmap_dir
                            
                            # Reinitialize with updated PATH
                            self.nm = nmap.PortScanner()
                            self.nm.nmap_version()
                            self.nmap_available = True
                            nmap_found = True
                            logger.info(f"✅ Nmap found after PATH update")
                        except Exception as e:
                            logger.debug(f"Failed with PATH update: {e}")
                    
                    if not nmap_found:
                        self.nm = None
                        self.nmap_available = False
                        logger.warning(f"⚠️ Nmap executable not accessible: {path_error}")
                        logger.warning("⚠️ Using socket-based scanning instead")
                        
            except Exception as e:
                self.nm = None
                self.nmap_available = False
                logger.warning(f"⚠️ Nmap initialization failed, using socket-based scanning: {e}")
        else:
            self.nm = None
            self.nmap_available = False
            logger.warning("⚠️ Nmap not installed, using socket-based scanning")
            
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
            'scan_stats': {},
            'scan_method': 'nmap' if self.nmap_available else 'socket'
        }
        
        try:
            if self.nmap_available:
                # Use Nmap for advanced scanning
                await self._nmap_port_scan(hostname, scan_results)
            else:
                # Fall back to socket-based scanning
                await self._socket_port_scan(hostname, scan_results)
            
        except Exception as e:
            logger.error(f"❌ Port scan error: {e}")
            scan_results['error'] = str(e)
            
        return scan_results
    
    async def _nmap_port_scan(self, hostname: str, scan_results: Dict[str, Any]):
        """Perform port scanning using Nmap"""
        try:
            # TCP scan - fast and focused on common ports only
            logger.info("🔌 Scanning TCP ports with Nmap...")
            # Only scan most common ports for speed - reduced from 1000+ to ~25 ports
            tcp_ports = '21,22,23,25,53,80,110,135,139,143,443,445,587,993,995,1433,1521,3306,3389,5432,5900,8080,8443,9090'
            
            # Use faster nmap options with shorter timeouts
            tcp_args = '-sS -T4 --max-retries 1 --host-timeout 15s --max-rate 100'
            tcp_scan = self.nm.scan(hostname, tcp_ports, arguments=tcp_args)
            
            if hostname in tcp_scan['scan']:
                host_info = tcp_scan['scan'][hostname]
                if 'tcp' in host_info:
                    scan_results['tcp_ports'] = host_info['tcp']
            
            # Skip UDP scan for speed - UDP is much slower and often blocked by firewalls
            # UDP scan can add 30+ seconds even with short timeouts
            logger.info("⏩ Skipping UDP scan for faster results")
            scan_results['udp_ports'] = {}
                
        except Exception as e:
            logger.error(f"❌ Nmap scan failed: {e}")
            raise
    
    async def _socket_port_scan(self, hostname: str, scan_results: Dict[str, Any]):
        """Perform port scanning using Python sockets"""
        logger.info("🔌 Scanning TCP ports with socket-based method...")
        
        # Common ports to scan when Nmap is not available - reduced set for speed
        tcp_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 587, 993, 995, 
                    1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443, 9090]
        
        tcp_results = {}
        
        # Resolve hostname to IP
        try:
            ip_address = socket.gethostbyname(hostname)
            logger.info(f"🔍 Resolved {hostname} to {ip_address}")
        except socket.gaierror:
            logger.error(f"❌ Could not resolve hostname: {hostname}")
            return
        
        # Scan TCP ports
        async def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)  # Reduced from 3 to 2 seconds for faster scanning
                result = sock.connect_ex((ip_address, port))
                sock.close()
                
                if result == 0:
                    # Port is open, try to get banner
                    banner = await self._get_service_banner(ip_address, port)
                    return {
                        'port': port,
                        'state': 'open',
                        'service': self._guess_service(port),
                        'banner': banner
                    }
            except Exception:
                pass
            return None
        
        # Scan ports concurrently but with rate limiting
        semaphore = asyncio.Semaphore(15)  # Increased from 10 to 15 for faster scanning
        
        async def scan_with_semaphore(port):
            async with semaphore:
                return await scan_port(port)
        
        # Create tasks for all ports
        tasks = [scan_with_semaphore(port) for port in tcp_ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for result in results:
            if result and not isinstance(result, Exception):
                port = result['port']
                tcp_results[port] = {
                    'state': result['state'],
                    'name': result['service'],
                    'product': result.get('banner', ''),
                    'version': '',
                    'extrainfo': 'Socket scan'
                }
        
        scan_results['tcp_ports'] = tcp_results
        logger.info(f"✅ Socket scan completed: found {len(tcp_results)} open ports")
    
    async def _get_service_banner(self, ip_address: str, port: int) -> str:
        """Try to get service banner for an open port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip_address, port))
            
            # Send HTTP request for web services
            if port in [80, 8080, 8443]:
                sock.send(b"GET / HTTP/1.0\r\n\r\n")
            # Send basic greeting for other services
            else:
                sock.send(b"\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner[:200]  # Limit banner length
        except Exception:
            return ""
    
    def _guess_service(self, port: int) -> str:
        """Guess service name based on port number"""
        common_ports = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 135: 'msrpc', 139: 'netbios-ssn',
            143: 'imap', 443: 'https', 445: 'microsoft-ds', 587: 'submission',
            993: 'imaps', 995: 'pop3s', 1433: 'ms-sql-s', 1521: 'oracle',
            3306: 'mysql', 3389: 'ms-wbt-server', 5432: 'postgresql',
            5900: 'vnc', 8080: 'http-proxy', 8443: 'https-alt', 9090: 'zeus-admin'
        }
        return common_ports.get(port, f'unknown-{port}')

    
    async def _service_enumeration(self, hostname: str, port_scan: Dict[str, Any]) -> Dict[str, Any]:
        """Enumerate services on open ports"""
        services = {}
        
        tcp_ports = port_scan.get('tcp_ports', {})
        
        for port, port_info in tcp_ports.items():
            if port_info.get('state') == 'open':
                try:
                    service_info = await self._enumerate_service(hostname, port, port_info)
                    services[port] = service_info
                    
                    # Reduced rate limiting for faster enumeration
                    await asyncio.sleep(0.2)  # Reduced from 0.5 to 0.2 seconds
                    
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
            sock.settimeout(3)  # Reduced from 5 to 3 seconds for faster banner grabbing
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
            # Use ping command with shorter timeout
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '1', hostname]
            
            start_time = time.time()
            result = subprocess.run(command, capture_output=True, text=True, timeout=5)  # Reduced from 10 to 5 seconds
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
            # Check if port 53 is open with shorter timeout
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)  # Reduced from 3 to 2 seconds
            result = sock.connect_ex((hostname, 53))
            sock.close()
            
            if result == 0:
                dns_result['is_dns_server'] = True
                
                # Skip DNS query test for speed - just knowing port 53 is open is enough
                # DNS query testing can add significant time and is often blocked
                logger.debug(f"Port 53 open on {hostname}, skipping DNS query test for speed")
        
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
                sock.settimeout(5)  # Reduced from 10 to 5 seconds for faster SSL testing
                
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
                
                # Reduced rate limiting for faster SSL testing
                await asyncio.sleep(0.2)  # Reduced from 0.5 to 0.2 seconds
                
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
