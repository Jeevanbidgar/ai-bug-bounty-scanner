# Enhanced Recon Agent with External Tool Integration
"""
Enhanced reconnaissance agent with:
- Sublist3r integration for subdomain discovery
- Amass integration for asset discovery
- Shodan API for service intelligence
- Advanced logging and error handling
"""

import asyncio
import subprocess
import json
import logging
import os
import tempfile
from urllib.parse import urlparse
from typing import Dict, List, Any, Optional
import aiohttp
import dns.resolver
import requests

from .security_validator import SecurityValidator

logger = logging.getLogger(__name__)

class EnhancedReconAgent:
    """Enhanced reconnaissance agent with external tool integration"""
    
    def __init__(self):
        self.session = None
        self.shodan_api_key = os.getenv('SHODAN_API_KEY')
        self.config = SecurityValidator.get_safe_scan_config()
        
        # Tool paths
        self.sublist3r_path = self._find_sublist3r()
        self.amass_path = self._find_amass()
        
        logger.info("Enhanced Recon Agent initialized", 
                   shodan_available=bool(self.shodan_api_key),
                   sublist3r_available=bool(self.sublist3r_path),
                   amass_available=bool(self.amass_path))
    
    def _find_sublist3r(self) -> Optional[str]:
        """Find Sublist3r installation"""
        possible_paths = [
            '/opt/Sublist3r/sublist3r.py',
            '/usr/local/bin/sublist3r',
            'sublist3r'
        ]
        
        for path in possible_paths:
            try:
                result = subprocess.run(['python3', path, '-h'], 
                                      capture_output=True, timeout=5)
                if result.returncode == 0:
                    return path
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        
        logger.warning("Sublist3r not found - subdomain enumeration will be limited")
        return None
    
    def _find_amass(self) -> Optional[str]:
        """Find Amass installation"""
        try:
            result = subprocess.run(['amass', 'help'], capture_output=True, timeout=5)
            if result.returncode == 0:
                return 'amass'
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        logger.warning("Amass not found - asset discovery will be limited")
        return None
    
    async def scan_target(self, target_url: str, progress_callback=None) -> Dict[str, Any]:
        """
        Comprehensive reconnaissance scan with external tools
        """
        logger.info("Starting enhanced reconnaissance scan", target=target_url)
        
        # Initialize aiohttp session
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.config['timeout']),
            headers={'User-Agent': self.config['user_agent']}
        )
        
        try:
            domain = self._extract_domain(target_url)
            
            results = {
                'target': target_url,
                'domain': domain,
                'scan_type': 'enhanced_reconnaissance',
                'vulnerabilities': [],
                'subdomains': [],
                'dns_records': {},
                'open_ports': [],
                'technologies': {},
                'shodan_data': {},
                'assets': []
            }
            
            # Phase 1: DNS Enumeration (10%)
            if progress_callback:
                progress_callback(10, "🔍 Performing DNS enumeration...")
            
            results['dns_records'] = await self._enhanced_dns_enumeration(domain)
            
            # Phase 2: Subdomain Discovery (30%)
            if progress_callback:
                progress_callback(30, "🌐 Discovering subdomains with external tools...")
            
            results['subdomains'] = await self._enhanced_subdomain_discovery(domain)
            
            # Phase 3: Asset Discovery (50%)
            if progress_callback:
                progress_callback(50, "🎯 Performing asset discovery...")
            
            results['assets'] = await self._asset_discovery(domain)
            
            # Phase 4: Port Scanning (70%)
            if progress_callback:
                progress_callback(70, "🔌 Scanning for open ports...")
            
            results['open_ports'] = await self._enhanced_port_scan(domain)
            
            # Phase 5: Shodan Intelligence (85%)
            if progress_callback:
                progress_callback(85, "🛰️ Gathering Shodan intelligence...")
            
            if self.shodan_api_key:
                results['shodan_data'] = await self._shodan_lookup(domain)
            
            # Phase 6: Technology Detection (95%)
            if progress_callback:
                progress_callback(95, "⚙️ Detecting technologies...")
            
            results['technologies'] = await self._enhanced_technology_detection(target_url)
            
            # Analyze findings for vulnerabilities
            results['vulnerabilities'] = self._analyze_recon_findings(results)
            
            logger.info("Enhanced reconnaissance completed", 
                       target=target_url,
                       subdomains=len(results['subdomains']),
                       vulnerabilities=len(results['vulnerabilities']))
            
            return results
            
        finally:
            if self.session:
                await self.session.close()
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        parsed = urlparse(url)
        return parsed.netloc or url
    
    async def _enhanced_dns_enumeration(self, domain: str) -> Dict[str, Any]:
        """Enhanced DNS enumeration with multiple record types"""
        logger.info("Performing enhanced DNS enumeration", domain=domain)
        
        dns_records = {
            'A': [],
            'AAAA': [],
            'MX': [],
            'NS': [],
            'TXT': [],
            'CNAME': [],
            'SOA': [],
            'SRV': []
        }
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                dns_records[record_type] = [str(answer) for answer in answers]
                logger.debug("DNS record found", type=record_type, 
                           count=len(dns_records[record_type]))
            except Exception as e:
                logger.debug("DNS record not found", type=record_type, error=str(e))
        
        # Additional SRV records for common services
        srv_services = ['_http._tcp', '_https._tcp', '_ftp._tcp', '_ssh._tcp']
        
        for service in srv_services:
            try:
                answers = dns.resolver.resolve(f"{service}.{domain}", 'SRV')
                dns_records['SRV'].extend([str(answer) for answer in answers])
            except Exception:
                pass
        
        return dns_records
    
    async def _enhanced_subdomain_discovery(self, domain: str) -> List[str]:
        """Enhanced subdomain discovery using multiple tools"""
        logger.info("Starting enhanced subdomain discovery", domain=domain)
        
        subdomains = set()
        
        # Method 1: Sublist3r
        if self.sublist3r_path:
            sublist3r_results = await self._run_sublist3r(domain)
            subdomains.update(sublist3r_results)
            logger.info("Sublist3r results", count=len(sublist3r_results))
        
        # Method 2: Certificate Transparency
        ct_results = await self._certificate_transparency_search(domain)
        subdomains.update(ct_results)
        logger.info("Certificate Transparency results", count=len(ct_results))
        
        # Method 3: DNS Brute Force (common subdomains)
        brute_results = await self._dns_brute_force(domain)
        subdomains.update(brute_results)
        logger.info("DNS Brute Force results", count=len(brute_results))
        
        # Filter and validate subdomains
        valid_subdomains = []
        for subdomain in subdomains:
            if await self._validate_subdomain(subdomain):
                valid_subdomains.append(subdomain)
        
        logger.info("Subdomain discovery completed", 
                   total_found=len(subdomains),
                   valid=len(valid_subdomains))
        
        return sorted(valid_subdomains)
    
    async def _run_sublist3r(self, domain: str) -> List[str]:
        """Run Sublist3r for subdomain enumeration"""
        if not self.sublist3r_path:
            return []
        
        try:
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.txt', delete=False) as f:
                output_file = f.name
            
            cmd = [
                'python3', self.sublist3r_path,
                '-d', domain,
                '-o', output_file,
                '-t', '50'  # Use 50 threads
            ]
            
            logger.info("Running Sublist3r", command=' '.join(cmd))
            
            # Run with timeout
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
                
                # Read results from output file
                subdomains = []
                if os.path.exists(output_file):
                    with open(output_file, 'r') as f:
                        subdomains = [line.strip() for line in f if line.strip()]
                
                os.unlink(output_file)
                return subdomains
                
            except asyncio.TimeoutError:
                proc.kill()
                logger.warning("Sublist3r timed out")
                return []
                
        except Exception as e:
            logger.error("Sublist3r execution failed", error=str(e))
            return []
    
    async def _certificate_transparency_search(self, domain: str) -> List[str]:
        """Search Certificate Transparency logs for subdomains"""
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    subdomains = set()
                    for cert in data:
                        name_value = cert.get('name_value', '')
                        for name in name_value.split('\n'):
                            name = name.strip()
                            if name.endswith(f'.{domain}') or name == domain:
                                # Remove wildcards
                                if name.startswith('*.'):
                                    name = name[2:]
                                subdomains.add(name)
                    
                    return list(subdomains)
        
        except Exception as e:
            logger.error("Certificate Transparency search failed", error=str(e))
        
        return []
    
    async def _dns_brute_force(self, domain: str) -> List[str]:
        """DNS brute force with common subdomain names"""
        common_subdomains = [
            'www', 'mail', 'ftp', 'ssh', 'remote', 'vpn', 'admin', 'blog',
            'api', 'dev', 'test', 'staging', 'demo', 'portal', 'support',
            'help', 'docs', 'cdn', 'media', 'static', 'img', 'images',
            'assets', 'files', 'upload', 'downloads', 'secure', 'login',
            'auth', 'sso', 'ldap', 'ad', 'exchange', 'owa', 'webmail',
            'cpanel', 'whm', 'plesk', 'directadmin', 'mysql', 'phpmyadmin',
            'grafana', 'kibana', 'jenkins', 'gitlab', 'github', 'bitbucket'
        ]
        
        valid_subdomains = []
        semaphore = asyncio.Semaphore(20)  # Limit concurrent DNS queries
        
        async def check_subdomain(subdomain):
            async with semaphore:
                full_domain = f"{subdomain}.{domain}"
                try:
                    answers = dns.resolver.resolve(full_domain, 'A')
                    if answers:
                        return full_domain
                except Exception:
                    pass
                return None
        
        tasks = [check_subdomain(sub) for sub in common_subdomains]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        valid_subdomains = [result for result in results if result and isinstance(result, str)]
        
        return valid_subdomains
    
    async def _validate_subdomain(self, subdomain: str) -> bool:
        """Validate if subdomain resolves and is accessible"""
        try:
            # DNS resolution check
            answers = dns.resolver.resolve(subdomain, 'A')
            if not answers:
                return False
            
            # HTTP accessibility check (optional, can be slow)
            # Uncomment if you want to verify HTTP accessibility
            # try:
            #     async with self.session.get(f"http://{subdomain}", timeout=5) as response:
            #         return True
            # except:
            #     try:
            #         async with self.session.get(f"https://{subdomain}", timeout=5) as response:
            #             return True
            #     except:
            #         pass
            
            return True
            
        except Exception:
            return False
    
    async def _asset_discovery(self, domain: str) -> List[Dict[str, Any]]:
        """Asset discovery using Amass and other techniques"""
        assets = []
        
        # Method 1: Amass if available
        if self.amass_path:
            amass_assets = await self._run_amass(domain)
            assets.extend(amass_assets)
        
        # Method 2: WHOIS information
        whois_assets = await self._whois_discovery(domain)
        assets.extend(whois_assets)
        
        # Method 3: ASN enumeration
        asn_assets = await self._asn_enumeration(domain)
        assets.extend(asn_assets)
        
        return assets
    
    async def _run_amass(self, domain: str) -> List[Dict[str, Any]]:
        """Run Amass for asset discovery"""
        if not self.amass_path:
            return []
        
        try:
            cmd = [
                'amass', 'enum',
                '-d', domain,
                '-json'
            ]
            
            logger.info("Running Amass", command=' '.join(cmd))
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
                
                assets = []
                for line in stdout.decode().split('\n'):
                    if line.strip():
                        try:
                            asset_data = json.loads(line)
                            assets.append({
                                'name': asset_data.get('name', ''),
                                'type': 'subdomain',
                                'source': 'amass',
                                'addresses': asset_data.get('addresses', [])
                            })
                        except json.JSONDecodeError:
                            continue
                
                return assets
                
            except asyncio.TimeoutError:
                proc.kill()
                logger.warning("Amass timed out")
                return []
                
        except Exception as e:
            logger.error("Amass execution failed", error=str(e))
            return []
    
    async def _whois_discovery(self, domain: str) -> List[Dict[str, Any]]:
        """Discover assets through WHOIS information"""
        try:
            import whois
            
            whois_data = whois.whois(domain)
            assets = []
            
            # Extract nameservers
            nameservers = whois_data.name_servers or []
            for ns in nameservers:
                if ns:
                    assets.append({
                        'name': ns,
                        'type': 'nameserver',
                        'source': 'whois'
                    })
            
            # Extract email domains
            emails = whois_data.emails or []
            for email in emails:
                if email and '@' in email:
                    email_domain = email.split('@')[1]
                    if email_domain != domain:
                        assets.append({
                            'name': email_domain,
                            'type': 'related_domain',
                            'source': 'whois'
                        })
            
            return assets
            
        except Exception as e:
            logger.error("WHOIS discovery failed", error=str(e))
            return []
    
    async def _asn_enumeration(self, domain: str) -> List[Dict[str, Any]]:
        """Enumerate ASN-related assets"""
        # This would typically involve BGP data sources
        # For now, return empty list as it requires specialized APIs
        return []
    
    async def _enhanced_port_scan(self, domain: str) -> List[Dict[str, Any]]:
        """Enhanced port scanning with service detection"""
        logger.info("Starting enhanced port scan", domain=domain)
        
        # Common ports to scan
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995,
            993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443
        ]
        
        open_ports = []
        semaphore = asyncio.Semaphore(50)  # Limit concurrent connections
        
        async def scan_port(port):
            async with semaphore:
                try:
                    future = asyncio.open_connection(domain, port)
                    reader, writer = await asyncio.wait_for(future, timeout=3)
                    writer.close()
                    await writer.wait_closed()
                    
                    # Get service banner if possible
                    banner = await self._get_service_banner(domain, port)
                    
                    return {
                        'port': port,
                        'state': 'open',
                        'service': self._guess_service(port),
                        'banner': banner
                    }
                except Exception:
                    return None
        
        tasks = [scan_port(port) for port in common_ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        open_ports = [result for result in results if result]
        
        logger.info("Port scan completed", open_ports=len(open_ports))
        return open_ports
    
    async def _get_service_banner(self, hostname: str, port: int) -> str:
        """Get service banner from open port"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(hostname, port), timeout=5
            )
            
            # Send basic probe
            writer.write(b'\r\n')
            await writer.drain()
            
            # Read response
            banner = await asyncio.wait_for(reader.read(1024), timeout=3)
            
            writer.close()
            await writer.wait_closed()
            
            return banner.decode('utf-8', errors='ignore').strip()
            
        except Exception:
            return ''
    
    def _guess_service(self, port: int) -> str:
        """Guess service based on port number"""
        port_services = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
            53: 'dns', 80: 'http', 110: 'pop3', 143: 'imap',
            443: 'https', 993: 'imaps', 995: 'pop3s',
            1433: 'mssql', 3306: 'mysql', 3389: 'rdp',
            5432: 'postgresql', 5900: 'vnc', 6379: 'redis',
            8080: 'http-alt', 8443: 'https-alt'
        }
        return port_services.get(port, 'unknown')
    
    async def _shodan_lookup(self, domain: str) -> Dict[str, Any]:
        """Lookup domain information in Shodan"""
        if not self.shodan_api_key:
            return {}
        
        try:
            import shodan
            
            api = shodan.Shodan(self.shodan_api_key)
            
            # Get IP address
            try:
                answers = dns.resolver.resolve(domain, 'A')
                ip = str(answers[0])
            except Exception:
                return {}
            
            # Shodan host lookup
            try:
                host_info = api.host(ip)
                
                shodan_data = {
                    'ip': ip,
                    'country': host_info.get('country_name'),
                    'city': host_info.get('city'),
                    'org': host_info.get('org'),
                    'isp': host_info.get('isp'),
                    'ports': host_info.get('ports', []),
                    'services': []
                }
                
                # Extract service information
                for item in host_info.get('data', []):
                    service = {
                        'port': item.get('port'),
                        'product': item.get('product'),
                        'version': item.get('version'),
                        'banner': item.get('data', '').strip()[:200]
                    }
                    shodan_data['services'].append(service)
                
                logger.info("Shodan lookup successful", 
                           ip=ip, services=len(shodan_data['services']))
                
                return shodan_data
                
            except shodan.APIError as e:
                logger.warning("Shodan API error", error=str(e))
                return {}
                
        except Exception as e:
            logger.error("Shodan lookup failed", error=str(e))
            return {}
    
    async def _enhanced_technology_detection(self, target_url: str) -> Dict[str, Any]:
        """Enhanced technology detection"""
        technologies = {
            'server': 'unknown',
            'cms': 'unknown',
            'framework': 'unknown',
            'programming_language': 'unknown',
            'database': 'unknown',
            'cdn': 'unknown'
        }
        
        try:
            async with self.session.get(target_url) as response:
                headers = response.headers
                content = await response.text()
                
                # Server detection
                if 'Server' in headers:
                    technologies['server'] = headers['Server']
                
                # CMS detection (basic patterns)
                cms_patterns = {
                    'wordpress': ['wp-content', 'wp-includes'],
                    'drupal': ['drupal', 'sites/default'],
                    'joomla': ['joomla', 'components/com_'],
                    'magento': ['magento', 'skin/frontend']
                }
                
                for cms, patterns in cms_patterns.items():
                    if any(pattern in content.lower() for pattern in patterns):
                        technologies['cms'] = cms
                        break
                
                # Framework detection
                framework_headers = {
                    'X-Powered-By': 'framework',
                    'X-AspNet-Version': 'asp.net',
                    'X-Generator': 'framework'
                }
                
                for header, tech in framework_headers.items():
                    if header in headers:
                        technologies['framework'] = headers[header]
                
                # CDN detection
                cdn_headers = [
                    'CF-Ray',  # Cloudflare
                    'X-Served-By',  # Fastly
                    'X-Cache',  # Various CDNs
                    'X-CDN-Provider'
                ]
                
                for header in cdn_headers:
                    if header in headers:
                        technologies['cdn'] = headers[header]
                        break
        
        except Exception as e:
            logger.error("Technology detection failed", error=str(e))
        
        return technologies
    
    def _analyze_recon_findings(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze reconnaissance findings for potential vulnerabilities"""
        vulnerabilities = []
        
        # Analyze subdomains for potential issues
        for subdomain in results.get('subdomains', []):
            if any(keyword in subdomain.lower() for keyword in ['test', 'dev', 'staging', 'admin']):
                vulnerabilities.append({
                    'title': f'Development/Admin Subdomain Exposed: {subdomain}',
                    'severity': 'Medium',
                    'cvss': 5.3,
                    'description': f'Found potentially sensitive subdomain: {subdomain}. Development and admin subdomains should not be publicly accessible.',
                    'url': f'https://{subdomain}',
                    'remediation': 'Remove public access to development/admin subdomains or implement proper access controls.',
                    'discovered_by': 'Enhanced Recon Agent'
                })
        
        # Analyze open ports
        for port_info in results.get('open_ports', []):
            port = port_info['port']
            
            # Flag dangerous services
            if port in [23, 21, 1433, 3306, 5432, 6379]:  # Telnet, FTP, SQL services, Redis
                vulnerabilities.append({
                    'title': f'Potentially Insecure Service on Port {port}',
                    'severity': 'High',
                    'cvss': 7.5,
                    'description': f'Found {port_info["service"]} service on port {port}. This service may be insecure or provide unauthorized access.',
                    'url': results['target'],
                    'parameter': f'port_{port}',
                    'remediation': f'Secure or disable the {port_info["service"]} service. Implement proper authentication and encryption.',
                    'discovered_by': 'Enhanced Recon Agent'
                })
        
        # Analyze DNS records for security issues
        dns_records = results.get('dns_records', {})
        txt_records = dns_records.get('TXT', [])
        
        for txt_record in txt_records:
            if 'v=spf1' in txt_record and 'include:' in txt_record:
                # Basic SPF analysis
                if '~all' not in txt_record and '-all' not in txt_record:
                    vulnerabilities.append({
                        'title': 'Weak SPF Policy Configuration',
                        'severity': 'Low',
                        'cvss': 3.1,
                        'description': f'SPF record may be too permissive: {txt_record}',
                        'url': results['target'],
                        'remediation': 'Implement a stricter SPF policy with ~all or -all qualifier.',
                        'discovered_by': 'Enhanced Recon Agent'
                    })
        
        # Analyze Shodan data
        shodan_data = results.get('shodan_data', {})
        if shodan_data.get('services'):
            for service in shodan_data['services']:
                banner = service.get('banner', '').lower()
                if any(keyword in banner for keyword in ['default', 'admin', 'password', 'login']):
                    vulnerabilities.append({
                        'title': f'Service Banner Information Disclosure on Port {service["port"]}',
                        'severity': 'Low',
                        'cvss': 2.3,
                        'description': f'Service banner may reveal sensitive information: {service["banner"][:100]}',
                        'url': results['target'],
                        'parameter': f'port_{service["port"]}',
                        'remediation': 'Configure service to hide version and sensitive information in banners.',
                        'discovered_by': 'Enhanced Recon Agent'
                    })
        
        logger.info("Reconnaissance analysis completed", 
                   vulnerabilities=len(vulnerabilities))
        
        return vulnerabilities
