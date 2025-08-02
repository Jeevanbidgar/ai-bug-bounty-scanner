# Web Application Agent - Web Security Testing
"""
Real web application security testing agent.
Performs actual web vulnerability scanning including XSS, SQL injection, and other OWASP Top 10 issues.
"""

import requests
import asyncio
import aiohttp
import time
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from typing import Dict, List, Any, Tuple
import logging
import re

from .security_validator import SecurityValidator
from .agent_config_utils import is_test_enabled, log_test_execution

logger = logging.getLogger(__name__)

class WebAppAgent:
    """Real web application security testing agent"""
    
    def __init__(self):
        self.session = requests.Session()
        self.config = SecurityValidator.get_safe_scan_config()
        
        # Configure session with safe defaults
        self.session.headers.update({
            'User-Agent': self.config['user_agent']
        })
        self.session.timeout = self.config['timeout']
        self.session.max_redirects = self.config['max_redirects']
        
        # XSS payloads for testing
        self.xss_payloads = [
            '<script>alert("XSS")</script>',
            '"><script>alert("XSS")</script>',
            "'><script>alert('XSS')</script>",
            'javascript:alert("XSS")',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>'
        ]
        
        # SQL injection payloads
        self.sql_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "admin'--",
            "' OR 'a'='a",
            "1' OR '1'='1' #"
        ]
    
    async def scan_target(self, target_url: str, progress_callback=None) -> Dict[str, Any]:
        """
        Main web application scanning function
        
        Args:
            target_url: Target URL to scan
            
        Returns:
            Dict containing scan results and vulnerabilities
        """
        try:
            # Validate target
            SecurityValidator.validate_target(target_url)
            
            logger.info(f"🌐 Starting web application scan for: {target_url}")
            
            results = {
                'target': target_url,
                'timestamp': time.time(),
                'scan_type': 'web_application',
                'vulnerabilities': [],
                'executed_tests': [],
                'skipped_tests': []
            }
            
            try:
                # Crawl and discover forms/endpoints
                if progress_callback:
                    progress_callback(10, "🕷️ Crawling web application and discovering endpoints...")
                logger.info("🕷️ Crawling web application...")
                crawl_data = await self._crawl_website(target_url)
                results['crawl_data'] = crawl_data

                # Test for XSS vulnerabilities (both reflected and stored)
                if is_test_enabled('webapp', 'xss_reflected') or is_test_enabled('webapp', 'xss_stored'):
                    if progress_callback:
                        progress_callback(30, "🔍 Testing for Cross-Site Scripting (XSS) vulnerabilities...")
                    logger.info("🔍 Testing for XSS vulnerabilities...")
                    xss_vulns = await self._test_xss_vulnerabilities(target_url, crawl_data)
                    results['vulnerabilities'].extend(xss_vulns)
                    results['executed_tests'].extend(['xss_reflected', 'xss_stored'])
                    log_test_execution('webapp', 'xss_reflected', True)
                    log_test_execution('webapp', 'xss_stored', True)
                else:
                    results['skipped_tests'].extend(['xss_reflected', 'xss_stored'])
                    log_test_execution('webapp', 'xss_reflected', False)
                    log_test_execution('webapp', 'xss_stored', False)

                # Test for SQL injection
                if is_test_enabled('webapp', 'sql_injection'):
                    if progress_callback:
                        progress_callback(50, "💉 Testing for SQL injection vulnerabilities...")
                    logger.info("💉 Testing for SQL injection...")
                    sql_vulns = await self._test_sql_injection(target_url, crawl_data)
                    results['vulnerabilities'].extend(sql_vulns)
                    results['executed_tests'].append('sql_injection')
                    log_test_execution('webapp', 'sql_injection', True)
                else:
                    results['skipped_tests'].append('sql_injection')
                    log_test_execution('webapp', 'sql_injection', False)

                # Test for security headers and clickjacking
                if is_test_enabled('webapp', 'clickjacking'):
                    if progress_callback:
                        progress_callback(70, "🛡️ Checking security headers and configurations...")
                    logger.info("🛡️ Checking security headers...")
                    header_vulns = await self._check_security_headers(target_url)
                    results['vulnerabilities'].extend(header_vulns)
                    results['executed_tests'].append('clickjacking')
                    log_test_execution('webapp', 'clickjacking', True)
                else:
                    results['skipped_tests'].append('clickjacking')
                    log_test_execution('webapp', 'clickjacking', False)

                # Test for directory traversal
                if is_test_enabled('webapp', 'path_traversal'):
                    if progress_callback:
                        progress_callback(85, "📁 Testing for directory traversal vulnerabilities...")
                    logger.info("📁 Testing for directory traversal...")
                    dir_vulns = await self._test_directory_traversal(target_url)
                    results['vulnerabilities'].extend(dir_vulns)
                    results['executed_tests'].append('path_traversal')
                    log_test_execution('webapp', 'path_traversal', True)
                else:
                    results['skipped_tests'].append('path_traversal')
                    log_test_execution('webapp', 'path_traversal', False)

                # Test for CSRF protection
                if is_test_enabled('webapp', 'csrf'):
                    if progress_callback:
                        progress_callback(90, "🔐 Testing for CSRF protection...")
                    logger.info("🔐 Testing for CSRF protection...")
                    csrf_vulns = await self._test_csrf_protection(target_url, crawl_data)
                    results['vulnerabilities'].extend(csrf_vulns)
                    results['executed_tests'].append('csrf')
                    log_test_execution('webapp', 'csrf', True)
                else:
                    results['skipped_tests'].append('csrf')
                    log_test_execution('webapp', 'csrf', False)

                # Test for information disclosure
                if progress_callback:
                    progress_callback(95, "ℹ️ Testing for information disclosure vulnerabilities...")
                logger.info("ℹ️ Testing for information disclosure...")
                info_vulns = await self._test_information_disclosure(target_url)
                results['vulnerabilities'].extend(info_vulns)

                if progress_callback:
                    progress_callback(100, f"✅ Web application scan completed: found {len(results['vulnerabilities'])} vulnerabilities")
                logger.info(f"✅ Web application scan completed: found {len(results['vulnerabilities'])} vulnerabilities")
                
            except Exception as scan_error:
                logger.error(f"❌ Web app scan error: {scan_error}")
                results['error'] = str(scan_error)
            
            return results
            
        except Exception as e:
            logger.error(f"❌ Web application scan failed: {e}")
            raise
    
    async def _crawl_website(self, base_url: str) -> Dict[str, Any]:
        """Crawl website to discover forms and endpoints"""
        crawl_data = {
            'forms': [],
            'links': [],
            'inputs': [],
            'pages_crawled': 0
        }
        
        try:
            visited_urls = set()
            urls_to_visit = [base_url]
            max_pages = self.config['max_pages']
            max_depth = self.config['max_depth']
            
            for depth in range(max_depth):
                if not urls_to_visit or crawl_data['pages_crawled'] >= max_pages:
                    break
                
                current_level_urls = urls_to_visit.copy()
                urls_to_visit.clear()
                
                for url in current_level_urls:
                    if url in visited_urls or crawl_data['pages_crawled'] >= max_pages:
                        continue
                    
                    try:
                        response = self.session.get(url, timeout=10)
                        if response.status_code == 200:
                            visited_urls.add(url)
                            crawl_data['pages_crawled'] += 1
                            
                            # Parse HTML content
                            soup = BeautifulSoup(response.content, 'html.parser')
                            
                            # Extract forms
                            forms = soup.find_all('form')
                            for form in forms:
                                form_data = self._extract_form_data(form, url)
                                crawl_data['forms'].append(form_data)
                            
                            # Extract links for next level
                            if depth < max_depth - 1:
                                links = soup.find_all('a', href=True)
                                for link in links:
                                    href = link['href']
                                    full_url = urljoin(url, href)
                                    
                                    # Only follow internal links
                                    if self._is_internal_url(full_url, base_url):
                                        urls_to_visit.append(full_url)
                        
                        # Rate limiting (reduced for faster scanning)
                        await asyncio.sleep(0.2)
                        
                    except Exception as e:
                        logger.warning(f"⚠️ Error crawling {url}: {e}")
                        continue
        
        except Exception as e:
            logger.warning(f"⚠️ Crawling error: {e}")
        
        return crawl_data
    
    def _extract_form_data(self, form, base_url: str) -> Dict[str, Any]:
        """Extract form data for testing"""
        form_data = {
            'action': urljoin(base_url, form.get('action', '')),
            'method': form.get('method', 'GET').upper(),
            'inputs': []
        }
        
        # Extract input fields
        inputs = form.find_all(['input', 'textarea', 'select'])
        for input_elem in inputs:
            input_data = {
                'name': input_elem.get('name', ''),
                'type': input_elem.get('type', 'text'),
                'value': input_elem.get('value', '')
            }
            if input_data['name']:  # Only include named inputs
                form_data['inputs'].append(input_data)
        
        return form_data
    
    def _is_internal_url(self, url: str, base_url: str) -> bool:
        """Check if URL is internal to the target domain"""
        try:
            base_domain = urlparse(base_url).netloc
            url_domain = urlparse(url).netloc
            return url_domain == base_domain or url_domain == ''
        except:
            return False
    
    async def _test_xss_vulnerabilities(self, base_url: str, crawl_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for Cross-Site Scripting vulnerabilities"""
        vulnerabilities = []
        
        # Test forms for XSS
        for form in crawl_data.get('forms', []):
            for payload in self.xss_payloads[:3]:  # Limit payloads for safety
                try:
                    # Prepare form data with XSS payload
                    form_data = {}
                    for input_field in form['inputs']:
                        if input_field['type'] not in ['submit', 'button', 'hidden']:
                            form_data[input_field['name']] = payload
                        else:
                            form_data[input_field['name']] = input_field['value']
                    
                    # Submit form
                    if form['method'] == 'POST':
                        response = self.session.post(form['action'], data=form_data, timeout=10)
                    else:
                        response = self.session.get(form['action'], params=form_data, timeout=10)
                    
                    # Check if payload is reflected
                    if payload in response.text and response.status_code == 200:
                        vulnerabilities.append({
                            'title': 'Cross-Site Scripting (XSS) Vulnerability',
                            'severity': 'High',
                            'cvss': 7.2,
                            'description': f'XSS vulnerability found in form at {form["action"]}',
                            'url': form['action'],
                            'parameter': ', '.join([inp['name'] for inp in form['inputs'] if inp['type'] not in ['submit', 'button', 'hidden']]),
                            'payload': payload,
                            'remediation': 'Implement proper input validation and output encoding',
                            'discovered_by': 'Web App Agent'
                        })
                        break  # Found XSS, no need to test more payloads for this form
                    
                    # Rate limiting (reduced for faster scanning)
                    await asyncio.sleep(0.2)
                    
                except Exception as e:
                    logger.warning(f"⚠️ XSS test error for {form['action']}: {e}")
                    continue
        
        return vulnerabilities
    
    async def _test_sql_injection(self, base_url: str, crawl_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for SQL injection vulnerabilities"""
        vulnerabilities = []
        
        # Test forms for SQL injection
        for form in crawl_data.get('forms', []):
            for payload in self.sql_payloads[:3]:  # Limit payloads for safety
                try:
                    # Prepare form data with SQL injection payload
                    form_data = {}
                    for input_field in form['inputs']:
                        if input_field['type'] not in ['submit', 'button', 'hidden']:
                            form_data[input_field['name']] = payload
                        else:
                            form_data[input_field['name']] = input_field['value']
                    
                    # Submit form
                    if form['method'] == 'POST':
                        response = self.session.post(form['action'], data=form_data, timeout=10)
                    else:
                        response = self.session.get(form['action'], params=form_data, timeout=10)
                    
                    # Check for SQL error indicators
                    sql_errors = [
                        'mysql_fetch_array', 'ORA-', 'Microsoft OLE DB',
                        'SQLServer JDBC Driver', 'PostgreSQL query failed',
                        'Warning: mysql_', 'MySQLSyntaxErrorException',
                        'valid MySQL result', 'check the manual that corresponds'
                    ]
                    
                    response_text = response.text.lower()
                    for error in sql_errors:
                        if error.lower() in response_text:
                            vulnerabilities.append({
                                'title': 'SQL Injection Vulnerability',
                                'severity': 'Critical',
                                'cvss': 9.1,
                                'description': f'SQL injection vulnerability found in form at {form["action"]}',
                                'url': form['action'],
                                'parameter': ', '.join([inp['name'] for inp in form['inputs'] if inp['type'] not in ['submit', 'button', 'hidden']]),
                                'payload': payload,
                                'remediation': 'Use parameterized queries and prepared statements',
                                'discovered_by': 'Web App Agent'
                            })
                            break
                    
                    # Rate limiting (reduced for faster scanning)
                    await asyncio.sleep(0.2)
                    
                except Exception as e:
                    logger.warning(f"⚠️ SQL injection test error for {form['action']}: {e}")
                    continue
        
        return vulnerabilities
    
    async def _check_security_headers(self, target_url: str) -> List[Dict[str, Any]]:
        """Check for exploitable security header issues only"""
        vulnerabilities = []
        
        try:
            response = self.session.get(target_url, timeout=10)
            headers = response.headers
            
            # Only check for security headers with demonstrated exploit potential
            # Check for missing X-Frame-Options only if page has sensitive forms/actions
            if 'X-Frame-Options' not in headers:
                # Check if page has forms or sensitive content
                soup = BeautifulSoup(response.text, 'html.parser')
                forms = soup.find_all('form')
                sensitive_keywords = ['login', 'password', 'admin', 'account', 'payment']
                
                has_sensitive_content = (
                    forms or 
                    any(keyword in response.text.lower() for keyword in sensitive_keywords)
                )
                
                if has_sensitive_content:
                    vulnerabilities.append({
                        'title': 'Missing X-Frame-Options on Sensitive Page',
                        'severity': 'Medium',
                        'cvss': 5.0,
                        'description': 'Page with sensitive content lacks clickjacking protection',
                        'url': target_url,
                        'parameter': 'x_frame_options',
                        'remediation': 'Implement X-Frame-Options header to prevent clickjacking attacks',
                        'discovered_by': 'Web App Agent'
                    })
            
            # Only check HSTS if site is HTTPS but allows HTTP fallback
            if target_url.startswith('https://') and 'Strict-Transport-Security' not in headers:
                # Test if HTTP version is accessible
                http_url = target_url.replace('https://', 'http://')
                try:
                    http_response = self.session.get(http_url, timeout=5, allow_redirects=False)
                    if http_response.status_code == 200:
                        vulnerabilities.append({
                            'title': 'Missing HSTS with HTTP Fallback Available',
                            'severity': 'Medium',
                            'cvss': 5.0,
                            'description': 'HTTPS site lacks HSTS header and HTTP version is accessible',
                            'url': target_url,
                            'parameter': 'hsts_missing',
                            'remediation': 'Implement HSTS header and redirect HTTP to HTTPS',
                            'discovered_by': 'Web App Agent'
                        })
                except:
                    pass  # HTTP not accessible, HSTS less critical
        
        except Exception as e:
            logger.warning(f"⚠️ Security headers check error: {e}")
        
        return vulnerabilities
    
    async def _test_directory_traversal(self, target_url: str) -> List[Dict[str, Any]]:
        """Test for directory traversal vulnerabilities"""
        vulnerabilities = []
        
        # Common directory traversal payloads
        traversal_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '....//....//....//etc/passwd'
        ]
        
        try:
            parsed_url = urlparse(target_url)
            
            # Test common parameters
            test_params = ['file', 'page', 'include', 'path', 'doc']
            
            for param in test_params:
                for payload in traversal_payloads:
                    try:
                        test_url = f"{target_url}?{param}={payload}"
                        response = self.session.get(test_url, timeout=10)
                        
                        # Check for directory traversal indicators
                        if ('root:' in response.text or 
                            'localhost' in response.text or
                            '[boot loader]' in response.text.lower()):
                            
                            vulnerabilities.append({
                                'title': 'Directory Traversal Vulnerability',
                                'severity': 'High',
                                'cvss': 7.5,
                                'description': f'Directory traversal vulnerability found in parameter {param}',
                                'url': test_url,
                                'parameter': param,
                                'payload': payload,
                                'remediation': 'Implement proper input validation and file access controls',
                                'discovered_by': 'Web App Agent'
                            })
                            break
                        
                        # Rate limiting (reduced for faster scanning)
                        await asyncio.sleep(0.2)
                        
                    except Exception as e:
                        logger.warning(f"⚠️ Directory traversal test error: {e}")
                        continue
        
        except Exception as e:
            logger.warning(f"⚠️ Directory traversal testing error: {e}")
        
        return vulnerabilities
    
    async def _test_csrf_protection(self, target_url: str, crawl_data: Dict) -> List[Dict[str, Any]]:
        """Test for CSRF protection on forms"""
        vulnerabilities = []
        
        try:
            forms = crawl_data.get('forms', [])
            
            for form in forms:
                try:
                    # Check if form has CSRF token
                    csrf_protected = False
                    
                    # Look for common CSRF token field names
                    csrf_field_names = ['csrf_token', '_token', 'authenticity_token', '_csrf', 'csrfmiddlewaretoken']
                    
                    for field in form.get('fields', []):
                        field_name = field.get('name', '').lower()
                        if any(csrf_name in field_name for csrf_name in csrf_field_names):
                            csrf_protected = True
                            break
                    
                    # Check for forms that modify data without CSRF protection
                    if not csrf_protected and form.get('method', '').upper() in ['POST', 'PUT', 'DELETE']:
                        vulnerabilities.append({
                            'type': 'Missing CSRF Protection',
                            'severity': 'Medium',
                            'description': f"Form at {form.get('action', 'unknown')} lacks CSRF protection",
                            'evidence': f"Form method: {form.get('method', 'unknown')}, Action: {form.get('action', 'unknown')}",
                            'recommendation': 'Implement CSRF tokens for all state-changing operations',
                            'cwe': 'CWE-352',
                            'owasp': 'A01:2021 - Broken Access Control'
                        })
                        
                        logger.info(f"🔍 Found form without CSRF protection: {form.get('action', 'unknown')}")
                
                except Exception as e:
                    logger.warning(f"⚠️ CSRF test error for form: {e}")
                    continue
        
        except Exception as e:
            logger.warning(f"⚠️ CSRF testing error: {e}")
        
        return vulnerabilities
    
    async def _test_information_disclosure(self, target_url: str) -> List[Dict[str, Any]]:
        """Test for information disclosure vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Test for common sensitive files
            sensitive_files = [
                'robots.txt', '.htaccess', 'web.config', 'phpinfo.php',
                'info.php', 'test.php', 'backup.sql', 'config.php',
                '.env', '.git/config', 'admin/', 'administrator/'
            ]
            
            base_url = target_url.rstrip('/')
            
            for file_path in sensitive_files:
                try:
                    test_url = f"{base_url}/{file_path}"
                    response = self.session.get(test_url, timeout=10)
                    
                    if response.status_code == 200 and len(response.text) > 0:
                        vulnerabilities.append({
                            'title': f'Information Disclosure: {file_path}',
                            'severity': 'Medium',
                            'cvss': 5.0,
                            'description': f'Sensitive file {file_path} is accessible',
                            'url': test_url,
                            'parameter': 'file_access',
                            'remediation': f'Restrict access to {file_path} or remove if not needed',
                            'discovered_by': 'Web App Agent'
                        })
                    
                    # Rate limiting (reduced for faster scanning)
                    await asyncio.sleep(0.2)
                    
                except Exception as e:
                    logger.warning(f"⚠️ Info disclosure test error for {file_path}: {e}")
                    continue
        
        except Exception as e:
            logger.warning(f"⚠️ Information disclosure testing error: {e}")
        
        return vulnerabilities
