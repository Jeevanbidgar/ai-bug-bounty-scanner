# API Agent - API Security Testing
"""
Real API security testing agent.
Performs API-specific security testing including REST API vulnerabilities,
authentication bypass, and API endpoint discovery.
"""

import requests
import asyncio
import aiohttp
import json
import time
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Any, Tuple
import logging
import re

from .security_validator import SecurityValidator

logger = logging.getLogger(__name__)

class APIAgent:
    """Real API security testing agent"""
    
    def __init__(self):
        self.session = requests.Session()
        self.config = SecurityValidator.get_safe_scan_config()
        
        # Configure session
        self.session.headers.update({
            'User-Agent': self.config['user_agent'],
            'Accept': 'application/json, text/plain, */*',
            'Content-Type': 'application/json'
        })
        self.session.timeout = self.config['timeout']
        
        # Common API endpoints to test
        self.common_endpoints = [
            '/api', '/api/v1', '/api/v2', '/rest', '/graphql',
            '/swagger', '/swagger.json', '/swagger-ui', '/docs',
            '/openapi.json', '/api-docs', '/redoc'
        ]
        
        # API authentication bypass payloads
        self.auth_bypass_payloads = [
            {'admin': True},
            {'role': 'admin'},
            {'is_admin': True},
            {'user_type': 'admin'},
            {'permissions': ['admin']},
            {'access_level': 'admin'}
        ]
    
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
                
                # Test API authentication
                logger.info("🔐 Testing API authentication...")
                auth_vulns = await self._test_api_authentication(target_url, endpoints)
                results['vulnerabilities'].extend(auth_vulns)
                
                # Test for API injection vulnerabilities
                logger.info("💉 Testing for API injection vulnerabilities...")
                injection_vulns = await self._test_api_injection(target_url, endpoints)
                results['vulnerabilities'].extend(injection_vulns)
                
                # Test API rate limiting
                logger.info("⏱️ Testing API rate limiting...")
                rate_limit_vulns = await self._test_rate_limiting(target_url, endpoints)
                results['vulnerabilities'].extend(rate_limit_vulns)
                
                # Test for sensitive data exposure
                logger.info("📊 Testing for sensitive data exposure...")
                data_exposure_vulns = await self._test_data_exposure(target_url, endpoints)
                results['vulnerabilities'].extend(data_exposure_vulns)
                
                # Test API versioning issues
                logger.info("🔄 Testing API versioning...")
                version_vulns = await self._test_api_versioning(target_url, endpoints)
                results['vulnerabilities'].extend(version_vulns)
                
                logger.info(f"✅ API security scan completed: found {len(results['vulnerabilities'])} vulnerabilities")
                
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
        """Test API rate limiting"""
        vulnerabilities = []
        
        for endpoint_info in endpoints[:3]:  # Test only first 3 endpoints for safety
            endpoint_url = endpoint_info['url']
            
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
                        'title': 'Missing API Rate Limiting',
                        'severity': 'Medium',
                        'cvss': 5.0,
                        'description': f'No rate limiting detected on API endpoint {endpoint_url}',
                        'url': endpoint_url,
                        'parameter': 'rate_limiting',
                        'remediation': 'Implement API rate limiting to prevent abuse',
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
