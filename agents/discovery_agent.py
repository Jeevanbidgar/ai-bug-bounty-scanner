# Discovery Agent - Comprehensive Application Reconnaissance System
"""
Discovery Agent: The foundational intelligence-gathering system for the AI Bug Bounty Scanner.

This agent transforms the scanner from blind testing to intelligence-driven assessment by:
1. Running FIRST before any vulnerability testing begins
2. Building comprehensive application understanding through systematic reconnaissance
3. Creating detailed intelligence profiles that guide all subsequent testing activities
4. Providing the shared knowledge that transforms independent agents into a coordinated team

The Discovery Agent operates like a professional penetration tester's reconnaissance phase,
building complete understanding of the target environment before attempting any exploitation.
"""

import asyncio
import aiohttp
import time
import json
import re
import logging
import os
from typing import Dict, List, Any, Set, Optional, Tuple
from urllib.parse import urlparse, urljoin, urlunparse, parse_qs, urlencode
from bs4 import BeautifulSoup
import requests
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import hashlib
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from collections import defaultdict, deque

from .security_validator import SecurityValidator
from .agent_config_utils import is_test_enabled, log_test_execution
from config import Config

logger = logging.getLogger(__name__)

@dataclass
class FormData:
    """Data structure for discovered form information"""
    url: str
    method: str
    action: str
    parameters: Dict[str, Any]
    hidden_fields: Dict[str, str]
    validation_patterns: List[str]
    form_type: str  # login, search, upload, data_entry, etc.
    csrf_token: Optional[str] = None
    captcha_present: bool = False
    javascript_validation: bool = False

@dataclass
class PageData:
    """Data structure for discovered page information"""
    url: str
    title: str
    content_type: str
    status_code: int
    response_size: int
    page_type: str  # login, admin, content, api, error, etc.
    forms: List[FormData]
    links: List[str]
    scripts: List[str]
    stylesheets: List[str]
    images: List[str]
    requires_auth: bool = False
    auth_level: str = "public"  # public, user, admin, etc.

@dataclass
class TechnologyInfo:
    """Data structure for technology stack information"""
    web_server: Optional[str] = None
    web_framework: Optional[str] = None
    programming_language: Optional[str] = None
    database: Optional[str] = None
    cms: Optional[str] = None
    javascript_frameworks: List[str] = None
    libraries: List[str] = None
    security_headers: Dict[str, str] = None
    ssl_info: Optional[Dict[str, Any]] = None

@dataclass
class AuthenticationInfo:
    """Data structure for authentication system information"""
    login_url: Optional[str] = None
    logout_url: Optional[str] = None
    auth_method: str = "form_based"  # form_based, basic_auth, oauth, etc.
    session_management: str = "cookie_based"
    csrf_protection: bool = False
    captcha_protection: bool = False
    rate_limiting: bool = False
    account_lockout: bool = False
    password_policy: Optional[Dict[str, Any]] = None

@dataclass
class DiscoveryContext:
    """Central intelligence data structure for the entire scanner system"""
    target_url: str
    base_domain: str
    scan_timestamp: datetime
    pages_discovered: List[PageData]
    forms_discovered: List[FormData]
    technology_stack: TechnologyInfo
    authentication_system: AuthenticationInfo
    site_map: Dict[str, Any]
    input_vectors: List[Dict[str, Any]]
    api_endpoints: List[Dict[str, Any]]
    security_headers: Dict[str, str]
    ssl_certificate: Optional[Dict[str, Any]] = None
    robots_txt: Optional[str] = None
    sitemap_urls: List[str] = None
    error_pages: Dict[int, str] = None
    redirect_chains: List[Dict[str, Any]] = None
    javascript_files: List[str] = None
    css_files: List[str] = None
    image_files: List[str] = None
    external_resources: List[str] = None
    session_cookies: Dict[str, str] = None
    discovery_metadata: Dict[str, Any] = None

class DiscoveryAgent:
    """
    Comprehensive Discovery Agent for application reconnaissance and intelligence gathering.
    
    This agent serves as the foundation for the entire scanner system, providing
    detailed intelligence about target applications that guides all subsequent
    vulnerability testing activities.
    """
    
    def __init__(self):
        """Initialize the Discovery Agent with comprehensive reconnaissance capabilities"""
        self.session = requests.Session()
        self.config = SecurityValidator.get_safe_scan_config()
        
        # Configure session with safe defaults
        self.session.headers.update({
            'User-Agent': self.config['user_agent']
        })
        self.session.timeout = self.config['timeout']
        self.session.max_redirects = self.config['max_redirects']
        
        # Discovery state management
        self.discovered_urls = set()
        self.visited_urls = set()
        self.auth_credentials = None
        self.session_cookies = {}
        self.discovery_context = None
        
        # Common technology signatures
        self.tech_signatures = {
            'web_servers': {
                'apache': ['Apache', 'apache', 'mod_'],
                'nginx': ['nginx', 'Nginx'],
                'iis': ['IIS', 'Microsoft-IIS'],
                'lighttpd': ['lighttpd'],
                'caddy': ['Caddy']
            },
            'frameworks': {
                'django': ['Django', 'csrfmiddlewaretoken', '__admin__'],
                'flask': ['Flask', 'Werkzeug'],
                'laravel': ['Laravel', 'XSRF-TOKEN'],
                'rails': ['Rails', '_rails'],
                'spring': ['Spring', 'JSESSIONID'],
                'express': ['Express', 'express'],
                'asp.net': ['ASP.NET', 'ASPXAUTH'],
                'php': ['PHP', 'PHPSESSID', '.php'],
                'node.js': ['Node.js', 'node']
            },
            'databases': {
                'mysql': ['MySQL', 'mysql_', 'mysqli'],
                'postgresql': ['PostgreSQL', 'postgres'],
                'sqlite': ['SQLite', 'sqlite'],
                'mongodb': ['MongoDB', 'mongo'],
                'redis': ['Redis', 'redis']
            },
            'cms': {
                'wordpress': ['WordPress', 'wp-', 'wp_'],
                'drupal': ['Drupal', 'Drupal.settings'],
                'joomla': ['Joomla', 'joomla'],
                'magento': ['Magento', 'magento'],
                'shopify': ['Shopify', 'shopify']
            },
            'javascript_frameworks': {
                'react': ['React', 'react', 'react-dom'],
                'vue': ['Vue', 'vue', 'vue.js'],
                'angular': ['Angular', 'angular', 'ng-'],
                'jquery': ['jQuery', 'jquery'],
                'bootstrap': ['Bootstrap', 'bootstrap']
            }
        }
        
        # Common form field patterns
        self.form_patterns = {
            'login': ['username', 'user', 'email', 'login', 'password', 'pass', 'pwd'],
            'search': ['search', 'q', 'query', 'keyword'],
            'upload': ['file', 'upload', 'attachment'],
            'contact': ['name', 'email', 'message', 'subject', 'phone'],
            'registration': ['username', 'email', 'password', 'confirm', 'register']
        }
        
        # Common admin paths
        self.admin_paths = [
            'admin', 'administrator', 'manage', 'management', 'panel',
            'dashboard', 'control', 'console', 'backend', 'cpanel',
            'webadmin', 'adminpanel', 'admin_area', 'admin-area'
        ]
        
        logger.info("🔍 Discovery Agent initialized with comprehensive reconnaissance capabilities")

    async def scan_target(self, target_url: str, credentials: Optional[Dict[str, str]] = None, 
                         progress_callback=None) -> Dict[str, Any]:
        """
        Main discovery scanning function - runs FIRST before any vulnerability testing.
        
        Args:
            target_url: Target URL to discover
            credentials: Optional authentication credentials
            progress_callback: Optional progress callback function
            
        Returns:
            Dict containing comprehensive discovery results and intelligence data
        """
        try:
            # Validate target
            SecurityValidator.validate_target(target_url)
            
            logger.info(f"🔍 Starting comprehensive discovery scan for: {target_url}")
            
            # Initialize discovery context
            self.discovery_context = DiscoveryContext(
                target_url=target_url,
                base_domain=urlparse(target_url).netloc,
                scan_timestamp=datetime.now(timezone.utc),
                pages_discovered=[],
                forms_discovered=[],
                technology_stack=TechnologyInfo(),
                authentication_system=AuthenticationInfo(),
                site_map={},
                input_vectors=[],
                api_endpoints=[],
                security_headers={},
                sitemap_urls=[],
                error_pages={},
                redirect_chains=[],
                javascript_files=[],
                css_files=[],
                image_files=[],
                external_resources=[],
                session_cookies={},
                discovery_metadata={}
            )
            
            # Store credentials for authentication
            self.auth_credentials = credentials
            
            results = {
                'target': target_url,
                'timestamp': time.time(),
                'scan_type': 'discovery',
                'discovery_context': None,
                'executed_tests': [],
                'skipped_tests': [],
                'discovery_summary': {}
            }
            
            try:
                # Phase 1: Initial reconnaissance and technology identification
                if progress_callback:
                    progress_callback(10, "🔍 Phase 1: Initial reconnaissance and technology identification...")
                
                await self._initial_reconnaissance(target_url)
                
                # Phase 2: Application structure mapping
                if progress_callback:
                    progress_callback(30, "🗺️ Phase 2: Mapping application structure...")
                
                await self._map_application_structure(target_url)
                
                # Phase 3: Form discovery and analysis
                if progress_callback:
                    progress_callback(50, "📝 Phase 3: Discovering and analyzing forms...")
                
                await self._analyze_forms_and_inputs()
                
                # Phase 4: Authentication system analysis
                if progress_callback:
                    progress_callback(70, "🔐 Phase 4: Analyzing authentication system...")
                
                await self._handle_authentication_requirements()
                
                # Phase 5: Technology stack identification
                if progress_callback:
                    progress_callback(85, "⚙️ Phase 5: Identifying technology stack...")
                
                await self._identify_technology_stack()
                
                # Phase 6: Final intelligence compilation
                if progress_callback:
                    progress_callback(95, "📊 Phase 6: Compiling intelligence data...")
                
                await self._compile_intelligence_data()
                
                # Phase 7: Validation and quality assurance
                if progress_callback:
                    progress_callback(98, "✅ Phase 7: Validating discovery results...")
                
                await self._validate_discovery_results()
                
                if progress_callback:
                    progress_callback(100, "🎯 Discovery scan completed successfully!")
                
                # Convert discovery context to dict for storage
                results['discovery_context'] = asdict(self.discovery_context)
                results['discovery_summary'] = self._generate_discovery_summary()
                
                logger.info(f"✅ Discovery scan completed for {target_url}")
                logger.info(f"📊 Discovered {len(self.discovery_context.pages_discovered)} pages")
                logger.info(f"📝 Found {len(self.discovery_context.forms_discovered)} forms")
                logger.info(f"🔗 Identified {len(self.discovery_context.api_endpoints)} API endpoints")
                
                return results
                
            except Exception as e:
                logger.error(f"❌ Discovery scan failed: {e}")
                logger.error(f"📊 Discovery error details: {type(e).__name__}: {str(e)}")
                raise
                
        except Exception as e:
            logger.error(f"❌ Discovery Agent initialization failed: {e}")
            raise

    async def _initial_reconnaissance(self, target_url: str):
        """Phase 1: Initial reconnaissance and basic information gathering"""
        logger.info("🔍 Starting initial reconnaissance...")
        
        try:
            # Basic connectivity test
            response = await self._make_request(target_url)
            if not response:
                raise Exception(f"Cannot connect to target: {target_url}")
            
            # Extract basic information
            self.discovery_context.security_headers = dict(response.headers)
            self.discovery_context.ssl_certificate = await self._analyze_ssl_certificate(target_url)
            
            # Analyze robots.txt
            robots_url = urljoin(target_url, '/robots.txt')
            robots_response = await self._make_request(robots_url)
            if robots_response and robots_response.status_code == 200:
                self.discovery_context.robots_txt = robots_response.text
                logger.info("📄 Found robots.txt")
            
            # Analyze sitemap
            await self._analyze_sitemap(target_url)
            
            # Basic technology detection from headers
            await self._detect_technologies_from_headers(response)
            
            logger.info("✅ Initial reconnaissance completed")
            
        except Exception as e:
            logger.error(f"❌ Initial reconnaissance failed: {e}")
            raise

    async def _map_application_structure(self, target_url: str):
        """Phase 2: Comprehensive application structure mapping"""
        logger.info("🗺️ Starting application structure mapping...")
        
        try:
            # Start with the main page
            await self._discover_page(target_url, "main")
            
            # Crawl discovered links recursively
            await self._recursive_crawl(target_url, max_depth=3, max_pages=50)
            
            # Discover common admin paths
            await self._discover_admin_paths(target_url)
            
            # Discover API endpoints
            await self._discover_api_endpoints(target_url)
            
            # Build site map
            self.discovery_context.site_map = self._build_site_map()
            
            logger.info(f"✅ Application structure mapping completed - {len(self.discovered_urls)} URLs discovered")
            
        except Exception as e:
            logger.error(f"❌ Application structure mapping failed: {e}")
            raise

    async def _analyze_forms_and_inputs(self):
        """Phase 3: Comprehensive form discovery and analysis"""
        logger.info("📝 Starting form discovery and analysis...")
        
        try:
            for page in self.discovery_context.pages_discovered:
                if page.forms:
                    for form in page.forms:
                        # Analyze form structure
                        await self._analyze_form_structure(form)
                        
                        # Detect form type and purpose
                        form.form_type = self._detect_form_type(form)
                        
                        # Analyze validation patterns
                        form.validation_patterns = await self._analyze_form_validation(form)
                        
                        # Check for CSRF protection
                        form.csrf_token = self._detect_csrf_token(form)
                        
                        # Check for CAPTCHA
                        form.captcha_present = self._detect_captcha(form)
                        
                        # Add to global forms list
                        self.discovery_context.forms_discovered.append(form)
                        
                        # Create input vector entries
                        for param_name, param_info in form.parameters.items():
                            input_vector = {
                                'url': form.url,
                                'parameter': param_name,
                                'type': param_info.get('type', 'text'),
                                'required': param_info.get('required', False),
                                'validation': param_info.get('validation', []),
                                'form_type': form.form_type,
                                'method': form.method
                            }
                            self.discovery_context.input_vectors.append(input_vector)
            
            logger.info(f"✅ Form analysis completed - {len(self.discovery_context.forms_discovered)} forms analyzed")
            
        except Exception as e:
            logger.error(f"❌ Form analysis failed: {e}")
            raise

    async def _handle_authentication_requirements(self):
        """Phase 4: Authentication system analysis and handling"""
        logger.info("🔐 Starting authentication system analysis...")
        
        try:
            # Find login forms
            login_forms = [f for f in self.discovery_context.forms_discovered 
                          if f.form_type == 'login']
            
            if login_forms:
                login_form = login_forms[0]  # Use the first login form found
                self.discovery_context.authentication_system.login_url = login_form.url
                self.discovery_context.authentication_system.auth_method = "form_based"
                
                # Attempt authentication if credentials provided
                if self.auth_credentials:
                    await self._attempt_authentication(login_form)
                
                # Discover authenticated areas
                if self.session_cookies:
                    await self._discover_authenticated_areas()
            
            # Look for logout functionality
            logout_urls = [url for url in self.discovered_urls if 'logout' in url.lower()]
            if logout_urls:
                self.discovery_context.authentication_system.logout_url = logout_urls[0]
            
            # Analyze session management
            await self._analyze_session_management()
            
            logger.info("✅ Authentication system analysis completed")
            
        except Exception as e:
            logger.error(f"❌ Authentication analysis failed: {e}")
            raise

    async def _identify_technology_stack(self):
        """Phase 5: Comprehensive technology stack identification"""
        logger.info("⚙️ Starting technology stack identification...")
        
        try:
            # Analyze all discovered pages for technology signatures
            for page in self.discovery_context.pages_discovered:
                await self._analyze_page_technologies(page)
            
            # Analyze JavaScript files
            await self._analyze_javascript_technologies()
            
            # Analyze CSS files
            await self._analyze_css_technologies()
            
            # Database technology detection
            await self._detect_database_technologies()
            
            # CMS detection
            await self._detect_cms()
            
            logger.info("✅ Technology stack identification completed")
            
        except Exception as e:
            logger.error(f"❌ Technology stack identification failed: {e}")
            raise

    async def _compile_intelligence_data(self):
        """Phase 6: Compile comprehensive intelligence data"""
        logger.info("📊 Compiling intelligence data...")
        
        try:
            # Add discovery metadata
            self.discovery_context.discovery_metadata = {
                'total_pages': len(self.discovery_context.pages_discovered),
                'total_forms': len(self.discovery_context.forms_discovered),
                'total_input_vectors': len(self.discovery_context.input_vectors),
                'total_api_endpoints': len(self.discovery_context.api_endpoints),
                'authentication_required': bool(self.discovery_context.authentication_system.login_url),
                'scan_duration': time.time() - self.discovery_context.scan_timestamp.timestamp(),
                'discovery_methods_used': [
                    'application_mapping',
                    'form_analysis',
                    'technology_detection',
                    'authentication_analysis'
                ]
            }
            
            # Save discovery context to persistent storage
            await self._save_discovery_context()
            
            logger.info("✅ Intelligence data compilation completed")
            
        except Exception as e:
            logger.error(f"❌ Intelligence data compilation failed: {e}")
            raise

    async def _validate_discovery_results(self):
        """Phase 7: Validate discovery results and quality assurance"""
        logger.info("✅ Validating discovery results...")
        
        try:
            # Validate that we have basic information
            if not self.discovery_context.pages_discovered:
                raise Exception("No pages discovered - discovery may have failed")
            
            # Validate technology stack information
            if not any([self.discovery_context.technology_stack.web_server,
                       self.discovery_context.technology_stack.web_framework,
                       self.discovery_context.technology_stack.programming_language]):
                logger.warning("⚠️ Limited technology stack information discovered")
            
            # Validate form discovery
            if not self.discovery_context.forms_discovered:
                logger.warning("⚠️ No forms discovered - application may be static or use AJAX")
            
            # Check for common issues
            await self._check_discovery_quality()
            
            logger.info("✅ Discovery validation completed")
            
        except Exception as e:
            logger.error(f"❌ Discovery validation failed: {e}")
            raise

    async def _make_request(self, url: str, method: str = 'GET', data: Dict = None, 
                           headers: Dict = None, allow_redirects: bool = True) -> Optional[requests.Response]:
        """Make HTTP request with proper error handling and session management"""
        try:
            request_headers = self.session.headers.copy()
            if headers:
                request_headers.update(headers)
            
            if method.upper() == 'GET':
                response = self.session.get(url, headers=request_headers, 
                                          allow_redirects=allow_redirects, timeout=self.config['timeout'])
            elif method.upper() == 'POST':
                response = self.session.post(url, headers=request_headers, data=data,
                                           allow_redirects=allow_redirects, timeout=self.config['timeout'])
            else:
                response = self.session.request(method, url, headers=request_headers, data=data,
                                              allow_redirects=allow_redirects, timeout=self.config['timeout'])
            
            return response
            
        except Exception as e:
            logger.debug(f"Request failed for {url}: {e}")
            return None

    async def _discover_page(self, url: str, page_type: str = "unknown"):
        """Discover and analyze a single page"""
        if url in self.visited_urls:
            return
        
        try:
            response = await self._make_request(url)
            if not response:
                return
            
            # Parse HTML content
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract page information
            page_data = PageData(
                url=url,
                title=soup.title.string if soup.title else "",
                content_type=response.headers.get('content-type', ''),
                status_code=response.status_code,
                response_size=len(response.content),
                page_type=page_type,
                forms=[],
                links=[],
                scripts=[],
                stylesheets=[],
                images=[],
                requires_auth=False
            )
            
            # Extract forms
            forms = soup.find_all('form')
            for form in forms:
                form_data = self._extract_form_data(form, url)
                if form_data:
                    page_data.forms.append(form_data)
            
            # Extract links
            links = soup.find_all('a', href=True)
            for link in links:
                href = link['href']
                absolute_url = urljoin(url, href)
                if self._is_internal_url(absolute_url, self.discovery_context.target_url):
                    page_data.links.append(absolute_url)
                    self.discovered_urls.add(absolute_url)
            
            # Extract scripts
            scripts = soup.find_all('script', src=True)
            for script in scripts:
                src = script['src']
                absolute_url = urljoin(url, src)
                page_data.scripts.append(absolute_url)
                self.discovery_context.javascript_files.append(absolute_url)
            
            # Extract stylesheets
            stylesheets = soup.find_all('link', rel='stylesheet')
            for stylesheet in stylesheets:
                href = stylesheet.get('href')
                if href:
                    absolute_url = urljoin(url, href)
                    page_data.stylesheets.append(absolute_url)
                    self.discovery_context.css_files.append(absolute_url)
            
            # Extract images
            images = soup.find_all('img', src=True)
            for img in images:
                src = img['src']
                absolute_url = urljoin(url, src)
                page_data.images.append(absolute_url)
                self.discovery_context.image_files.append(absolute_url)
            
            # Add to discovered pages
            self.discovery_context.pages_discovered.append(page_data)
            self.visited_urls.add(url)
            
        except Exception as e:
            logger.debug(f"Failed to discover page {url}: {e}")

    def _extract_form_data(self, form, base_url: str) -> Optional[FormData]:
        """Extract comprehensive form data from HTML form element"""
        try:
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            
            # Resolve action URL
            if action:
                action_url = urljoin(base_url, action)
            else:
                action_url = base_url
            
            # Extract form fields
            parameters = {}
            hidden_fields = {}
            
            for input_field in form.find_all(['input', 'textarea', 'select']):
                field_name = input_field.get('name')
                if not field_name:
                    continue
                
                field_type = input_field.get('type', 'text')
                field_value = input_field.get('value', '')
                required = input_field.get('required') is not None
                
                if field_type == 'hidden':
                    hidden_fields[field_name] = field_value
                else:
                    parameters[field_name] = {
                        'type': field_type,
                        'value': field_value,
                        'required': required,
                        'placeholder': input_field.get('placeholder', ''),
                        'pattern': input_field.get('pattern', ''),
                        'maxlength': input_field.get('maxlength', ''),
                        'minlength': input_field.get('minlength', '')
                    }
            
            return FormData(
                url=base_url,
                method=method,
                action=action_url,
                parameters=parameters,
                hidden_fields=hidden_fields,
                validation_patterns=[],
                form_type="unknown"
            )
            
        except Exception as e:
            logger.debug(f"Failed to extract form data: {e}")
            return None

    def _detect_form_type(self, form: FormData) -> str:
        """Detect the type and purpose of a form"""
        param_names = list(form.parameters.keys())
        param_names_lower = [name.lower() for name in param_names]
        
        # Check for login forms
        if any(pattern in param_names_lower for pattern in self.form_patterns['login']):
            return "login"
        
        # Check for search forms
        if any(pattern in param_names_lower for pattern in self.form_patterns['search']):
            return "search"
        
        # Check for upload forms
        if any(pattern in param_names_lower for pattern in self.form_patterns['upload']):
            return "upload"
        
        # Check for contact forms
        if any(pattern in param_names_lower for pattern in self.form_patterns['contact']):
            return "contact"
        
        # Check for registration forms
        if any(pattern in param_names_lower for pattern in self.form_patterns['registration']):
            return "registration"
        
        return "data_entry"

    async def _recursive_crawl(self, base_url: str, max_depth: int = 3, max_pages: int = 50):
        """Recursively crawl the application to discover all accessible pages"""
        queue = deque([(base_url, 0)])  # (url, depth)
        
        while queue and len(self.visited_urls) < max_pages:
            current_url, depth = queue.popleft()
            
            if depth > max_depth or current_url in self.visited_urls:
                continue
            
            try:
                await self._discover_page(current_url)
                
                # Add discovered links to queue
                for page in self.discovery_context.pages_discovered:
                    if page.url == current_url:
                        for link in page.links:
                            if link not in self.visited_urls:
                                queue.append((link, depth + 1))
                        break
                        
            except Exception as e:
                logger.debug(f"Failed to crawl {current_url}: {e}")

    async def _discover_admin_paths(self, base_url: str):
        """Discover common administrative paths"""
        for admin_path in self.admin_paths:
            admin_url = urljoin(base_url, f"/{admin_path}")
            try:
                response = await self._make_request(admin_url)
                if response and response.status_code in [200, 301, 302, 403]:
                    await self._discover_page(admin_url, "admin")
                    logger.info(f"🔐 Discovered admin path: {admin_url}")
            except Exception as e:
                logger.debug(f"Admin path check failed for {admin_url}: {e}")

    async def _discover_api_endpoints(self, base_url: str):
        """Discover API endpoints"""
        api_paths = ['/api', '/api/v1', '/api/v2', '/rest', '/graphql', '/swagger', '/openapi']
        
        for api_path in api_paths:
            api_url = urljoin(base_url, api_path)
            try:
                response = await self._make_request(api_url)
                if response:
                    api_info = {
                        'url': api_url,
                        'status_code': response.status_code,
                        'content_type': response.headers.get('content-type', ''),
                        'response_size': len(response.content)
                    }
                    self.discovery_context.api_endpoints.append(api_info)
                    logger.info(f"🔗 Discovered API endpoint: {api_url}")
            except Exception as e:
                logger.debug(f"API endpoint check failed for {api_url}: {e}")

    async def _attempt_authentication(self, login_form: FormData):
        """Attempt authentication using provided credentials"""
        if not self.auth_credentials:
            return
        
        try:
            # Prepare login data
            login_data = {}
            for param_name, param_info in login_form.parameters.items():
                param_name_lower = param_name.lower()
                if 'user' in param_name_lower or 'email' in param_name_lower:
                    login_data[param_name] = self.auth_credentials.get('username', 'admin')
                elif 'pass' in param_name_lower:
                    login_data[param_name] = self.auth_credentials.get('password', 'password')
                else:
                    login_data[param_name] = param_info.get('value', '')
            
            # Add hidden fields
            login_data.update(login_form.hidden_fields)
            
            # Attempt login
            response = await self._make_request(login_form.action, method='POST', data=login_data)
            
            if response:
                # Check if login was successful
                if response.status_code == 200 and len(response.content) > 0:
                    # Store session cookies
                    self.session_cookies.update(response.cookies.get_dict())
                    self.discovery_context.session_cookies = self.session_cookies
                    
                    logger.info("✅ Authentication successful")
                    
                    # Update session headers
                    self.session.headers.update({
                        'Cookie': '; '.join([f'{k}={v}' for k, v in self.session_cookies.items()])
                    })
                else:
                    logger.warning("⚠️ Authentication may have failed")
            
        except Exception as e:
            logger.error(f"❌ Authentication attempt failed: {e}")

    async def _discover_authenticated_areas(self):
        """Discover areas that require authentication"""
        if not self.session_cookies:
            return
        
        # Re-crawl discovered URLs with authentication
        for url in list(self.discovered_urls):
            try:
                response = await self._make_request(url)
                if response and response.status_code == 200:
                    # Check if this page shows different content when authenticated
                    await self._discover_page(url, "authenticated")
            except Exception as e:
                logger.debug(f"Authenticated discovery failed for {url}: {e}")

    def _build_site_map(self) -> Dict[str, Any]:
        """Build comprehensive site map from discovered pages"""
        site_map = {
            'pages': {},
            'relationships': {},
            'structure': {}
        }
        
        for page in self.discovery_context.pages_discovered:
            site_map['pages'][page.url] = {
                'title': page.title,
                'type': page.page_type,
                'status_code': page.status_code,
                'forms_count': len(page.forms),
                'links_count': len(page.links),
                'requires_auth': page.requires_auth
            }
            
            # Build relationships
            site_map['relationships'][page.url] = {
                'links_to': page.links,
                'linked_from': []
            }
        
        # Build reverse relationships
        for page_url, relationships in site_map['relationships'].items():
            for linked_url in relationships['links_to']:
                if linked_url in site_map['relationships']:
                    site_map['relationships'][linked_url]['linked_from'].append(page_url)
        
        return site_map

    async def _analyze_ssl_certificate(self, url: str) -> Optional[Dict[str, Any]]:
        """Analyze SSL certificate information"""
        try:
            parsed_url = urlparse(url)
            if parsed_url.scheme != 'https':
                return None
            
            import ssl
            import socket
            
            hostname = parsed_url.netloc
            port = parsed_url.port or 443
            
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'san': cert.get('subjectAltName', [])
                    }
                    
        except Exception as e:
            logger.debug(f"SSL certificate analysis failed: {e}")
            return None

    async def _analyze_sitemap(self, base_url: str):
        """Analyze sitemap.xml if available"""
        sitemap_urls = [
            urljoin(base_url, '/sitemap.xml'),
            urljoin(base_url, '/sitemap_index.xml'),
            urljoin(base_url, '/sitemap1.xml')
        ]
        
        for sitemap_url in sitemap_urls:
            try:
                response = await self._make_request(sitemap_url)
                if response and response.status_code == 200:
                    # Parse sitemap XML
                    soup = BeautifulSoup(response.text, 'xml')
                    urls = soup.find_all('loc')
                    
                    for url_tag in urls:
                        url = url_tag.text.strip()
                        if self._is_internal_url(url, base_url):
                            self.discovery_context.sitemap_urls.append(url)
                            self.discovered_urls.add(url)
                    
                    logger.info(f"📄 Found sitemap with {len(urls)} URLs")
                    break
                    
            except Exception as e:
                logger.debug(f"Sitemap analysis failed for {sitemap_url}: {e}")

    def _is_internal_url(self, url: str, base_url: str) -> bool:
        """Check if URL is internal to the target application"""
        try:
            parsed_url = urlparse(url)
            parsed_base = urlparse(base_url)
            
            return parsed_url.netloc == parsed_base.netloc
        except Exception:
            return False

    async def _save_discovery_context(self):
        """Save discovery context to persistent storage"""
        try:
            # Create discovery data directory
            os.makedirs('discovery_data', exist_ok=True)
            
            # Generate filename based on target and timestamp
            target_hash = hashlib.md5(self.discovery_context.target_url.encode()).hexdigest()[:8]
            timestamp = self.discovery_context.scan_timestamp.strftime('%Y%m%d_%H%M%S')
            filename = f"discovery_data/discovery_{target_hash}_{timestamp}.json"
            
            # Save as JSON
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(asdict(self.discovery_context), f, indent=2, default=str)
            
            logger.info(f"💾 Discovery context saved to {filename}")
            
        except Exception as e:
            logger.error(f"❌ Failed to save discovery context: {e}")

    def _generate_discovery_summary(self) -> Dict[str, Any]:
        """Generate summary of discovery results"""
        return {
            'total_pages': len(self.discovery_context.pages_discovered),
            'total_forms': len(self.discovery_context.forms_discovered),
            'total_input_vectors': len(self.discovery_context.input_vectors),
            'total_api_endpoints': len(self.discovery_context.api_endpoints),
            'authentication_required': bool(self.discovery_context.authentication_system.login_url),
            'technology_stack_identified': bool(self.discovery_context.technology_stack.web_server),
            'discovery_completion_time': time.time() - self.discovery_context.scan_timestamp.timestamp(),
            'urls_discovered': len(self.discovered_urls),
            'pages_analyzed': len(self.visited_urls)
        }

    async def _check_discovery_quality(self):
        """Check the quality and completeness of discovery results"""
        quality_issues = []
        
        # Check for minimum required information
        if len(self.discovery_context.pages_discovered) < 1:
            quality_issues.append("No pages discovered")
        
        if not self.discovery_context.technology_stack.web_server:
            quality_issues.append("Web server not identified")
        
        # Check for authentication analysis
        if not self.discovery_context.authentication_system.login_url:
            logger.info("ℹ️ No authentication system detected - application may be public")
        
        # Log quality issues
        if quality_issues:
            logger.warning(f"⚠️ Discovery quality issues: {', '.join(quality_issues)}")
        else:
            logger.info("✅ Discovery quality check passed")

    # Additional helper methods for technology detection
    async def _detect_technologies_from_headers(self, response: requests.Response):
        """Detect technologies from HTTP response headers"""
        headers = response.headers
        
        # Server detection
        server_header = headers.get('Server', '')
        if server_header:
            for server_name, signatures in self.tech_signatures['web_servers'].items():
                if any(sig in server_header for sig in signatures):
                    self.discovery_context.technology_stack.web_server = server_name
                    break
        
        # Framework detection from headers
        for framework_name, signatures in self.tech_signatures['frameworks'].items():
            for header_name, header_value in headers.items():
                if any(sig in header_value for sig in signatures):
                    self.discovery_context.technology_stack.web_framework = framework_name
                    break

    async def _analyze_page_technologies(self, page: PageData):
        """Analyze technologies from page content"""
        # This would analyze the HTML content for technology signatures
        # Implementation would be similar to header analysis but for page content
        pass

    async def _analyze_javascript_technologies(self):
        """Analyze JavaScript files for framework detection"""
        # This would analyze discovered JavaScript files for framework signatures
        pass

    async def _analyze_css_technologies(self):
        """Analyze CSS files for framework detection"""
        # This would analyze discovered CSS files for framework signatures
        pass

    async def _detect_database_technologies(self):
        """Detect database technologies from error messages and patterns"""
        # This would analyze error pages and responses for database signatures
        pass

    async def _detect_cms(self):
        """Detect content management systems"""
        # This would analyze for CMS signatures
        pass

    async def _analyze_form_validation(self, form: FormData) -> List[str]:
        """Analyze form validation patterns"""
        validation_patterns = []
        
        for param_name, param_info in form.parameters.items():
            if param_info.get('pattern'):
                validation_patterns.append(f"{param_name}: {param_info['pattern']}")
            if param_info.get('maxlength'):
                validation_patterns.append(f"{param_name}: maxlength={param_info['maxlength']}")
            if param_info.get('minlength'):
                validation_patterns.append(f"{param_name}: minlength={param_info['minlength']}")
        
        return validation_patterns

    def _detect_csrf_token(self, form: FormData) -> Optional[str]:
        """Detect CSRF token in form"""
        for field_name, field_value in form.hidden_fields.items():
            if any(token in field_name.lower() for token in ['csrf', 'token', 'xsrf']):
                return field_value
        return None

    def _detect_captcha(self, form: FormData) -> bool:
        """Detect CAPTCHA in form"""
        for param_name in form.parameters.keys():
            if 'captcha' in param_name.lower():
                return True
        return False

    async def _analyze_session_management(self):
        """Analyze session management mechanisms"""
        # This would analyze cookies, session tokens, etc.
        pass

    def get_discovery_context(self) -> Optional[DiscoveryContext]:
        """Get the current discovery context"""
        return self.discovery_context

    def get_forms_by_type(self, form_type: str) -> List[FormData]:
        """Get forms by type"""
        return [f for f in self.discovery_context.forms_discovered if f.form_type == form_type]

    def get_input_vectors_by_type(self, param_type: str) -> List[Dict[str, Any]]:
        """Get input vectors by parameter type"""
        return [iv for iv in self.discovery_context.input_vectors if iv['type'] == param_type]

    def get_api_endpoints(self) -> List[Dict[str, Any]]:
        """Get discovered API endpoints"""
        return self.discovery_context.api_endpoints

    def get_technology_stack(self) -> TechnologyInfo:
        """Get technology stack information"""
        return self.discovery_context.technology_stack

    def get_authentication_info(self) -> AuthenticationInfo:
        """Get authentication system information"""
        return self.discovery_context.authentication_system