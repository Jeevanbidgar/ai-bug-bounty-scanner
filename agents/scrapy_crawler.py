"""
Scrapy Web Crawler Integration for Web App Agent
Provides advanced web crawling capabilities with form discovery and URL extraction
"""

import scrapy
import logging
import os
import json
import tempfile
import subprocess
import asyncio
from urllib.parse import urlparse, urljoin, parse_qs
from typing import Dict, List, Any, Set
from scrapy.crawler import CrawlerProcess
from scrapy.utils.project import get_project_settings
from scrapy.utils.log import configure_logging
from multiprocessing import Process, Queue
import time

logger = logging.getLogger(__name__)

class WebAppCrawlerSpider(scrapy.Spider):
    """Enhanced spider for web application crawling with form and parameter discovery"""
    
    name = "webapp_crawler"
    
    def __init__(self, target_url=None, max_pages=50, max_depth=3, *args, **kwargs):
        super(WebAppCrawlerSpider, self).__init__(*args, **kwargs)
        self.start_urls = [target_url] if target_url else []
        self.target_domain = urlparse(target_url).netloc if target_url else ""
        self.allowed_domains = [self.target_domain]
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.pages_crawled = 0
        self.crawl_results = {
            'urls': [],
            'forms': [],
            'parameters': [],
            'endpoints': [],
            'pages_crawled': 0
        }
        
        # Custom settings for respectful crawling
        self.custom_settings = {
            'DOWNLOAD_DELAY': 0.5,
            'RANDOMIZE_DOWNLOAD_DELAY': 0.5,
            'CONCURRENT_REQUESTS': 2,
            'CONCURRENT_REQUESTS_PER_DOMAIN': 2,
            'ROBOTSTXT_OBEY': True,
            'USER_AGENT': 'AI Bug Bounty Scanner/1.0 (Security Testing)',
            'DEPTH_LIMIT': max_depth,
            'CLOSESPIDER_PAGECOUNT': max_pages,
        }

    def parse(self, response):
        """Parse response and extract URLs, forms, and parameters"""
        if self.pages_crawled >= self.max_pages:
            return
            
        self.pages_crawled += 1
        current_url = response.url
        
        # Store the URL
        self.crawl_results['urls'].append(current_url)
        
        # Extract forms
        forms = response.css('form')
        for form in forms:
            form_data = self._extract_form_data(form, current_url)
            if form_data:
                self.crawl_results['forms'].append(form_data)
        
        # Extract parameters from current URL
        parsed_url = urlparse(current_url)
        if parsed_url.query:
            params = parse_qs(parsed_url.query)
            for param_name, param_values in params.items():
                param_data = {
                    'url': current_url,
                    'parameter': param_name,
                    'values': param_values,
                    'method': 'GET'
                }
                self.crawl_results['parameters'].append(param_data)
        
        # Extract API-like endpoints
        self._extract_api_endpoints(response)
        
        # Follow internal links
        links = response.css('a::attr(href)').getall()
        for link in links:
            if link:
                full_url = urljoin(current_url, link)
                if self._is_internal_url(full_url) and self.pages_crawled < self.max_pages:
                    yield scrapy.Request(
                        full_url, 
                        callback=self.parse,
                        dont_filter=False,
                        meta={'depth': response.meta.get('depth', 0) + 1}
                    )

    def _extract_form_data(self, form_selector, current_url):
        """Extract form data including action, method, and inputs"""
        try:
            action = form_selector.css('::attr(action)').get() or current_url
            method = form_selector.css('::attr(method)').get() or 'GET'
            full_action = urljoin(current_url, action)
            
            inputs = []
            for input_elem in form_selector.css('input, textarea, select'):
                input_data = {
                    'name': input_elem.css('::attr(name)').get(),
                    'type': input_elem.css('::attr(type)').get() or 'text',
                    'value': input_elem.css('::attr(value)').get() or '',
                    'required': input_elem.css('::attr(required)').get() is not None
                }
                if input_data['name']:
                    inputs.append(input_data)
            
            return {
                'url': current_url,
                'action': full_action,
                'method': method.upper(),
                'inputs': inputs,
                'input_count': len(inputs)
            }
        except Exception as e:
            logger.warning(f"Error extracting form data: {e}")
            return None

    def _extract_api_endpoints(self, response):
        """Extract potential API endpoints from JavaScript and HTML"""
        try:
            # Look for API patterns in scripts
            scripts = response.css('script::text').getall()
            for script in scripts:
                if script:
                    # Look for common API patterns
                    api_patterns = [
                        r'/api/[^\s\'"`]+',
                        r'/v\d+/[^\s\'"`]+',
                        r'\.json[^\s\'"`]*',
                        r'/rest/[^\s\'"`]+',
                        r'/graphql[^\s\'"`]*'
                    ]
                    
                    import re
                    for pattern in api_patterns:
                        matches = re.findall(pattern, script)
                        for match in matches:
                            full_endpoint = urljoin(response.url, match)
                            if self._is_internal_url(full_endpoint):
                                self.crawl_results['endpoints'].append({
                                    'url': full_endpoint,
                                    'type': 'api',
                                    'found_in': response.url
                                })
        except Exception as e:
            logger.warning(f"Error extracting API endpoints: {e}")

    def _is_internal_url(self, url):
        """Check if URL belongs to target domain"""
        try:
            parsed = urlparse(url)
            return parsed.netloc == self.target_domain or parsed.netloc == ""
        except:
            return False

    def closed(self, reason):
        """Called when spider is closed"""
        self.crawl_results['pages_crawled'] = self.pages_crawled
        logger.info(f"Spider closed: {reason}. Crawled {self.pages_crawled} pages.")


class ScrapyCrawlerIntegration:
    """Integration class for using Scrapy with the Web App Agent"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
    async def crawl_website(self, target_url: str, max_pages: int = 50, max_depth: int = 3) -> Dict[str, Any]:
        """
        Crawl website using Scrapy and return comprehensive results
        
        Args:
            target_url: Target URL to crawl
            max_pages: Maximum pages to crawl
            max_depth: Maximum depth to crawl
            
        Returns:
            Dict containing crawled URLs, forms, parameters, and endpoints
        """
        try:
            self.logger.info(f"🕷️ Starting Scrapy crawl of {target_url}")
            
            # Create a temporary file to store results
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
                temp_filename = temp_file.name
            
            # Run Scrapy in a separate process to avoid reactor conflicts
            crawler_process = Process(
                target=self._run_scrapy_crawler,
                args=(target_url, max_pages, max_depth, temp_filename)
            )
            crawler_process.start()
            crawler_process.join(timeout=300)  # 5 minute timeout
            
            if crawler_process.is_alive():
                crawler_process.terminate()
                self.logger.warning("Scrapy crawler timed out")
                return self._get_empty_results()
            
            # Read results from temporary file
            try:
                with open(temp_filename, 'r') as f:
                    results = json.load(f)
                os.unlink(temp_filename)  # Clean up temp file
                
                self.logger.info(f"✅ Scrapy crawl completed: {len(results.get('urls', []))} URLs found")
                return results
                
            except (FileNotFoundError, json.JSONDecodeError) as e:
                self.logger.error(f"Failed to read crawler results: {e}")
                return self._get_empty_results()
                
        except Exception as e:
            self.logger.error(f"Scrapy crawling error: {e}")
            return self._get_empty_results()
    
    def _run_scrapy_crawler(self, target_url: str, max_pages: int, max_depth: int, output_file: str):
        """Run Scrapy crawler in separate process"""
        try:
            # Configure Scrapy logging to be less verbose
            configure_logging({'LOG_LEVEL': 'WARNING'})
            
            # Create crawler process
            process = CrawlerProcess({
                'LOG_LEVEL': 'WARNING',
                'USER_AGENT': 'AI Bug Bounty Scanner/1.0 (Security Testing)',
                'ROBOTSTXT_OBEY': True,
                'DOWNLOAD_DELAY': 0.5,
                'CONCURRENT_REQUESTS': 2,
                'DEPTH_LIMIT': max_depth,
                'CLOSESPIDER_PAGECOUNT': max_pages,
            })
            
            # Create spider instance
            spider = WebAppCrawlerSpider(
                target_url=target_url,
                max_pages=max_pages,
                max_depth=max_depth
            )
            
            # Add spider to process
            process.crawl(spider)
            
            # Start crawling
            process.start()
            
            # Save results to file
            with open(output_file, 'w') as f:
                json.dump(spider.crawl_results, f, indent=2)
                
        except Exception as e:
            # Save error result
            error_result = self._get_empty_results()
            error_result['error'] = str(e)
            with open(output_file, 'w') as f:
                json.dump(error_result, f, indent=2)
    
    def _get_empty_results(self) -> Dict[str, Any]:
        """Return empty results structure"""
        return {
            'urls': [],
            'forms': [],
            'parameters': [],
            'endpoints': [],
            'pages_crawled': 0,
            'error': None
        }
    
    def get_testable_urls(self, crawl_results: Dict[str, Any]) -> List[str]:
        """
        Extract URLs suitable for SQLMap testing
        
        Args:
            crawl_results: Results from crawl_website
            
        Returns:
            List of URLs with parameters or forms suitable for testing
        """
        testable_urls = []
        
        # Add URLs with GET parameters
        for param_data in crawl_results.get('parameters', []):
            if param_data.get('method') == 'GET' and param_data.get('url'):
                testable_urls.append(param_data['url'])
        
        # Add form action URLs
        for form_data in crawl_results.get('forms', []):
            if form_data.get('action') and form_data.get('inputs'):
                testable_urls.append(form_data['action'])
        
        # Add API endpoints
        for endpoint_data in crawl_results.get('endpoints', []):
            if endpoint_data.get('url'):
                testable_urls.append(endpoint_data['url'])
        
        # Remove duplicates and return
        return list(set(testable_urls))
