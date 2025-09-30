"""
GAU (GetAllURLs) adapter - Aggregated URL discovery from Common Crawl
"""

import json
import re
from typing import Dict, List, Any
from urllib.parse import urlparse
from .base_adapter import BaseAdapter, AdapterConfig

class GAUAdapter(BaseAdapter):
    """Adapter for gau (getallurls) tool"""

    def __init__(self):
        super().__init__("gau")

    def get_command(self, target: str, **kwargs) -> List[str]:
        """Get gau command"""
        output_file = kwargs.get('output_file', f'{self.tool_name}_{target.replace("://", "_").replace("/", "_")}.txt')

        command = [
            'gau',
            target,
            '--o', f'/output/{output_file}'
        ]

        # Add optional flags
        if kwargs.get('threads'):
            command.extend(['--threads', str(kwargs['threads'])])

        if kwargs.get('verbose', False):
            command.append('--verbose')

        return command

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        """Parse gau output"""
        urls = []
        unique_urls = set()

        # Parse URLs from stdout
        for line in stdout.split('\n'):
            line = line.strip()
            if line and self._is_valid_url(line):
                unique_urls.add(line)

        # Process unique URLs
        for url in unique_urls:
            parsed = urlparse(url)

            url_info = {
                'url': url,
                'domain': parsed.netloc,
                'path': parsed.path,
                'type': self._categorize_url(url),
                'has_parameters': bool(parsed.query),
                'source': 'gau',
                'common_crawl': True,  # GAU uses Common Crawl data
                'parameters': dict(param.split('=') for param in parsed.query.split('&') if '=' in param) if parsed.query else {}
            }

            urls.append(url_info)

        return {
            'urls_found': len(urls),
            'unique_domains': len(set(url_info['domain'] for url_info in urls)),
            'urls': urls,
            'raw_output': stdout,
            'errors': stderr
        }

    def _is_valid_url(self, url: str) -> bool:
        """Validate if string is a valid URL"""
        try:
            parsed = urlparse(url)
            return bool(parsed.scheme and parsed.netloc)
        except:
            return False

    def _categorize_url(self, url: str) -> str:
        """Categorize URL type"""
        parsed = urlparse(url)
        path = parsed.path.lower()

        # API endpoints
        if '/api/' in path or path.endswith(('.json', '.xml', '.txt')):
            return 'api'

        # Admin areas
        if any(admin_path in path for admin_path in ['/admin', '/wp-admin', '/login', '/auth']):
            return 'admin'

        # File downloads
        if any(ext in path for ext in ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip', '.tar', '.gz', '.jpg', '.png', '.gif']):
            return 'file'

        # JavaScript/CSS
        if path.endswith(('.js', '.css', '.ico')):
            return 'static'

        # Default to web page
        return 'web'

    def get_risk_level(self) -> str:
        """GAU is passive and very low risk"""
        return "low"
