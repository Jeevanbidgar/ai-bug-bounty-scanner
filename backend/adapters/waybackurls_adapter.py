"""
WaybackURLs adapter - Archive URL harvesting
"""

import json
import re
from typing import Dict, List, Any
from urllib.parse import urlparse
from .base_adapter import BaseAdapter, AdapterConfig

class WaybackURLsAdapter(BaseAdapter):
    """Adapter for waybackurls tool"""

    def __init__(self):
        super().__init__("waybackurls")

    def get_command(self, target: str, **kwargs) -> List[str]:
        """Get waybackurls command"""
        output_file = kwargs.get('output_file', f'{self.tool_name}_{target.replace("://", "_").replace("/", "_")}.txt')

        command = [
            'waybackurls',
            target
        ]

        # Redirect output to file
        command.extend(['>', f'/output/{output_file}'])

        return ['sh', '-c', ' '.join(command)]

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        """Parse waybackurls output"""
        urls = []
        unique_urls = set()

        # Parse URLs from stdout (waybackurls outputs to stdout)
        for line in stdout.split('\n'):
            line = line.strip()
            if line and self._is_valid_url(line):
                # Get domain from target for filtering
                parsed_target = urlparse(line)
                if parsed_target.netloc:
                    unique_urls.add(line)

        # Convert to list and validate
        for url in unique_urls:
            parsed = urlparse(url)

            # Categorize URL types
            url_info = {
                'url': url,
                'domain': parsed.netloc,
                'path': parsed.path,
                'type': self._categorize_url(url),
                'has_parameters': bool(parsed.query),
                'source': 'waybackurls',
                'timestamp': None  # Wayback doesn't provide timestamps in basic output
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
        if '/api/' in path or path.endswith('.json') or path.endswith('.xml'):
            return 'api'

        # Admin/login areas
        if any(admin_path in path for admin_path in ['/admin', '/login', '/auth', '/dashboard']):
            return 'admin'

        # File downloads
        if any(ext in path for ext in ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip', '.tar', '.gz']):
            return 'file'

        # JavaScript/CSS
        if path.endswith('.js') or path.endswith('.css'):
            return 'static'

        # Default to web page
        return 'web'

    def get_risk_level(self) -> str:
        """WaybackURLs is passive and very low risk"""
        return "low"
