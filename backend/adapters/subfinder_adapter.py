"""
Subfinder adapter - Fast passive subdomain discovery
"""

import json
import re
from typing import Dict, List, Any
from .base_adapter import BaseAdapter, AdapterConfig

class SubfinderAdapter(BaseAdapter):
    """Adapter for subfinder tool"""

    def __init__(self):
        super().__init__("subfinder")

    def get_command(self, target: str, **kwargs) -> List[str]:
        """Get subfinder command"""
        output_file = kwargs.get('output_file', f'{self.tool_name}_{target.replace("://", "_").replace("/", "_")}.txt')

        command = [
            'subfinder',
            '-d', target,
            '-o', f'/output/{output_file}',
            '-silent'
        ]

        # Add optional flags
        if kwargs.get('passive', True):
            command.extend(['-passive'])

        if kwargs.get('all', False):
            command.extend(['-all'])

        return command

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        """Parse subfinder output"""
        subdomains = []

        # Parse subdomains from stdout
        for line in stdout.split('\n'):
            line = line.strip()
            if line and not line.startswith('[') and not line.startswith('Using') and not line.startswith('Total'):
                # Basic domain validation
                if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', line):
                    subdomains.append({
                        'subdomain': line,
                        'source': 'subfinder',
                        'type': 'passive'
                    })

        return {
            'subdomains_found': len(subdomains),
            'subdomains': subdomains,
            'raw_output': stdout,
            'errors': stderr
        }

    def get_risk_level(self) -> str:
        """Subfinder is passive and low risk"""
        return "low"
