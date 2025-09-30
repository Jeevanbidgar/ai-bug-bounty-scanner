"""
Amass adapter - DNS enumeration and subdomain discovery
"""

import json
import re
from typing import Dict, List, Any
from .base_adapter import BaseAdapter, AdapterConfig

class AmassAdapter(BaseAdapter):
    """Adapter for amass tool"""

    def __init__(self):
        super().__init__("amass")

    def get_command(self, target: str, **kwargs) -> List[str]:
        """Get amass command"""
        output_file = kwargs.get('output_file', f'{self.tool_name}_{target.replace("://", "_").replace("/", "_")}.txt')

        command = [
            'amass', 'enum',
            '-d', target,
            '-o', f'/output/{output_file}'
        ]

        # Add optional flags
        if kwargs.get('passive', True):
            command.extend(['-passive'])

        if kwargs.get('brute', False):
            command.extend(['-brute'])

        if kwargs.get('active', False):
            command.extend(['-active'])

        return command

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        """Parse amass output"""
        subdomains = []
        findings = []

        # Parse subdomains from stdout
        for line in stdout.split('\n'):
            line = line.strip()
            if line and not line.startswith('[') and not line.startswith('Using'):
                # Basic domain validation
                if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', line):
                    subdomains.append({
                        'subdomain': line,
                        'source': 'amass',
                        'type': 'passive' if 'passive' in line.lower() else 'active'
                    })

        # Parse JSON output if available (amass can output JSON)
        try:
            # Look for JSON lines in output
            json_pattern = r'\{.*\}'
            json_matches = re.findall(json_pattern, stdout)

            for match in json_matches:
                try:
                    data = json.loads(match)
                    if 'name' in data:
                        findings.append({
                            'type': 'subdomain',
                            'value': data['name'],
                            'source': data.get('source', 'amass'),
                            'confidence': data.get('confidence', 1)
                        })
                except json.JSONDecodeError:
                    continue
        except:
            pass

        return {
            'subdomains_found': len(subdomains),
            'subdomains': subdomains,
            'findings': findings,
            'raw_output': stdout,
            'errors': stderr
        }

    def get_risk_level(self) -> str:
        """Amass can be active, so medium risk"""
        return "medium"
