"""
Naabu adapter - Fast port scanner
"""

import json
import re
from typing import Dict, List, Any
from .base_adapter import BaseAdapter, AdapterConfig

class NaabuAdapter(BaseAdapter):
    """Adapter for naabu tool"""

    def __init__(self):
        super().__init__("naabu")

    def get_command(self, target: str, **kwargs) -> List[str]:
        """Get naabu command"""
        output_file = kwargs.get('output_file', f'{self.tool_name}_{target.replace("://", "_").replace("/", "_")}.txt')

        command = [
            'naabu',
            '-host', target,
            '-o', f'/output/{output_file}'
        ]

        # Add optional flags
        if kwargs.get('ports'):
            ports = kwargs['ports']
            if isinstance(ports, list):
                command.extend(['-p'] + [','.join(ports)])
            else:
                command.extend(['-p', ports])

        if kwargs.get('rate'):
            command.extend(['-rate', str(kwargs['rate'])])

        if kwargs.get('passive', False):
            command.extend(['-passive'])

        if kwargs.get('verbose', False):
            command.append('-v')

        return command

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        """Parse naabu output"""
        open_ports = []

        # Parse port information from stdout
        for line in stdout.split('\n'):
            line = line.strip()
            if not line:
                continue

            # Naabu output format: host:port
            if ':' in line:
                try:
                    host_port = line.split(':')
                    if len(host_port) == 2:
                        host, port_str = host_port
                        port = int(port_str)

                        port_info = {
                            'host': host,
                            'port': port,
                            'protocol': 'tcp',  # Naabu defaults to TCP
                            'state': 'open',
                            'service': self._get_common_service(port),
                            'source': 'naabu'
                        }

                        open_ports.append(port_info)

                except (ValueError, IndexError):
                    continue

        # Group by host
        hosts = {}
        for port_info in open_ports:
            host = port_info['host']
            if host not in hosts:
                hosts[host] = {
                    'host': host,
                    'ports': [],
                    'total_ports': 0
                }
            hosts[host]['ports'].append(port_info)
            hosts[host]['total_ports'] += 1

        return {
            'open_ports_found': len(open_ports),
            'hosts_scanned': len(hosts),
            'open_ports': open_ports,
            'hosts': list(hosts.values()),
            'raw_output': stdout,
            'errors': stderr
        }

    def _get_common_service(self, port: int) -> str:
        """Get common service name for a port"""
        common_ports = {
            20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet',
            25: 'smtp', 53: 'dns', 80: 'http', 110: 'pop3',
            143: 'imap', 443: 'https', 993: 'imaps', 995: 'pop3s',
            1433: 'mssql', 1521: 'oracle', 3306: 'mysql', 3389: 'rdp',
            5432: 'postgresql', 5984: 'couchdb', 8080: 'http-alt',
            9200: 'elasticsearch', 27017: 'mongodb'
        }
        return common_ports.get(port, 'unknown')

    def get_risk_level(self) -> str:
        """Naabu is active scanning, so medium risk"""
        return "medium"

    def requires_authorization(self) -> bool:
        """Naabu requires authorization for active scanning"""
        return True
