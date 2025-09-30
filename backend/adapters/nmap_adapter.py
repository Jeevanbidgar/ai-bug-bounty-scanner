"""
Nmap adapter - Deep port and service discovery
"""

import json
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Any
from .base_adapter import BaseAdapter, AdapterConfig

class NmapAdapter(BaseAdapter):
    """Adapter for nmap tool"""

    def __init__(self):
        super().__init__("nmap")

    def get_command(self, target: str, **kwargs) -> List[str]:
        """Get nmap command"""
        output_file = kwargs.get('output_file', f'{self.tool_name}_{target.replace("://", "_").replace("/", "_")}.txt')
        xml_output_file = kwargs.get('xml_output_file', f'{self.tool_name}_{target.replace("://", "_").replace("/", "_")}.xml')

        command = [
            'nmap',
            '-oN', f'/output/{output_file}',
            '-oX', f'/output/{xml_output_file}'
        ]

        # Add scan options
        if kwargs.get('service_scan', True):
            command.append('-sV')

        if kwargs.get('script_scan', True):
            command.append('-sC')

        if kwargs.get('os_detection', False):
            command.append('-O')

        if kwargs.get('ports'):
            ports = kwargs['ports']
            if isinstance(ports, list):
                command.extend(['-p'] + [','.join(ports)])
            else:
                command.extend(['-p', ports])

        # Add target
        command.append(target)

        return command

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        """Parse nmap output"""
        hosts = []
        open_ports = []

        try:
            # Try to parse XML output first (more reliable)
            xml_file = None
            for artifact in self.config.volumes.get('/output', {}).values():
                if artifact.endswith('.xml'):
                    xml_file = artifact
                    break

            if xml_file:
                hosts, open_ports = self._parse_xml_output(xml_file)

        except Exception as e:
            logger.warning(f"Failed to parse XML output: {e}")

        # Fallback to text parsing
        if not hosts:
            hosts, open_ports = self._parse_text_output(stdout)

        # Calculate statistics
        total_hosts = len(hosts)
        total_ports = len(open_ports)

        return {
            'hosts_found': total_hosts,
            'open_ports_found': total_ports,
            'hosts': hosts,
            'open_ports': open_ports,
            'raw_output': stdout,
            'errors': stderr
        }

    def _parse_xml_output(self, xml_file: str) -> tuple[List[Dict], List[Dict]]:
        """Parse nmap XML output"""
        hosts = []
        open_ports = []

        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            for host in root.findall('host'):
                host_info = {
                    'address': '',
                    'status': 'unknown',
                    'ports': [],
                    'os': '',
                    'hostname': ''
                }

                # Get address
                addr_elem = host.find('address')
                if addr_elem is not None:
                    host_info['address'] = addr_elem.get('addr', '')

                # Get status
                status_elem = host.find('status')
                if status_elem is not None:
                    host_info['status'] = status_elem.get('state', 'unknown')

                # Get hostname
                hostname_elem = host.find('hostnames/hostname')
                if hostname_elem is not None:
                    host_info['hostname'] = hostname_elem.get('name', '')

                # Get OS info
                os_elem = host.find('os/osmatch')
                if os_elem is not None:
                    host_info['os'] = os_elem.get('name', '')

                # Get ports
                for port_elem in host.find_all('port'):
                    port_info = {
                        'port': int(port_elem.get('portid', 0)),
                        'protocol': port_elem.get('protocol', ''),
                        'state': 'unknown',
                        'service': '',
                        'version': ''
                    }

                    state_elem = port_elem.find('state')
                    if state_elem is not None:
                        port_info['state'] = state_elem.get('state', 'unknown')

                    service_elem = port_elem.find('service')
                    if service_elem is not None:
                        port_info['service'] = service_elem.get('name', '')
                        port_info['version'] = service_elem.get('version', '')

                    host_info['ports'].append(port_info)

                    # Add to global open ports list
                    if port_info['state'] == 'open':
                        open_ports.append({
                            'host': host_info['address'],
                            'port': port_info['port'],
                            'protocol': port_info['protocol'],
                            'service': port_info['service'],
                            'version': port_info['version'],
                            'source': 'nmap'
                        })

                hosts.append(host_info)

        except Exception as e:
            logger.error(f"Failed to parse nmap XML: {e}")

        return hosts, open_ports

    def _parse_text_output(self, stdout: str) -> tuple[List[Dict], List[Dict]]:
        """Parse nmap text output (fallback)"""
        hosts = []
        open_ports = []

        # Simple regex patterns for text parsing
        host_pattern = r'Host:\s+([^\s]+)\s+\(([^\)]+)\)\s+Status:\s+(\w+)'
        port_pattern = r'(\d+)/(\w+)\s+(\w+)\s+([^\s]+)'

        current_host = None
        for line in stdout.split('\n'):
            line = line.strip()

            # Match host line
            host_match = re.search(host_pattern, line)
            if host_match:
                if current_host:
                    hosts.append(current_host)

                current_host = {
                    'address': host_match.group(2),  # IP in parentheses
                    'hostname': host_match.group(1),  # Hostname
                    'status': host_match.group(3),    # Status
                    'ports': []
                }
                continue

            # Match port line
            port_match = re.search(port_pattern, line)
            if port_match and current_host:
                port_num, protocol, state, service = port_match.groups()

                port_info = {
                    'port': int(port_num),
                    'protocol': protocol,
                    'state': state,
                    'service': service
                }

                current_host['ports'].append(port_info)

                # Add to global open ports if open
                if state == 'open':
                    open_ports.append({
                        'host': current_host['address'],
                        'port': int(port_num),
                        'protocol': protocol,
                        'service': service,
                        'source': 'nmap'
                    })

        if current_host:
            hosts.append(current_host)

        return hosts, open_ports

    def get_risk_level(self) -> str:
        """Nmap is active scanning, so high risk"""
        return "high"

    def requires_authorization(self) -> bool:
        """Nmap requires authorization for active scanning"""
        return True
