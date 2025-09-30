"""
Nuclei adapter - Template-based vulnerability scanner
"""

import json
import re
from typing import Dict, List, Any
from .base_adapter import BaseAdapter, AdapterConfig

class NucleiAdapter(BaseAdapter):
    """Adapter for nuclei tool"""

    def __init__(self):
        super().__init__("nuclei")

    def get_command(self, target: str, **kwargs) -> List[str]:
        """Get nuclei command"""
        output_file = kwargs.get('output_file', f'{self.tool_name}_{target.replace("://", "_").replace("/", "_")}.json')

        command = [
            'nuclei',
            '-target', target,
            '-o', f'/output/{output_file}',
            '-json'
        ]

        # Add optional flags
        severity = kwargs.get('severity', 'medium,high,critical')
        if severity:
            command.extend(['-severity', severity])

        if kwargs.get('passive', False):
            command.extend(['-passive'])

        if kwargs.get('templates'):
            templates = kwargs['templates']
            if isinstance(templates, list):
                command.extend(['-t'] + templates)
            else:
                command.extend(['-t', templates])

        return command

    def parse_output(self, stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        """Parse nuclei output"""
        vulnerabilities = []

        try:
            # Parse JSON lines from nuclei output
            for line in stdout.split('\n'):
                line = line.strip()
                if not line:
                    continue

                try:
                    data = json.loads(line)

                    # Extract vulnerability information
                    vuln = {
                        'title': data.get('info', {}).get('name', 'Unknown'),
                        'severity': data.get('info', {}).get('severity', 'unknown').lower(),
                        'description': data.get('info', {}).get('description', ''),
                        'cvss_score': self._extract_cvss(data),
                        'cve': data.get('info', {}).get('classification', {}).get('cve-id', ''),
                        'tags': data.get('info', {}).get('tags', []),
                        'url': data.get('host', ''),
                        'template': data.get('template', ''),
                        'type': data.get('type', 'unknown'),
                        'timestamp': data.get('timestamp', ''),
                        'evidence': {
                            'matched_at': data.get('matched-at', ''),
                            'extracted_results': data.get('extracted-results', []),
                            'request': data.get('request', ''),
                            'response': data.get('response', '')
                        }
                    }

                    # Map severity to standard levels
                    vuln['severity'] = self._normalize_severity(vuln['severity'])

                    vulnerabilities.append(vuln)

                except json.JSONDecodeError:
                    continue

        except Exception as e:
            logger.warning(f"Failed to parse nuclei JSON output: {e}")

        # Fallback: parse plain text output
        if not vulnerabilities:
            vulnerabilities = self._parse_text_output(stdout)

        # Group by severity
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        return {
            'vulnerabilities_found': len(vulnerabilities),
            'vulnerabilities': vulnerabilities,
            'severity_breakdown': severity_counts,
            'raw_output': stdout,
            'errors': stderr
        }

    def _extract_cvss(self, data: Dict) -> float:
        """Extract CVSS score from nuclei data"""
        try:
            # Try different CVSS fields
            cvss_score = (
                data.get('info', {}).get('classification', {}).get('cvss-score', 0) or
                data.get('info', {}).get('severity', {}).get('cvss-score', 0) or
                0
            )
            return float(cvss_score)
        except:
            return 0.0

    def _normalize_severity(self, severity: str) -> str:
        """Normalize nuclei severity to standard levels"""
        severity_map = {
            'info': 'low',
            'low': 'low',
            'medium': 'medium',
            'high': 'high',
            'critical': 'critical'
        }
        return severity_map.get(severity.lower(), 'unknown')

    def _parse_text_output(self, stdout: str) -> List[Dict[str, Any]]:
        """Fallback parser for plain text output"""
        vulnerabilities = []

        # Simple regex patterns for common nuclei output
        patterns = [
            (r'\[([^\]]+)\]\s+([^\n]+)', 'template', 'title'),
            (r'Severity:\s+(\w+)', 'severity'),
            (r'URL:\s+([^\n]+)', 'url'),
        ]

        current_vuln = {}
        for line in stdout.split('\n'):
            line = line.strip()
            if not line:
                if current_vuln:
                    vulnerabilities.append(current_vuln)
                    current_vuln = {}
                continue

            for pattern, key, value_key in patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    if key == 'template':
                        current_vuln['template'] = match.group(1)
                        current_vuln['title'] = match.group(2)
                    elif key == 'severity':
                        current_vuln['severity'] = self._normalize_severity(match.group(1))
                    elif key == 'url':
                        current_vuln['url'] = match.group(1)

        if current_vuln:
            vulnerabilities.append(current_vuln)

        return vulnerabilities

    def get_risk_level(self) -> str:
        """Nuclei can be active, so medium risk"""
        return "medium"
