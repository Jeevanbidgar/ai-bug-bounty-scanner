# scanning_agents.py - Enhanced Integrated Security Scanner
"""
Integrated security scanner with external tool support
Combines custom agents with industry-standard security tools
"""

import os
import json
import asyncio
import logging
import subprocess
import tempfile
from typing import Dict, List, Any, Optional
from datetime import datetime
import aiohttp
import xml.etree.ElementTree as ET

# Setup logging
logger = logging.getLogger(__name__)


class IntegratedSecurityScanner:
    """Integrated scanner combining custom agents with external tools"""
    
    def __init__(self):
        self.config = self._load_config()
        self.session = None
        
    def _load_config(self):
        """Load configuration from environment variables"""
        from config import get_config
        config = get_config()
        
        return {
            'shodan_api_key': config.SHODAN_API_KEY,
            'virustotal_api_key': config.VIRUSTOTAL_API_KEY,
            'abuseipdb_api_key': config.ABUSEIPDB_API_KEY,
            'nuclei_path': config.NUCLEI_PATH,
            'sublist3r_path': config.SUBLIST3R_PATH,
            'amass_path': config.AMASS_PATH,
            'sqlmap_path': config.SQLMAP_PATH,
            'burp_jar_path': config.BURP_JAR_PATH,
        }
    
    async def run_comprehensive_scan(self, target: str, tools: List[str], options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Run comprehensive scan using multiple external tools
        
        Args:
            target: Target URL or IP to scan
            tools: List of tools to run
            options: Additional options
            
        Returns:
            Dictionary containing all results
        """
        options = options or {}
        results = {
            'target': target,
            'tools_used': tools,
            'started_at': datetime.now().isoformat(),
            'tool_results': {},
            'summary': {
                'total_vulnerabilities': 0,
                'tools_completed': 0,
                'tools_failed': 0
            }
        }
        
        # Create HTTP session for API calls
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=300)) as session:
            self.session = session
            
            # Run each tool
            for tool in tools:
                try:
                    logger.info(f"Running {tool} scan on {target}")
                    
                    if tool == 'nuclei':
                        tool_result = await self._run_nuclei(target, options)
                    elif tool == 'sublist3r':
                        tool_result = await self._run_sublist3r(target, options)
                    elif tool == 'amass':
                        tool_result = await self._run_amass(target, options)
                    elif tool == 'sqlmap':
                        tool_result = await self._run_sqlmap(target, options)
                    elif tool == 'burp':
                        tool_result = await self._run_burp_cli(target, options)
                    elif tool == 'shodan':
                        tool_result = await self._run_shodan_scan(target, options)
                    elif tool == 'virustotal':
                        tool_result = await self._run_virustotal_scan(target, options)
                    else:
                        logger.warning(f"Unknown tool: {tool}")
                        continue
                    
                    results['tool_results'][tool] = tool_result
                    results['summary']['tools_completed'] += 1
                    results['summary']['total_vulnerabilities'] += len(tool_result.get('vulnerabilities', []))
                    
                except Exception as e:
                    logger.error(f"Error running {tool}: {str(e)}")
                    results['tool_results'][tool] = {
                        'error': str(e),
                        'status': 'failed'
                    }
                    results['summary']['tools_failed'] += 1
        
        results['completed_at'] = datetime.now().isoformat()
        return results
    
    async def _run_nuclei(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Run Nuclei vulnerability scanner"""
        nuclei_path = self.config.get('nuclei_path', 'nuclei')
        
        # Create temporary file for results
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as temp_file:
            temp_path = temp_file.name
        
        try:
            # Build Nuclei command
            cmd = [
                nuclei_path,
                '-target', target,
                '-json',
                '-output', temp_path,
                '-silent'
            ]
            
            # Add template options
            if options.get('templates'):
                cmd.extend(['-t', options['templates']])
            else:
                cmd.extend(['-t', 'cves,vulnerabilities,exposures'])
            
            # Add severity filter
            if options.get('severity'):
                cmd.extend(['-severity', options['severity']])
            
            # Run Nuclei
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            # Parse results
            vulnerabilities = []
            if os.path.exists(temp_path):
                with open(temp_path, 'r') as f:
                    for line in f:
                        if line.strip():
                            try:
                                result = json.loads(line)
                                vuln = self._parse_nuclei_result(result)
                                if vuln:
                                    vulnerabilities.append(vuln)
                            except json.JSONDecodeError:
                                continue
            
            return {
                'tool': 'nuclei',
                'status': 'completed' if process.returncode == 0 else 'failed',
                'vulnerabilities': vulnerabilities,
                'raw_output': stdout.decode() if stdout else '',
                'errors': stderr.decode() if stderr else ''
            }
            
        finally:
            # Clean up temporary file
            if os.path.exists(temp_path):
                os.unlink(temp_path)
    
    async def _run_sublist3r(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Run Sublist3r subdomain enumeration"""
        sublist3r_path = self.config.get('sublist3r_path', 'sublist3r')
        
        # Extract domain from URL if needed
        domain = self._extract_domain(target)
        
        # Create temporary file for results
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.txt', delete=False) as temp_file:
            temp_path = temp_file.name
        
        try:
            # Build command
            cmd = [
                'python',
                sublist3r_path,
                '-d', domain,
                '-o', temp_path
            ]
            
            # Add options
            if options.get('bruteforce'):
                cmd.append('-b')
            
            if options.get('threads'):
                cmd.extend(['-t', str(options['threads'])])
            
            # Run Sublist3r
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            # Parse results
            subdomains = []
            if os.path.exists(temp_path):
                with open(temp_path, 'r') as f:
                    subdomains = [line.strip() for line in f if line.strip()]
            
            return {
                'tool': 'sublist3r',
                'status': 'completed' if process.returncode == 0 else 'failed',
                'subdomains': subdomains,
                'vulnerabilities': self._analyze_subdomains(subdomains),
                'raw_output': stdout.decode() if stdout else '',
                'errors': stderr.decode() if stderr else ''
            }
            
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
    
    async def _run_amass(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Run OWASP Amass for reconnaissance"""
        amass_path = self.config.get('amass_path', 'amass')
        domain = self._extract_domain(target)
        
        try:
            # Build command
            cmd = [amass_path, 'enum', '-d', domain, '-json']
            
            # Add passive mode if specified
            if options.get('passive_only'):
                cmd.append('-passive')
            
            # Run Amass
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            # Parse JSON results
            results = []
            if stdout:
                for line in stdout.decode().split('\n'):
                    if line.strip():
                        try:
                            result = json.loads(line)
                            results.append(result)
                        except json.JSONDecodeError:
                            continue
            
            return {
                'tool': 'amass',
                'status': 'completed' if process.returncode == 0 else 'failed',
                'results': results,
                'vulnerabilities': self._analyze_amass_results(results),
                'errors': stderr.decode() if stderr else ''
            }
            
        except Exception as e:
            return {
                'tool': 'amass',
                'status': 'failed',
                'error': str(e),
                'vulnerabilities': []
            }
    
    async def _run_sqlmap(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Run SQLMap for SQL injection testing"""
        sqlmap_path = self.config.get('sqlmap_path', 'sqlmap')
        
        try:
            # Build command
            cmd = [
                'python',
                sqlmap_path,
                '-u', target,
                '--batch',
                '--smart',
                '--level=2',
                '--risk=2'
            ]
            
            # Add specific options
            if options.get('data'):
                cmd.extend(['--data', options['data']])
            
            if options.get('cookie'):
                cmd.extend(['--cookie', options['cookie']])
            
            if options.get('forms'):
                cmd.append('--forms')
            
            # Run SQLMap
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            # Parse output for vulnerabilities
            output = stdout.decode() if stdout else ''
            vulnerabilities = self._parse_sqlmap_output(output)
            
            return {
                'tool': 'sqlmap',
                'status': 'completed' if process.returncode == 0 else 'failed',
                'vulnerabilities': vulnerabilities,
                'raw_output': output,
                'errors': stderr.decode() if stderr else ''
            }
            
        except Exception as e:
            return {
                'tool': 'sqlmap',
                'status': 'failed',
                'error': str(e),
                'vulnerabilities': []
            }
    
    async def _run_burp_cli(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Run Burp Suite Professional CLI scan"""
        burp_jar = self.config.get('burp_jar_path')
        
        if not burp_jar or not os.path.exists(burp_jar):
            return {
                'tool': 'burp',
                'status': 'skipped',
                'error': 'Burp Suite JAR not found',
                'vulnerabilities': []
            }
        
        try:
            # Create temporary files
            with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as config_file:
                config_path = config_file.name
                # Write Burp scan configuration
                config_file.write(self._create_burp_config(target, options))
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as report_file:
                report_path = report_file.name
            
            # Build command
            cmd = [
                'java', '-jar', burp_jar,
                '--headless',
                '--config-file=' + config_path,
                '--report-output=' + report_path
            ]
            
            # Run Burp Suite
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            # Parse results
            vulnerabilities = []
            if os.path.exists(report_path):
                vulnerabilities = self._parse_burp_report(report_path)
            
            return {
                'tool': 'burp',
                'status': 'completed' if process.returncode == 0 else 'failed',
                'vulnerabilities': vulnerabilities,
                'raw_output': stdout.decode() if stdout else '',
                'errors': stderr.decode() if stderr else ''
            }
            
        finally:
            # Clean up temporary files
            for path in [config_path, report_path]:
                if os.path.exists(path):
                    os.unlink(path)
    
    async def _run_shodan_scan(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Run Shodan intelligence gathering"""
        api_key = self.config.get('shodan_api_key')
        
        if not api_key:
            return {
                'tool': 'shodan',
                'status': 'skipped',
                'error': 'Shodan API key not configured',
                'vulnerabilities': []
            }
        
        try:
            # Extract IP or domain
            host = self._extract_host(target)
            
            # Query Shodan API
            url = f"https://api.shodan.io/shodan/host/{host}?key={api_key}"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    vulnerabilities = self._analyze_shodan_data(data)
                    
                    return {
                        'tool': 'shodan',
                        'status': 'completed',
                        'vulnerabilities': vulnerabilities,
                        'raw_data': data
                    }
                else:
                    return {
                        'tool': 'shodan',
                        'status': 'failed',
                        'error': f"API returned status {response.status}",
                        'vulnerabilities': []
                    }
                    
        except Exception as e:
            return {
                'tool': 'shodan',
                'status': 'failed',
                'error': str(e),
                'vulnerabilities': []
            }
    
    async def _run_virustotal_scan(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Run VirusTotal URL/domain analysis"""
        api_key = self.config.get('virustotal_api_key')
        
        if not api_key:
            return {
                'tool': 'virustotal',
                'status': 'skipped',
                'error': 'VirusTotal API key not configured',
                'vulnerabilities': []
            }
        
        try:
            # Query VirusTotal API
            headers = {'x-apikey': api_key}
            domain = self._extract_domain(target)
            
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    vulnerabilities = self._analyze_virustotal_data(data)
                    
                    return {
                        'tool': 'virustotal',
                        'status': 'completed',
                        'vulnerabilities': vulnerabilities,
                        'raw_data': data
                    }
                else:
                    return {
                        'tool': 'virustotal',
                        'status': 'failed',
                        'error': f"API returned status {response.status}",
                        'vulnerabilities': []
                    }
                    
        except Exception as e:
            return {
                'tool': 'virustotal',
                'status': 'failed',
                'error': str(e),
                'vulnerabilities': []
            }
    
    # Helper methods for parsing results
    
    def _parse_nuclei_result(self, result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse Nuclei JSON result into vulnerability format"""
        try:
            return {
                'title': result.get('info', {}).get('name', 'Nuclei Detection'),
                'description': result.get('info', {}).get('description', ''),
                'severity': result.get('info', {}).get('severity', 'info'),
                'type': 'nuclei_template',
                'url': result.get('matched-at', ''),
                'payload': result.get('request', ''),
                'evidence': {
                    'template_id': result.get('template-id'),
                    'matcher_name': result.get('matcher-name'),
                    'extracted_results': result.get('extracted-results', [])
                },
                'recommendation': 'Review the detected issue and apply appropriate fixes',
                'cve_id': result.get('info', {}).get('classification', {}).get('cve-id')
            }
        except Exception:
            return None
    
    def _analyze_subdomains(self, subdomains: List[str]) -> List[Dict[str, Any]]:
        """Analyze subdomain enumeration results for potential vulnerabilities"""
        vulnerabilities = []
        
        # Look for potentially interesting subdomains
        interesting_patterns = [
            'admin', 'test', 'dev', 'staging', 'api', 'ftp',
            'mail', 'vpn', 'backup', 'db', 'database'
        ]
        
        for subdomain in subdomains:
            for pattern in interesting_patterns:
                if pattern in subdomain.lower():
                    vulnerabilities.append({
                        'title': f'Potentially Sensitive Subdomain: {subdomain}',
                        'description': f'Subdomain "{subdomain}" may contain sensitive information or services',
                        'severity': 'info',
                        'type': 'information_disclosure',
                        'url': f'http://{subdomain}',
                        'payload': '',
                        'evidence': {'subdomain': subdomain, 'pattern': pattern},
                        'recommendation': 'Review the subdomain for sensitive information exposure'
                    })
                    break
        
        return vulnerabilities
    
    def _analyze_amass_results(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze Amass results for vulnerabilities"""
        vulnerabilities = []
        
        for result in results:
            # Look for exposed services or interesting findings
            if result.get('addresses'):
                vulnerabilities.append({
                    'title': f'Domain Resolution: {result.get("name")}',
                    'description': f'Domain resolves to: {", ".join(result["addresses"])}',
                    'severity': 'info',
                    'type': 'information_disclosure',
                    'url': result.get('name'),
                    'payload': '',
                    'evidence': result,
                    'recommendation': 'Verify that all resolved addresses are authorized'
                })
        
        return vulnerabilities
    
    def _parse_sqlmap_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse SQLMap output for SQL injection vulnerabilities"""
        vulnerabilities = []
        
        # Look for injection indicators in output
        if 'parameter' in output.lower() and 'injectable' in output.lower():
            # Extract parameter name if possible
            lines = output.split('\n')
            for line in lines:
                if 'parameter' in line.lower() and 'injectable' in line.lower():
                    vulnerabilities.append({
                        'title': 'SQL Injection Vulnerability',
                        'description': 'SQLMap detected a potential SQL injection vulnerability',
                        'severity': 'high',
                        'type': 'sql_injection',
                        'url': '',
                        'payload': line.strip(),
                        'evidence': {'sqlmap_output': output},
                        'recommendation': 'Implement proper input validation and parameterized queries',
                        'cwe_id': 'CWE-89'
                    })
                    break
        
        return vulnerabilities
    
    def _create_burp_config(self, target: str, options: Dict[str, Any]) -> str:
        """Create Burp Suite scan configuration"""
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<config>
    <target>
        <url>{target}</url>
    </target>
    <scanConfig>
        <crawl>true</crawl>
        <audit>true</audit>
    </scanConfig>
</config>"""
    
    def _parse_burp_report(self, report_path: str) -> List[Dict[str, Any]]:
        """Parse Burp Suite XML report"""
        vulnerabilities = []
        
        try:
            tree = ET.parse(report_path)
            root = tree.getroot()
            
            for issue in root.findall('.//issue'):
                vuln = {
                    'title': issue.find('name').text if issue.find('name') is not None else 'Burp Finding',
                    'description': issue.find('issueDetail').text if issue.find('issueDetail') is not None else '',
                    'severity': self._map_burp_severity(issue.find('severity').text if issue.find('severity') is not None else 'Low'),
                    'type': 'burp_finding',
                    'url': issue.find('url').text if issue.find('url') is not None else '',
                    'payload': '',
                    'evidence': {
                        'confidence': issue.find('confidence').text if issue.find('confidence') is not None else '',
                        'issue_background': issue.find('issueBackground').text if issue.find('issueBackground') is not None else ''
                    },
                    'recommendation': issue.find('remediationDetail').text if issue.find('remediationDetail') is not None else ''
                }
                vulnerabilities.append(vuln)
                
        except Exception as e:
            logger.error(f"Error parsing Burp report: {str(e)}")
        
        return vulnerabilities
    
    def _analyze_shodan_data(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze Shodan data for vulnerabilities"""
        vulnerabilities = []
        
        # Check for known vulnerabilities
        if 'vulns' in data:
            for cve in data['vulns']:
                vulnerabilities.append({
                    'title': f'Known Vulnerability: {cve}',
                    'description': f'Shodan detected vulnerability {cve} on this host',
                    'severity': 'high',
                    'type': 'known_vulnerability',
                    'url': '',
                    'payload': '',
                    'evidence': data['vulns'][cve],
                    'recommendation': f'Apply security patches for {cve}',
                    'cve_id': cve
                })
        
        # Check for exposed services
        for service in data.get('data', []):
            port = service.get('port')
            product = service.get('product', '')
            
            if port in [21, 23, 135, 139, 445, 1433, 3389]:  # Commonly attacked ports
                vulnerabilities.append({
                    'title': f'Exposed Service on Port {port}',
                    'description': f'Service "{product}" is exposed on port {port}',
                    'severity': 'medium',
                    'type': 'exposed_service',
                    'url': f'{data.get("ip_str")}:{port}',
                    'payload': '',
                    'evidence': service,
                    'recommendation': 'Review if this service needs to be publicly accessible'
                })
        
        return vulnerabilities
    
    def _analyze_virustotal_data(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze VirusTotal data for threats"""
        vulnerabilities = []
        
        attributes = data.get('data', {}).get('attributes', {})
        
        # Check reputation
        reputation = attributes.get('reputation', 0)
        if reputation < -10:
            vulnerabilities.append({
                'title': 'Poor Domain Reputation',
                'description': f'Domain has poor reputation score: {reputation}',
                'severity': 'medium',
                'type': 'reputation',
                'url': '',
                'payload': '',
                'evidence': {'reputation': reputation},
                'recommendation': 'Investigate domain reputation and potential compromise'
            })
        
        # Check for malicious detections
        last_analysis = attributes.get('last_analysis_stats', {})
        malicious = last_analysis.get('malicious', 0)
        
        if malicious > 0:
            vulnerabilities.append({
                'title': 'Malicious Domain Detection',
                'description': f'Domain flagged as malicious by {malicious} security vendors',
                'severity': 'high',
                'type': 'malware',
                'url': '',
                'payload': '',
                'evidence': last_analysis,
                'recommendation': 'Domain may be compromised or hosting malware'
            })
        
        return vulnerabilities
    
    # Utility methods
    
    def _extract_domain(self, target: str) -> str:
        """Extract domain from URL or return as-is if already a domain"""
        if target.startswith(('http://', 'https://')):
            from urllib.parse import urlparse
            return urlparse(target).netloc
        return target
    
    def _extract_host(self, target: str) -> str:
        """Extract host (IP or domain) from target"""
        domain = self._extract_domain(target)
        return domain.split(':')[0]  # Remove port if present
    
    def _map_burp_severity(self, burp_severity: str) -> str:
        """Map Burp Suite severity to our severity levels"""
        mapping = {
            'High': 'high',
            'Medium': 'medium',
            'Low': 'low',
            'Information': 'info'
        }
        return mapping.get(burp_severity, 'info')
