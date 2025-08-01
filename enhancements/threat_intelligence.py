# Threat Intelligence Integration Module
"""
Real-time threat intelligence integration for enhanced vulnerability detection
"""

import requests
import asyncio
import aiohttp
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging
import hashlib
import os

class ThreatIntelligenceAgent:
    """Threat intelligence integration for real-time security updates"""
    
    def __init__(self):
        self.threat_feeds = {
            'cve_database': 'https://cve.circl.lu/api/last/30',  # Free CVE API
            'malware_domains': 'https://urlhaus-api.abuse.ch/v1/urls/recent/',
            'ip_reputation': 'https://api.abuseipdb.com/api/v2/check',
            'shodan_api': 'https://api.shodan.io/shodan/host/search',
            'virustotal_domain': 'https://www.virustotal.com/vtapi/v2/domain/report',
            'virustotal_url': 'https://www.virustotal.com/vtapi/v2/url/report'
        }
        
        self.api_keys = {
            'abuseipdb': os.getenv('ABUSEIPDB_API_KEY', '3f0fa7f9204bd618d24f7b2be233382f0a37cc16ef41c36976b3ee87611c844ecc8b3c2fbe3a3ba3'),
            'shodan': os.getenv('SHODAN_API_KEY', 'gB4ThIkHfWApnpDawWLGnq9Tc7TqvuDw'),
            'virustotal': os.getenv('VIRUSTOTAL_API_KEY', 'a9f4b3641ade0460ce11d4e9c81f066959a97bc62a3f155efb4ccf10b8efda2d')
        }
        
        self.threat_cache = {}
        self.cache_duration = 3600  # 1 hour cache
        
    async def analyze_target_reputation(self, target_url: str) -> Dict:
        """Analyze target reputation using multiple threat intelligence sources"""
        
        domain = self._extract_domain(target_url)
        ip_address = await self._resolve_domain_to_ip(domain)
        
        reputation_data = {
            'domain': domain,
            'ip_address': ip_address,
            'threat_score': 0,
            'reputation_sources': {},
            'cve_matches': [],
            'malware_associations': [],
            'recommendations': []
        }
        
        # Check domain reputation
        domain_rep = await self._check_domain_reputation(domain)
        reputation_data['reputation_sources']['domain'] = domain_rep
        
        # Check IP reputation
        if ip_address:
            ip_rep = await self._check_ip_reputation(ip_address)
            reputation_data['reputation_sources']['ip'] = ip_rep
        
        # Check for known vulnerabilities
        cve_data = await self._check_cve_database(domain)
        reputation_data['cve_matches'] = cve_data
        
        # Calculate overall threat score
        reputation_data['threat_score'] = self._calculate_threat_score(reputation_data)
        
        # Generate recommendations
        reputation_data['recommendations'] = self._generate_security_recommendations(reputation_data)
        
        return reputation_data
    
    async def get_latest_vulnerabilities(self, technology_stack: List[str] = None) -> List[Dict]:
        """Get latest vulnerabilities relevant to the target technology stack"""
        
        cache_key = f"latest_vulns_{hash(str(technology_stack))}"
        
        # Check cache first
        if cache_key in self.threat_cache:
            cached_data = self.threat_cache[cache_key]
            if datetime.now() - cached_data['timestamp'] < timedelta(seconds=self.cache_duration):
                return cached_data['data']
        
        vulnerabilities = []
        
        try:
            # Get recent CVEs
            async with aiohttp.ClientSession() as session:
                async with session.get(self.threat_feeds['cve_database']) as response:
                    if response.status == 200:
                        cve_data = await response.json()
                        
                        for cve in cve_data:
                            if self._is_relevant_to_stack(cve, technology_stack):
                                vuln = {
                                    'id': cve.get('id', ''),
                                    'summary': cve.get('summary', ''),
                                    'cvss': cve.get('cvss', 0),
                                    'published': cve.get('Published', ''),
                                    'severity': self._cvss_to_severity(cve.get('cvss', 0)),
                                    'references': cve.get('references', []),
                                    'source': 'CVE Database'
                                }
                                vulnerabilities.append(vuln)
        
        except Exception as e:
            logging.error(f"Error fetching CVE data: {e}")
        
        # Cache the results
        self.threat_cache[cache_key] = {
            'data': vulnerabilities,
            'timestamp': datetime.now()
        }
        
        return vulnerabilities
    
    async def enrich_vulnerability_data(self, vulnerability: Dict) -> Dict:
        """Enrich found vulnerabilities with threat intelligence"""
        
        enriched = vulnerability.copy()
        
        # Add threat intelligence context
        enriched['threat_intel'] = {
            'exploitability': await self._check_exploitability(vulnerability),
            'public_exploits': await self._find_public_exploits(vulnerability),
            'attack_patterns': await self._get_attack_patterns(vulnerability),
            'mitigation_priority': self._calculate_mitigation_priority(vulnerability)
        }
        
        return enriched
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.netloc
    
    async def _resolve_domain_to_ip(self, domain: str) -> Optional[str]:
        """Resolve domain to IP address"""
        try:
            import socket
            ip = socket.gethostbyname(domain)
            return ip
        except:
            return None
    
    async def _check_domain_reputation(self, domain: str) -> Dict:
        """Check domain reputation using multiple sources"""
        reputation = {
            'score': 0,
            'sources': [],
            'details': {}
        }
        
        # Check VirusTotal if API key available
        if self.api_keys.get('virustotal'):
            vt_domain_result = await self._check_virustotal_domain(domain)
            vt_url_result = await self._check_virustotal_url(f"http://{domain}")
            
            reputation['sources'].extend(['VirusTotal Domain', 'VirusTotal URL'])
            reputation['details']['virustotal_domain'] = vt_domain_result
            reputation['details']['virustotal_url'] = vt_url_result
            
            # Average the threat scores
            avg_vt_score = (vt_domain_result.get('threat_score', 0) + vt_url_result.get('threat_score', 0)) / 2
            reputation['score'] += avg_vt_score
        
        # Check URLHaus for malware associations
        urlhaus_result = await self._check_urlhaus(domain)
        reputation['sources'].append('URLHaus')
        reputation['details']['urlhaus'] = urlhaus_result
        reputation['score'] += urlhaus_result.get('threat_score', 0)
        
        return reputation
    
    async def _check_ip_reputation(self, ip_address: str) -> Dict:
        """Check IP reputation using AbuseIPDB"""
        reputation = {
            'score': 0,
            'abuse_reports': 0,
            'country': '',
            'isp': '',
            'details': {}
        }
        
        if not self.api_keys.get('abuseipdb'):
            return reputation
        
        try:
            headers = {
                'Key': self.api_keys['abuseipdb'],
                'Accept': 'application/json'
            }
            
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.threat_feeds['ip_reputation'], 
                    headers=headers, 
                    params=params
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        if 'data' in data:
                            ip_data = data['data']
                            reputation.update({
                                'score': ip_data.get('abuseConfidencePercentage', 0),
                                'abuse_reports': ip_data.get('totalReports', 0),
                                'country': ip_data.get('countryCode', ''),
                                'isp': ip_data.get('isp', ''),
                                'details': ip_data
                            })
        
        except Exception as e:
            logging.error(f"Error checking IP reputation: {e}")
        
        return reputation
    
    async def _check_cve_database(self, domain: str) -> List[Dict]:
        """Check for CVEs related to the domain/technology"""
        cves = []
        
        try:
            # Search for CVEs related to domain or common technologies
            search_terms = [domain, 'web application', 'http', 'ssl', 'tls']
            
            for term in search_terms:
                search_url = f"https://cve.circl.lu/api/search/{term}"
                
                async with aiohttp.ClientSession() as session:
                    async with session.get(search_url) as response:
                        if response.status == 200:
                            search_results = await response.json()
                            cves.extend(search_results[:5])  # Limit to 5 results per term
        
        except Exception as e:
            logging.error(f"Error searching CVE database: {e}")
        
        return cves
    
    def _is_relevant_to_stack(self, cve: Dict, technology_stack: List[str]) -> bool:
        """Check if CVE is relevant to the technology stack"""
        if not technology_stack:
            return True
        
        cve_text = f"{cve.get('summary', '')} {cve.get('id', '')}".lower()
        
        for tech in technology_stack:
            if tech.lower() in cve_text:
                return True
        
        return False
    
    def _cvss_to_severity(self, cvss: float) -> str:
        """Convert CVSS score to severity level"""
        if cvss >= 9.0:
            return 'Critical'
        elif cvss >= 7.0:
            return 'High'
        elif cvss >= 4.0:
            return 'Medium'
        else:
            return 'Low'
    
    def _calculate_threat_score(self, reputation_data: Dict) -> int:
        """Calculate overall threat score from 0-100"""
        score = 0
        
        # Domain reputation
        domain_rep = reputation_data.get('reputation_sources', {}).get('domain', {})
        score += domain_rep.get('score', 0) * 0.3
        
        # IP reputation
        ip_rep = reputation_data.get('reputation_sources', {}).get('ip', {})
        score += ip_rep.get('score', 0) * 0.3
        
        # CVE count
        cve_count = len(reputation_data.get('cve_matches', []))
        score += min(cve_count * 10, 40)  # Max 40 points for CVEs
        
        return min(int(score), 100)
    
    def _generate_security_recommendations(self, reputation_data: Dict) -> List[str]:
        """Generate security recommendations based on threat intelligence"""
        recommendations = []
        
        threat_score = reputation_data.get('threat_score', 0)
        
        if threat_score > 70:
            recommendations.append("HIGH RISK: Target has significant threat indicators")
            recommendations.append("Implement additional security monitoring")
            recommendations.append("Consider blocking or restricting access")
        
        elif threat_score > 40:
            recommendations.append("MEDIUM RISK: Some threat indicators present")
            recommendations.append("Increase scan frequency and monitoring")
        
        cve_count = len(reputation_data.get('cve_matches', []))
        if cve_count > 0:
            recommendations.append(f"Found {cve_count} relevant CVE(s) - prioritize patching")
        
        ip_rep = reputation_data.get('reputation_sources', {}).get('ip', {})
        if ip_rep.get('abuse_reports', 0) > 0:
            recommendations.append("IP has abuse reports - monitor for malicious activity")
        
        return recommendations
    
    async def _check_exploitability(self, vulnerability: Dict) -> Dict:
        """Check if vulnerability has known exploits"""
        # In a real implementation, this would check exploit databases
        return {
            'public_exploits_available': False,
            'exploit_complexity': 'Medium',
            'exploitation_likelihood': 'Low'
        }
    
    async def _find_public_exploits(self, vulnerability: Dict) -> List[Dict]:
        """Find public exploits for the vulnerability"""
        # In a real implementation, this would search exploit databases
        return []
    
    async def _get_attack_patterns(self, vulnerability: Dict) -> List[str]:
        """Get common attack patterns for this vulnerability type"""
        patterns = {
            'xss': ['Reflected XSS', 'Stored XSS', 'DOM-based XSS'],
            'sql injection': ['Union-based', 'Boolean-based', 'Time-based'],
            'directory traversal': ['Path traversal', 'File inclusion', 'Directory listing']
        }
        
        vuln_type = vulnerability.get('title', '').lower()
        
        for pattern_type, attack_patterns in patterns.items():
            if pattern_type in vuln_type:
                return attack_patterns
        
        return ['Generic attack patterns']
    
    def _calculate_mitigation_priority(self, vulnerability: Dict) -> str:
        """Calculate mitigation priority based on various factors"""
        severity = vulnerability.get('severity', 'Low').lower()
        cvss = vulnerability.get('cvss', 0)
        
        if severity == 'critical' or cvss >= 9.0:
            return 'Immediate'
        elif severity == 'high' or cvss >= 7.0:
            return 'High'
        elif severity == 'medium' or cvss >= 4.0:
            return 'Medium'
        else:
            return 'Low'
    
    async def _check_virustotal_domain(self, domain: str) -> Dict:
        """Check domain reputation on VirusTotal"""
        vt_result = {'threat_score': 0, 'detections': 0, 'scan_engines': 0, 'details': {}}
        
        if not self.api_keys.get('virustotal'):
            return vt_result
        
        try:
            headers = {
                'x-apikey': self.api_keys['virustotal']
            }
            
            # Get domain analysis from VirusTotal
            url = f"https://www.virustotal.com/vtapi/v2/domain/report"
            params = {
                'apikey': self.api_keys['virustotal'],
                'domain': domain
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        if data.get('response_code') == 1:
                            # Domain found in VirusTotal
                            detections = 0
                            scan_engines = 0
                            
                            # Count positive detections
                            for engine, result in data.get('scans', {}).items():
                                scan_engines += 1
                                if result.get('detected', False):
                                    detections += 1
                            
                            # Calculate threat score (0-100)
                            threat_score = 0
                            if scan_engines > 0:
                                threat_score = int((detections / scan_engines) * 100)
                            
                            vt_result.update({
                                'threat_score': threat_score,
                                'detections': detections,
                                'scan_engines': scan_engines,
                                'details': {
                                    'categories': data.get('categories', []),
                                    'subdomains': data.get('subdomains', [])[:10],  # Limit to 10
                                    'resolutions': data.get('resolutions', [])[:5],  # Limit to 5
                                    'detected_urls': len(data.get('detected_urls', [])),
                                    'undetected_urls': len(data.get('undetected_urls', []))
                                }
                            })
                        
        except Exception as e:
            logging.error(f"Error checking VirusTotal domain: {e}")
        
        return vt_result
    
    async def _check_virustotal_url(self, url: str) -> Dict:
        """Check URL reputation on VirusTotal"""
        vt_result = {'threat_score': 0, 'detections': 0, 'scan_engines': 0, 'details': {}}
        
        if not self.api_keys.get('virustotal'):
            return vt_result
        
        try:
            # Get URL analysis from VirusTotal
            vt_url = "https://www.virustotal.com/vtapi/v2/url/report"
            params = {
                'apikey': self.api_keys['virustotal'],
                'resource': url
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(vt_url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        if data.get('response_code') == 1:
                            # URL found in VirusTotal
                            detections = data.get('positives', 0)
                            scan_engines = data.get('total', 0)
                            
                            # Calculate threat score (0-100)
                            threat_score = 0
                            if scan_engines > 0:
                                threat_score = int((detections / scan_engines) * 100)
                            
                            vt_result.update({
                                'threat_score': threat_score,
                                'detections': detections,
                                'scan_engines': scan_engines,
                                'details': {
                                    'scan_date': data.get('scan_date', ''),
                                    'permalink': data.get('permalink', ''),
                                    'filescan_id': data.get('filescan_id', '')
                                }
                            })
                        
        except Exception as e:
            logging.error(f"Error checking VirusTotal URL: {e}")
        
        return vt_result
    
    async def _check_urlhaus(self, domain: str) -> Dict:
        """Check URLHaus for malware associations"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.threat_feeds['malware_domains']) as response:
                    if response.status == 200:
                        data = await response.json()
                        urls = data.get('urls', [])
                        
                        # Check if domain appears in recent malware URLs
                        threat_score = 0
                        for url_data in urls:
                            if domain in url_data.get('url', ''):
                                threat_score += 10
                        
                        return {
                            'threat_score': min(threat_score, 50),
                            'malware_urls_found': threat_score // 10
                        }
        
        except Exception as e:
            logging.error(f"Error checking URLHaus: {e}")
        
        return {'threat_score': 0, 'malware_urls_found': 0}
    
    def get_agent_status(self) -> Dict:
        """Get threat intelligence agent status"""
        return {
            'name': 'Threat Intelligence Agent',
            'status': 'active',
            'capabilities': [
                'Domain Reputation Analysis',
                'URL Reputation Analysis',
                'IP Reputation Checking',
                'CVE Database Integration',
                'Malware Intelligence',
                'VirusTotal Integration',
                'Shodan Intelligence',
                'Vulnerability Enrichment'
            ],
            'api_keys_configured': len([k for k in self.api_keys.values() if k]),
            'available_sources': [
                'AbuseIPDB', 'Shodan', 'VirusTotal', 'CVE Database', 'URLHaus'
            ],
            'threat_feeds_active': len(self.threat_feeds),
            'cache_entries': len(self.threat_cache)
        }
