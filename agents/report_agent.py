# Report Agent - Security Report Generation
"""
Real security report generation agent.
Aggregates findings from all security agents and generates comprehensive security reports.
"""

import json
import time
from datetime import datetime, timezone
from typing import Dict, List, Any
import logging

logger = logging.getLogger(__name__)

class ReportAgent:
    """Real security report generation agent"""
    
    def __init__(self):
        self.severity_scores = {
            'Critical': 10,
            'High': 7,
            'Medium': 5,
            'Low': 2,
            'Info': 1
        }
        
        self.cvss_ranges = {
            'Critical': (9.0, 10.0),
            'High': (7.0, 8.9),
            'Medium': (4.0, 6.9),
            'Low': (0.1, 3.9),
            'None': (0.0, 0.0)
        }
    
    async def generate_report(self, scan_results: List[Dict[str, Any]], target_url: str, progress_callback=None) -> Dict[str, Any]:
        """
        Generate comprehensive security report from scan results
        
        Args:
            scan_results: List of scan results from different agents
            target_url: Target URL that was scanned
            
        Returns:
            Dict containing comprehensive security report
        """
        try:
            logger.info(f"📊 Generating security report for: {target_url}")
            
            # Initialize report structure
            report = {
                'target': target_url,
                'scan_timestamp': time.time(),
                'scan_date': datetime.now(timezone.utc).isoformat(),
                'report_version': '1.0',
                'executive_summary': {},
                'vulnerability_summary': {},
                'detailed_findings': [],
                'recommendations': [],
                'scan_coverage': {},
                'risk_assessment': {},
                'compliance_status': {},
                'appendix': {}
            }
            
            # Aggregate all vulnerabilities
            if progress_callback:
                progress_callback(20, "📋 Aggregating vulnerability findings...")
            all_vulnerabilities = self._aggregate_vulnerabilities(scan_results)
            report['detailed_findings'] = all_vulnerabilities

            # Generate executive summary
            if progress_callback:
                progress_callback(40, "📝 Generating executive summary...")
            report['executive_summary'] = self._generate_executive_summary(all_vulnerabilities, target_url)

            # Generate vulnerability summary
            if progress_callback:
                progress_callback(60, "📊 Creating vulnerability summary and statistics...")
            report['vulnerability_summary'] = self._generate_vulnerability_summary(all_vulnerabilities)

            # Generate recommendations
            if progress_callback:
                progress_callback(80, "💡 Generating security recommendations...")
            report['recommendations'] = self._generate_recommendations(all_vulnerabilities)

            # Assess scan coverage
            if progress_callback:
                progress_callback(90, "🔍 Assessing scan coverage and completeness...")
            report['scan_coverage'] = self._assess_scan_coverage(scan_results)
            
            # Perform risk assessment
            report['risk_assessment'] = self._perform_risk_assessment(all_vulnerabilities)

            # Check compliance status
            report['compliance_status'] = self._check_compliance_status(all_vulnerabilities)

            # Generate appendix
            report['appendix'] = self._generate_appendix(scan_results)

            if progress_callback:
                progress_callback(100, f"✅ Security report generated: {len(all_vulnerabilities)} findings")
            logger.info(f"✅ Security report generated: {len(all_vulnerabilities)} findings")
            
            return report
            
        except Exception as e:
            logger.error(f"❌ Report generation failed: {e}")
            raise
    
    def _aggregate_vulnerabilities(self, scan_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Aggregate vulnerabilities from all scan results"""
        all_vulnerabilities = []
        
        for scan_result in scan_results:
            vulnerabilities = scan_result.get('vulnerabilities', [])
            
            for vuln in vulnerabilities:
                # Add scan context
                vuln['scan_type'] = scan_result.get('scan_type', 'unknown')
                vuln['scan_timestamp'] = scan_result.get('timestamp', time.time())
                
                # Ensure required fields
                if 'id' not in vuln:
                    vuln['id'] = f"vuln_{len(all_vulnerabilities) + 1}"
                
                all_vulnerabilities.append(vuln)
        
        # Sort by severity and CVSS score
        all_vulnerabilities.sort(
            key=lambda x: (self.severity_scores.get(x.get('severity', 'Low'), 1), 
                          x.get('cvss', 0.0)), 
            reverse=True
        )
        
        return all_vulnerabilities
    
    def _generate_executive_summary(self, vulnerabilities: List[Dict[str, Any]], target_url: str) -> Dict[str, Any]:
        """Generate executive summary"""
        total_vulns = len(vulnerabilities)
        
        # Count by severity
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Low')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Calculate risk score
        risk_score = self._calculate_overall_risk_score(vulnerabilities)
        
        # Determine risk level
        if risk_score >= 8.0:
            risk_level = 'Critical'
        elif risk_score >= 6.0:
            risk_level = 'High'
        elif risk_score >= 4.0:
            risk_level = 'Medium'
        else:
            risk_level = 'Low'
        
        return {
            'target_url': target_url,
            'total_vulnerabilities': total_vulns,
            'severity_breakdown': severity_counts,
            'overall_risk_score': round(risk_score, 2),
            'overall_risk_level': risk_level,
            'critical_issues': severity_counts.get('Critical', 0),
            'high_issues': severity_counts.get('High', 0),
            'key_findings': self._get_key_findings(vulnerabilities),
            'immediate_actions_required': self._get_immediate_actions(vulnerabilities)
        }
    
    def _calculate_overall_risk_score(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        """Calculate overall risk score based on vulnerabilities"""
        if not vulnerabilities:
            return 0.0
        
        total_score = 0.0
        weight_sum = 0.0
        
        for vuln in vulnerabilities:
            cvss = vuln.get('cvss', 0.0)
            severity = vuln.get('severity', 'Low')
            weight = self.severity_scores.get(severity, 1)
            
            total_score += cvss * weight
            weight_sum += weight
        
        return total_score / weight_sum if weight_sum > 0 else 0.0
    
    def _get_key_findings(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Extract key findings from vulnerabilities"""
        key_findings = []
        
        # Get top 5 most severe vulnerabilities
        top_vulns = vulnerabilities[:5]
        
        for vuln in top_vulns:
            finding = f"{vuln.get('severity', 'Unknown')} severity: {vuln.get('title', 'Unknown vulnerability')}"
            key_findings.append(finding)
        
        return key_findings
    
    def _get_immediate_actions(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Get immediate actions required"""
        actions = []
        
        # Critical and High severity vulnerabilities require immediate action
        critical_high_vulns = [v for v in vulnerabilities if v.get('severity') in ['Critical', 'High']]
        
        if critical_high_vulns:
            actions.append(f"Address {len(critical_high_vulns)} critical/high severity vulnerabilities immediately")
        
        # Check for specific vulnerability types
        vuln_types = {}
        for vuln in critical_high_vulns:
            title = vuln.get('title', '')
            if 'SQL Injection' in title:
                vuln_types['sql_injection'] = vuln_types.get('sql_injection', 0) + 1
            elif 'XSS' in title:
                vuln_types['xss'] = vuln_types.get('xss', 0) + 1
            elif 'Authentication' in title:
                vuln_types['auth'] = vuln_types.get('auth', 0) + 1
        
        for vuln_type, count in vuln_types.items():
            if vuln_type == 'sql_injection':
                actions.append(f"Patch {count} SQL injection vulnerabilities to prevent data breaches")
            elif vuln_type == 'xss':
                actions.append(f"Fix {count} XSS vulnerabilities to prevent client-side attacks")
            elif vuln_type == 'auth':
                actions.append(f"Secure {count} authentication issues to prevent unauthorized access")
        
        return actions
    
    def _generate_vulnerability_summary(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate detailed vulnerability summary"""
        summary = {
            'total_count': len(vulnerabilities),
            'by_severity': {},
            'by_agent': {},
            'by_category': {},
            'cvss_distribution': {},
            'top_vulnerabilities': []
        }
        
        # Count by severity
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Low')
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
        
        # Count by discovering agent
        for vuln in vulnerabilities:
            agent = vuln.get('discovered_by', 'Unknown')
            summary['by_agent'][agent] = summary['by_agent'].get(agent, 0) + 1
        
        # Categorize vulnerabilities
        for vuln in vulnerabilities:
            category = self._categorize_vulnerability(vuln)
            summary['by_category'][category] = summary['by_category'].get(category, 0) + 1
        
        # CVSS distribution
        for vuln in vulnerabilities:
            cvss = vuln.get('cvss', 0.0)
            cvss_range = self._get_cvss_range(cvss)
            summary['cvss_distribution'][cvss_range] = summary['cvss_distribution'].get(cvss_range, 0) + 1
        
        # Top 10 vulnerabilities
        summary['top_vulnerabilities'] = vulnerabilities[:10]
        
        return summary
    
    def _categorize_vulnerability(self, vulnerability: Dict[str, Any]) -> str:
        """Categorize vulnerability by type"""
        title = vulnerability.get('title', '').lower()
        
        if 'sql injection' in title or 'sqli' in title:
            return 'Injection'
        elif 'xss' in title or 'cross-site scripting' in title:
            return 'Cross-Site Scripting'
        elif 'authentication' in title or 'auth' in title:
            return 'Authentication'
        elif 'authorization' in title or 'access control' in title:
            return 'Authorization'
        elif 'information disclosure' in title or 'data exposure' in title:
            return 'Information Disclosure'
        elif 'security header' in title or 'header' in title:
            return 'Security Headers'
        elif 'ssl' in title or 'tls' in title or 'certificate' in title:
            return 'Cryptography'
        elif 'directory traversal' in title or 'path traversal' in title:
            return 'Directory Traversal'
        elif 'rate limit' in title:
            return 'Rate Limiting'
        elif 'port' in title or 'service' in title:
            return 'Network Security'
        else:
            return 'Other'
    
    def _get_cvss_range(self, cvss: float) -> str:
        """Get CVSS range category"""
        for severity, (min_score, max_score) in self.cvss_ranges.items():
            if min_score <= cvss <= max_score:
                return f"{severity} ({min_score}-{max_score})"
        return "Unknown"
    
    def _generate_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate security recommendations"""
        recommendations = []
        
        # Group vulnerabilities by category
        categories = {}
        for vuln in vulnerabilities:
            category = self._categorize_vulnerability(vuln)
            if category not in categories:
                categories[category] = []
            categories[category].append(vuln)
        
        # Generate recommendations for each category
        for category, vulns in categories.items():
            recommendation = self._get_category_recommendation(category, len(vulns))
            if recommendation:
                recommendations.append(recommendation)
        
        # Add general security recommendations
        general_recommendations = self._get_general_recommendations(vulnerabilities)
        recommendations.extend(general_recommendations)
        
        return recommendations
    
    def _get_category_recommendation(self, category: str, count: int) -> Dict[str, Any]:
        """Get recommendation for specific vulnerability category"""
        recommendations_map = {
            'Injection': {
                'title': 'Prevent Injection Attacks',
                'priority': 'Critical',
                'description': f'Address {count} injection vulnerabilities by implementing input validation and parameterized queries',
                'actions': [
                    'Use parameterized queries for database interactions',
                    'Implement input validation and sanitization',
                    'Use ORM frameworks with built-in protection',
                    'Apply principle of least privilege for database accounts'
                ]
            },
            'Cross-Site Scripting': {
                'title': 'Prevent XSS Attacks',
                'priority': 'High',
                'description': f'Fix {count} XSS vulnerabilities through proper output encoding and input validation',
                'actions': [
                    'Implement output encoding for all user input',
                    'Use Content Security Policy (CSP) headers',
                    'Validate and sanitize all user input',
                    'Use secure coding frameworks'
                ]
            },
            'Authentication': {
                'title': 'Strengthen Authentication',
                'priority': 'High',
                'description': f'Secure {count} authentication issues to prevent unauthorized access',
                'actions': [
                    'Implement multi-factor authentication',
                    'Use strong password policies',
                    'Implement account lockout mechanisms',
                    'Use secure session management'
                ]
            },
            'Security Headers': {
                'title': 'Implement Security Headers',
                'priority': 'Medium',
                'description': f'Add {count} missing security headers for enhanced protection',
                'actions': [
                    'Implement X-Frame-Options header',
                    'Add X-Content-Type-Options header',
                    'Configure Strict-Transport-Security header',
                    'Set up Content-Security-Policy header'
                ]
            }
        }
        
        return recommendations_map.get(category)
    
    def _get_general_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Get general security recommendations"""
        return [
            {
                'title': 'Regular Security Assessments',
                'priority': 'Medium',
                'description': 'Conduct regular security assessments to identify new vulnerabilities',
                'actions': [
                    'Schedule quarterly security scans',
                    'Implement continuous security monitoring',
                    'Perform code reviews for security issues',
                    'Keep security tools and signatures updated'
                ]
            },
            {
                'title': 'Security Training',
                'priority': 'Medium',
                'description': 'Provide security training for development and operations teams',
                'actions': [
                    'Train developers on secure coding practices',
                    'Educate staff on security awareness',
                    'Implement security champions program',
                    'Regular security workshops and updates'
                ]
            }
        ]
    
    def _assess_scan_coverage(self, scan_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess the coverage of security scans"""
        coverage = {
            'scans_performed': [],
            'coverage_percentage': 0,
            'missing_scans': [],
            'scan_quality': 'Good'
        }
        
        # Expected scan types
        expected_scans = ['reconnaissance', 'web_application', 'network', 'api_security']
        
        # Performed scans
        performed_scans = [result.get('scan_type', 'unknown') for result in scan_results]
        coverage['scans_performed'] = list(set(performed_scans))
        
        # Calculate coverage percentage
        coverage_count = len(set(performed_scans) & set(expected_scans))
        coverage['coverage_percentage'] = (coverage_count / len(expected_scans)) * 100
        
        # Missing scans
        coverage['missing_scans'] = list(set(expected_scans) - set(performed_scans))
        
        # Assess scan quality
        if coverage['coverage_percentage'] >= 75:
            coverage['scan_quality'] = 'Excellent'
        elif coverage['coverage_percentage'] >= 50:
            coverage['scan_quality'] = 'Good'
        else:
            coverage['scan_quality'] = 'Limited'
        
        return coverage
    
    def _perform_risk_assessment(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Perform comprehensive risk assessment"""
        risk_assessment = {
            'overall_risk_level': 'Low',
            'business_impact': 'Low',
            'likelihood': 'Low',
            'risk_factors': [],
            'mitigation_priority': []
        }
        
        # Calculate risk based on vulnerabilities
        critical_count = len([v for v in vulnerabilities if v.get('severity') == 'Critical'])
        high_count = len([v for v in vulnerabilities if v.get('severity') == 'High'])
        
        # Determine overall risk level
        if critical_count > 0:
            risk_assessment['overall_risk_level'] = 'Critical'
            risk_assessment['business_impact'] = 'High'
            risk_assessment['likelihood'] = 'High'
        elif high_count > 2:
            risk_assessment['overall_risk_level'] = 'High'
            risk_assessment['business_impact'] = 'Medium'
            risk_assessment['likelihood'] = 'Medium'
        elif high_count > 0:
            risk_assessment['overall_risk_level'] = 'Medium'
            risk_assessment['business_impact'] = 'Medium'
            risk_assessment['likelihood'] = 'Low'
        
        # Identify risk factors
        if critical_count > 0:
            risk_assessment['risk_factors'].append(f'{critical_count} critical vulnerabilities present')
        if high_count > 0:
            risk_assessment['risk_factors'].append(f'{high_count} high severity vulnerabilities')
        
        # Set mitigation priorities
        if critical_count > 0:
            risk_assessment['mitigation_priority'].append('Address critical vulnerabilities immediately')
        if high_count > 0:
            risk_assessment['mitigation_priority'].append('Fix high severity issues within 7 days')
        
        return risk_assessment
    
    def _check_compliance_status(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Check compliance with security standards"""
        compliance = {
            'owasp_top_10': {'status': 'Compliant', 'issues': []},
            'pci_dss': {'status': 'Compliant', 'issues': []},
            'gdpr': {'status': 'Compliant', 'issues': []},
            'overall_compliance': 'Compliant'
        }
        
        # Check OWASP Top 10 compliance
        owasp_issues = []
        for vuln in vulnerabilities:
            title = vuln.get('title', '').lower()
            if any(term in title for term in ['injection', 'xss', 'authentication', 'authorization']):
                owasp_issues.append(vuln.get('title', 'Unknown'))
        
        if owasp_issues:
            compliance['owasp_top_10']['status'] = 'Non-Compliant'
            compliance['owasp_top_10']['issues'] = owasp_issues[:5]  # Top 5 issues
            compliance['overall_compliance'] = 'Non-Compliant'
        
        return compliance
    
    def _generate_appendix(self, scan_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate report appendix with technical details"""
        return {
            'scan_configuration': {
                'scan_types': [result.get('scan_type', 'unknown') for result in scan_results],
                'total_scan_time': sum(result.get('scan_duration', 0) for result in scan_results),
                'tools_used': ['nmap', 'requests', 'beautifulsoup4', 'dns.resolver']
            },
            'methodology': {
                'reconnaissance': 'DNS enumeration, subdomain discovery, port scanning',
                'web_application': 'XSS testing, SQL injection, security headers analysis',
                'network': 'Port scanning, service enumeration, SSL/TLS testing',
                'api_security': 'Authentication testing, injection testing, rate limiting'
            },
            'limitations': [
                'Scans performed with safety limitations to prevent damage',
                'Limited to common vulnerability patterns',
                'Manual verification recommended for critical findings',
                'Some tests may produce false positives'
            ]
        }
