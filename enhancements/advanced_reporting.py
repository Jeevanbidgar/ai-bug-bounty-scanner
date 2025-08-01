# Advanced Analytics & Reporting Module
"""
Enhanced reporting system with advanced analytics, charts, and export options
"""

import json
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import base64
import io
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt
import seaborn as sns
from jinja2 import Template
import logging

class AdvancedReportingAgent:
    """Advanced reporting and analytics for vulnerability data"""
    
    def __init__(self):
        self.report_templates = {
            'executive_summary': self._load_executive_template(),
            'technical_detailed': self._load_technical_template(),
            'compliance_report': self._load_compliance_template(),
            'trend_analysis': self._load_trend_template()
        }
        
        # Set up plotting style
        plt.style.use('dark_background')
        sns.set_palette("husl")
    
    async def generate_executive_dashboard(self, scan_data: List[Dict]) -> Dict:
        """Generate executive-level dashboard with KPIs and trends"""
        
        dashboard_data = {
            'summary_kpis': await self._calculate_executive_kpis(scan_data),
            'risk_metrics': await self._calculate_risk_metrics(scan_data),
            'trend_analysis': await self._analyze_security_trends(scan_data),
            'compliance_status': await self._assess_compliance_status(scan_data),
            'charts': {
                'vulnerability_trends': await self._create_vulnerability_trend_chart(scan_data),
                'severity_distribution': await self._create_severity_pie_chart(scan_data),
                'risk_heatmap': await self._create_risk_heatmap(scan_data),
                'compliance_radar': await self._create_compliance_radar(scan_data)
            },
            'recommendations': await self._generate_executive_recommendations(scan_data)
        }
        
        return dashboard_data
    
    async def generate_technical_report(self, scan_data: List[Dict], vulnerabilities: List[Dict]) -> Dict:
        """Generate detailed technical report for security teams"""
        
        report_data = {
            'scan_summary': await self._generate_scan_summary(scan_data),
            'vulnerability_analysis': await self._analyze_vulnerabilities(vulnerabilities),
            'attack_surface_analysis': await self._analyze_attack_surface(scan_data),
            'remediation_plan': await self._create_remediation_plan(vulnerabilities),
            'technical_charts': {
                'vulnerability_timeline': await self._create_vulnerability_timeline(vulnerabilities),
                'attack_vector_analysis': await self._create_attack_vector_chart(vulnerabilities),
                'remediation_priority': await self._create_remediation_priority_chart(vulnerabilities),
                'technology_risk_map': await self._create_technology_risk_map(vulnerabilities)
            },
            'detailed_findings': await self._format_detailed_findings(vulnerabilities)
        }
        
        return report_data
    
    async def generate_compliance_report(self, scan_data: List[Dict], framework: str = 'OWASP') -> Dict:
        """Generate compliance report for specific frameworks (OWASP, NIST, ISO27001)"""
        
        compliance_mapping = {
            'OWASP': await self._map_to_owasp_top10(scan_data),
            'NIST': await self._map_to_nist_framework(scan_data),
            'ISO27001': await self._map_to_iso27001(scan_data)
        }
        
        report_data = {
            'framework': framework,
            'compliance_score': await self._calculate_compliance_score(scan_data, framework),
            'control_mappings': compliance_mapping.get(framework, {}),
            'gaps_identified': await self._identify_compliance_gaps(scan_data, framework),
            'improvement_roadmap': await self._create_improvement_roadmap(scan_data, framework),
            'evidence_collection': await self._collect_compliance_evidence(scan_data)
        }
        
        return report_data
    
    async def _calculate_executive_kpis(self, scan_data: List[Dict]) -> Dict:
        """Calculate key performance indicators for executives"""
        
        if not scan_data:
            return {}
        
        # Calculate KPIs
        total_scans = len(scan_data)
        completed_scans = len([s for s in scan_data if s.get('status') == 'completed'])
        total_vulnerabilities = sum(s.get('vulnerabilities', 0) for s in scan_data)
        critical_vulnerabilities = sum(s.get('critical', 0) for s in scan_data)
        
        # Calculate averages
        avg_scan_time = np.mean([self._calculate_scan_duration(s) for s in scan_data if s.get('completed')])
        avg_vulns_per_scan = total_vulnerabilities / max(completed_scans, 1)
        
        # Calculate trends (compare with previous period)
        current_period = datetime.now() - timedelta(days=30)
        recent_scans = [s for s in scan_data if self._parse_date(s.get('started')) > current_period]
        trend_direction = 'up' if len(recent_scans) > len(scan_data) / 2 else 'down'
        
        return {
            'total_scans': total_scans,
            'completion_rate': (completed_scans / max(total_scans, 1)) * 100,
            'total_vulnerabilities': total_vulnerabilities,
            'critical_vulnerabilities': critical_vulnerabilities,
            'average_scan_time_hours': avg_scan_time,
            'vulnerabilities_per_scan': avg_vulns_per_scan,
            'security_trend': trend_direction,
            'risk_reduction_percentage': self._calculate_risk_reduction(scan_data)
        }
    
    async def _calculate_risk_metrics(self, scan_data: List[Dict]) -> Dict:
        """Calculate advanced risk metrics"""
        
        # Risk scoring based on CVSS and frequency
        risk_scores = []
        exposure_time = []
        
        for scan in scan_data:
            # Calculate risk score (0-100)
            critical = scan.get('critical', 0)
            high = scan.get('high', 0)
            medium = scan.get('medium', 0)
            low = scan.get('low', 0)
            
            risk_score = (critical * 10) + (high * 7) + (medium * 4) + (low * 1)
            risk_scores.append(min(risk_score, 100))
            
            # Calculate exposure time
            if scan.get('started'):
                exposure = (datetime.now() - self._parse_date(scan.get('started'))).days
                exposure_time.append(exposure)
        
        return {
            'average_risk_score': np.mean(risk_scores) if risk_scores else 0,
            'maximum_risk_score': max(risk_scores) if risk_scores else 0,
            'risk_distribution': {
                'low': len([r for r in risk_scores if r < 25]),
                'medium': len([r for r in risk_scores if 25 <= r < 50]),
                'high': len([r for r in risk_scores if 50 <= r < 75]),
                'critical': len([r for r in risk_scores if r >= 75])
            },
            'average_exposure_days': np.mean(exposure_time) if exposure_time else 0,
            'risk_velocity': self._calculate_risk_velocity(risk_scores)
        }
    
    async def _create_vulnerability_trend_chart(self, scan_data: List[Dict]) -> str:
        """Create vulnerability trend chart as base64 encoded image"""
        
        plt.figure(figsize=(12, 6))
        
        # Prepare data
        dates = []
        critical_counts = []
        high_counts = []
        medium_counts = []
        
        # Group by date
        date_groups = {}
        for scan in scan_data:
            if scan.get('started'):
                date = self._parse_date(scan.get('started')).date()
                if date not in date_groups:
                    date_groups[date] = {'critical': 0, 'high': 0, 'medium': 0}
                
                date_groups[date]['critical'] += scan.get('critical', 0)
                date_groups[date]['high'] += scan.get('high', 0)
                date_groups[date]['medium'] += scan.get('medium', 0)
        
        # Sort by date
        sorted_dates = sorted(date_groups.keys())
        
        for date in sorted_dates:
            dates.append(date)
            critical_counts.append(date_groups[date]['critical'])
            high_counts.append(date_groups[date]['high'])
            medium_counts.append(date_groups[date]['medium'])
        
        # Create plot
        plt.plot(dates, critical_counts, label='Critical', color='#FF4444', linewidth=3)
        plt.plot(dates, high_counts, label='High', color='#FF8800', linewidth=2)
        plt.plot(dates, medium_counts, label='Medium', color='#FFBB00', linewidth=2)
        
        plt.title('Vulnerability Trends Over Time', fontsize=16, fontweight='bold')
        plt.xlabel('Date', fontsize=12)
        plt.ylabel('Number of Vulnerabilities', fontsize=12)
        plt.legend()
        plt.grid(True, alpha=0.3)
        plt.xticks(rotation=45)
        plt.tight_layout()
        
        # Convert to base64
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', facecolor='#1a1a1a', edgecolor='none')
        buffer.seek(0)
        chart_data = base64.b64encode(buffer.read()).decode()
        plt.close()
        
        return f"data:image/png;base64,{chart_data}"
    
    async def _create_severity_pie_chart(self, scan_data: List[Dict]) -> str:
        """Create severity distribution pie chart"""
        
        plt.figure(figsize=(8, 8))
        
        # Calculate totals
        critical_total = sum(s.get('critical', 0) for s in scan_data)
        high_total = sum(s.get('high', 0) for s in scan_data)
        medium_total = sum(s.get('medium', 0) for s in scan_data)
        low_total = sum(s.get('low', 0) for s in scan_data)
        
        if critical_total + high_total + medium_total + low_total == 0:
            # No data to display
            plt.text(0.5, 0.5, 'No Vulnerability Data', ha='center', va='center', 
                    fontsize=16, transform=plt.gca().transAxes)
            plt.axis('off')
        else:
            # Create pie chart
            sizes = [critical_total, high_total, medium_total, low_total]
            labels = ['Critical', 'High', 'Medium', 'Low']
            colors = ['#FF4444', '#FF8800', '#FFBB00', '#4488FF']
            
            # Only include non-zero slices
            non_zero_data = [(size, label, color) for size, label, color in zip(sizes, labels, colors) if size > 0]
            
            if non_zero_data:
                sizes, labels, colors = zip(*non_zero_data)
                
                plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', 
                       startangle=90, textprops={'fontsize': 12})
        
        plt.title('Vulnerability Severity Distribution', fontsize=16, fontweight='bold')
        plt.axis('equal')
        
        # Convert to base64
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', facecolor='#1a1a1a', edgecolor='none')
        buffer.seek(0)
        chart_data = base64.b64encode(buffer.read()).decode()
        plt.close()
        
        return f"data:image/png;base64,{chart_data}"
    
    async def _create_risk_heatmap(self, scan_data: List[Dict]) -> str:
        """Create risk heatmap by target and time"""
        
        plt.figure(figsize=(12, 8))
        
        # Prepare data for heatmap
        targets = list(set(s.get('target', 'Unknown') for s in scan_data))
        dates = []
        
        # Get date range
        all_dates = [self._parse_date(s.get('started')) for s in scan_data if s.get('started')]
        if all_dates:
            min_date = min(all_dates).date()
            max_date = max(all_dates).date()
            
            current_date = min_date
            while current_date <= max_date:
                dates.append(current_date)
                current_date += timedelta(days=7)  # Weekly intervals
        
        if not dates or not targets:
            plt.text(0.5, 0.5, 'Insufficient Data for Heatmap', ha='center', va='center', 
                    fontsize=16, transform=plt.gca().transAxes)
            plt.axis('off')
        else:
            # Create risk matrix
            risk_matrix = np.zeros((len(targets), len(dates)))
            
            for i, target in enumerate(targets):
                for j, date in enumerate(dates):
                    # Find scans for this target around this date
                    target_scans = [s for s in scan_data if s.get('target') == target]
                    date_scans = [s for s in target_scans if abs((self._parse_date(s.get('started')).date() - date).days) <= 3]
                    
                    if date_scans:
                        # Calculate risk score
                        risk_score = sum((s.get('critical', 0) * 10 + s.get('high', 0) * 7 + 
                                        s.get('medium', 0) * 4 + s.get('low', 0) * 1) for s in date_scans)
                        risk_matrix[i][j] = min(risk_score, 100)
            
            # Create heatmap
            sns.heatmap(risk_matrix, 
                       xticklabels=[d.strftime('%m/%d') for d in dates],
                       yticklabels=targets,
                       cmap='Reds',
                       cbar_kws={'label': 'Risk Score'})
        
        plt.title('Risk Heatmap by Target and Time', fontsize=16, fontweight='bold')
        plt.xlabel('Date', fontsize=12)
        plt.ylabel('Target', fontsize=12)
        plt.xticks(rotation=45)
        plt.yticks(rotation=0)
        plt.tight_layout()
        
        # Convert to base64
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', facecolor='#1a1a1a', edgecolor='none')
        buffer.seek(0)
        chart_data = base64.b64encode(buffer.read()).decode()
        plt.close()
        
        return f"data:image/png;base64,{chart_data}"
    
    def _parse_date(self, date_str: str) -> datetime:
        """Parse date string to datetime object"""
        if isinstance(date_str, datetime):
            return date_str
        
        try:
            return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        except:
            return datetime.now()
    
    def _calculate_scan_duration(self, scan: Dict) -> float:
        """Calculate scan duration in hours"""
        started = scan.get('started')
        completed = scan.get('completed')
        
        if not started or not completed:
            return 0
        
        start_time = self._parse_date(started)
        end_time = self._parse_date(completed)
        duration = (end_time - start_time).total_seconds() / 3600
        
        return max(duration, 0)
    
    def _calculate_risk_reduction(self, scan_data: List[Dict]) -> float:
        """Calculate risk reduction percentage over time"""
        if len(scan_data) < 2:
            return 0
        
        # Sort by date
        sorted_scans = sorted(scan_data, key=lambda x: self._parse_date(x.get('started', '')))
        
        # Compare first and last periods
        first_half = sorted_scans[:len(sorted_scans)//2]
        second_half = sorted_scans[len(sorted_scans)//2:]
        
        first_risk = sum(s.get('critical', 0) * 10 + s.get('high', 0) * 7 for s in first_half)
        second_risk = sum(s.get('critical', 0) * 10 + s.get('high', 0) * 7 for s in second_half)
        
        if first_risk == 0:
            return 0
        
        reduction = ((first_risk - second_risk) / first_risk) * 100
        return max(0, reduction)
    
    def _calculate_risk_velocity(self, risk_scores: List[float]) -> str:
        """Calculate if risk is increasing or decreasing"""
        if len(risk_scores) < 2:
            return 'stable'
        
        recent_avg = np.mean(risk_scores[-5:])  # Last 5 scores
        earlier_avg = np.mean(risk_scores[:-5])  # Earlier scores
        
        if recent_avg > earlier_avg * 1.1:
            return 'increasing'
        elif recent_avg < earlier_avg * 0.9:
            return 'decreasing'
        else:
            return 'stable'
    
    def _load_executive_template(self) -> str:
        """Load executive summary template"""
        return """
        <div class="executive-summary">
            <h1>Executive Security Summary</h1>
            <div class="kpi-grid">
                <div class="kpi-card">
                    <h3>Security Score</h3>
                    <div class="score">{{ security_score }}/100</div>
                </div>
                <div class="kpi-card">
                    <h3>Critical Issues</h3>
                    <div class="critical">{{ critical_count }}</div>
                </div>
                <div class="kpi-card">
                    <h3>Risk Trend</h3>
                    <div class="trend {{ trend_direction }}">{{ trend_text }}</div>
                </div>
            </div>
            <div class="recommendations">
                <h3>Key Recommendations</h3>
                <ul>
                {% for rec in recommendations %}
                    <li>{{ rec }}</li>
                {% endfor %}
                </ul>
            </div>
        </div>
        """
    
    def _load_technical_template(self) -> str:
        """Load technical report template"""
        return """
        <div class="technical-report">
            <h1>Technical Security Assessment</h1>
            <div class="vulnerability-summary">
                {{ vulnerability_table }}
            </div>
            <div class="remediation-plan">
                {{ remediation_plan }}
            </div>
        </div>
        """
    
    def _load_compliance_template(self) -> str:
        """Load compliance report template"""
        return """
        <div class="compliance-report">
            <h1>{{ framework }} Compliance Assessment</h1>
            <div class="compliance-score">
                <h2>Overall Score: {{ compliance_score }}%</h2>
            </div>
            <div class="control-mappings">
                {{ control_table }}
            </div>
        </div>
        """
    
    def _load_trend_template(self) -> str:
        """Load trend analysis template"""
        return """
        <div class="trend-analysis">
            <h1>Security Trends Analysis</h1>
            <div class="charts">
                {{ trend_charts }}
            </div>
        </div>
        """
    
    async def export_report_to_pdf(self, report_data: Dict, report_type: str) -> bytes:
        """Export report to PDF format"""
        # This would use a library like WeasyPrint or ReportLab
        # For now, return placeholder
        return b"PDF report placeholder"
    
    async def export_to_excel(self, vulnerabilities: List[Dict]) -> bytes:
        """Export vulnerability data to Excel format"""
        
        # Create DataFrame
        df = pd.DataFrame(vulnerabilities)
        
        # Create Excel file in memory
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Vulnerabilities', index=False)
            
            # Add summary sheet
            summary_data = {
                'Severity': ['Critical', 'High', 'Medium', 'Low'],
                'Count': [
                    len([v for v in vulnerabilities if v.get('severity') == 'Critical']),
                    len([v for v in vulnerabilities if v.get('severity') == 'High']),
                    len([v for v in vulnerabilities if v.get('severity') == 'Medium']),
                    len([v for v in vulnerabilities if v.get('severity') == 'Low'])
                ]
            }
            summary_df = pd.DataFrame(summary_data)
            summary_df.to_excel(writer, sheet_name='Summary', index=False)
        
        output.seek(0)
        return output.read()
    
    def get_agent_status(self) -> Dict:
        """Get reporting agent status"""
        return {
            'name': 'Advanced Reporting Agent',
            'status': 'active',
            'capabilities': [
                'Executive Dashboards',
                'Technical Reports', 
                'Compliance Mapping',
                'Trend Analysis',
                'Multi-format Export'
            ],
            'report_types': list(self.report_templates.keys()),
            'chart_types': ['trend', 'pie', 'heatmap', 'radar'],
            'export_formats': ['HTML', 'PDF', 'Excel', 'JSON']
        }
