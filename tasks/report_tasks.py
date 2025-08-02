# tasks/report_tasks.py - Asynchronous Report Generation
"""
Celery tasks for report generation and export operations
Handles PDF, JSON, and Markdown report generation
"""

import os
import sys
import json
import tempfile
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from celery import current_task
from celery.utils.log import get_task_logger

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from core.celery_app import celery_app
from database.models import Scan, Vulnerability, Report
from database.database import get_db_session

# Setup logging
logger = get_task_logger(__name__)


@celery_app.task(bind=True, name='tasks.report_tasks.generate_report')
def generate_report(self, scan_id: int, report_format: str = 'json', options: Dict[str, Any] = None):
    """
    Generate a comprehensive vulnerability report
    
    Args:
        scan_id: Database ID of the scan
        report_format: Format of the report (json, markdown, pdf)
        options: Additional report options
    """
    options = options or {}
    
    try:
        logger.info(f"Generating {report_format} report for scan {scan_id}")
        
        self.update_state(
            state='PROGRESS',
            meta={'status': f'Generating {report_format} report', 'format': report_format}
        )
        
        with get_db_session() as session:
            # Get scan and vulnerabilities
            scan = session.query(Scan).get(scan_id)
            if not scan:
                raise ValueError(f"Scan {scan_id} not found")
            
            vulnerabilities = session.query(Vulnerability).filter(
                Vulnerability.scan_id == scan_id
            ).all()
            
            # Generate report content
            report_data = generate_report_data(scan, vulnerabilities, options)
            
            # Format report based on type
            if report_format == 'json':
                content = generate_json_report(report_data)
                content_type = 'application/json'
                
            elif report_format == 'markdown':
                content = generate_markdown_report(report_data)
                content_type = 'text/markdown'
                
            elif report_format == 'pdf':
                content = generate_pdf_report(report_data)
                content_type = 'application/pdf'
                
            else:
                raise ValueError(f"Unsupported report format: {report_format}")
            
            # Save report to database
            report = Report(
                scan_id=scan_id,
                format=report_format,
                content=content if report_format != 'pdf' else None,  # Don't store PDF in DB
                file_path=None,  # Will be set if saved to file
                generated_at=datetime.now(timezone.utc),
                metadata=json.dumps({
                    'total_vulnerabilities': len(vulnerabilities),
                    'severity_breakdown': get_severity_breakdown(vulnerabilities),
                    'scan_duration': str(scan.completed_at - scan.started_at) if scan.completed_at and scan.started_at else None,
                    'options': options
                })
            )
            session.add(report)
            session.commit()
            
            logger.info(f"Report generated successfully for scan {scan_id}")
            
            return {
                'report_id': report.id,
                'scan_id': scan_id,
                'format': report_format,
                'content_type': content_type,
                'size': len(content) if isinstance(content, (str, bytes)) else 0,
                'generated_at': report.generated_at.isoformat()
            }
            
    except Exception as e:
        logger.error(f"Report generation failed for scan {scan_id}: {str(e)}")
        
        self.update_state(
            state='FAILURE',
            meta={'error': str(e), 'scan_id': scan_id, 'format': report_format}
        )
        
        raise


@celery_app.task(bind=True, name='tasks.report_tasks.export_report')
def export_report(self, report_id: int, export_path: str = None):
    """
    Export a report to file system
    
    Args:
        report_id: Database ID of the report
        export_path: Path to save the report (optional)
    """
    try:
        logger.info(f"Exporting report {report_id}")
        
        self.update_state(
            state='PROGRESS',
            meta={'status': 'Exporting report', 'report_id': report_id}
        )
        
        with get_db_session() as session:
            report = session.query(Report).get(report_id)
            if not report:
                raise ValueError(f"Report {report_id} not found")
            
            # Determine export path
            if not export_path:
                export_dir = os.path.join(project_root, 'exports')
                os.makedirs(export_dir, exist_ok=True)
                
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"scan_{report.scan_id}_report_{timestamp}.{report.format}"
                export_path = os.path.join(export_dir, filename)
            
            # Write file
            if report.format == 'pdf':
                # For PDF, we need to regenerate content if not stored
                if not report.content:
                    scan = session.query(Scan).get(report.scan_id)
                    vulnerabilities = session.query(Vulnerability).filter(
                        Vulnerability.scan_id == report.scan_id
                    ).all()
                    report_data = generate_report_data(scan, vulnerabilities, {})
                    content = generate_pdf_report(report_data)
                else:
                    content = report.content
                
                with open(export_path, 'wb') as f:
                    f.write(content)
            else:
                with open(export_path, 'w', encoding='utf-8') as f:
                    f.write(report.content)
            
            # Update report with file path
            report.file_path = export_path
            session.commit()
            
            logger.info(f"Report exported to: {export_path}")
            
            return {
                'report_id': report_id,
                'export_path': export_path,
                'file_size': os.path.getsize(export_path)
            }
            
    except Exception as e:
        logger.error(f"Report export failed for report {report_id}: {str(e)}")
        
        self.update_state(
            state='FAILURE',
            meta={'error': str(e), 'report_id': report_id}
        )
        
        raise


def generate_report_data(scan, vulnerabilities, options):
    """Generate comprehensive report data structure"""
    
    # Group vulnerabilities by severity
    severity_groups = {}
    for vuln in vulnerabilities:
        severity = vuln.severity or 'info'
        if severity not in severity_groups:
            severity_groups[severity] = []
        severity_groups[severity].append(vuln)
    
    # Calculate statistics
    total_vulns = len(vulnerabilities)
    severity_counts = {sev: len(vulns) for sev, vulns in severity_groups.items()}
    
    return {
        'scan': {
            'id': scan.id,
            'target': scan.target,
            'scan_types': scan.scan_types,
            'status': scan.status,
            'started_at': scan.started_at.isoformat() if scan.started_at else None,
            'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
            'duration': str(scan.completed_at - scan.started_at) if scan.completed_at and scan.started_at else None
        },
        'summary': {
            'total_vulnerabilities': total_vulns,
            'severity_breakdown': severity_counts,
            'scan_types_used': scan.scan_types
        },
        'vulnerabilities': [
            {
                'id': vuln.id,
                'title': vuln.title,
                'description': vuln.description,
                'severity': vuln.severity,
                'type': vuln.type,
                'url': vuln.url,
                'payload': vuln.payload,
                'evidence': json.loads(vuln.evidence) if vuln.evidence else {},
                'recommendation': vuln.recommendation,
                'cve_id': vuln.cve_id,
                'cvss_score': vuln.cvss_score,
                'discovered_at': vuln.discovered_at.isoformat() if vuln.discovered_at else None
            }
            for vuln in vulnerabilities
        ],
        'severity_groups': {
            sev: [
                {
                    'title': vuln.title,
                    'description': vuln.description,
                    'url': vuln.url,
                    'type': vuln.type,
                    'recommendation': vuln.recommendation
                }
                for vuln in vulns
            ]
            for sev, vulns in severity_groups.items()
        },
        'metadata': {
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'generator': 'AI Bug Bounty Scanner',
            'version': '2.0'
        }
    }


def generate_json_report(report_data):
    """Generate JSON format report"""
    return json.dumps(report_data, indent=2)


def generate_markdown_report(report_data):
    """Generate Markdown format report"""
    
    md = f"""# Vulnerability Scan Report

## Scan Summary
- **Target**: {report_data['scan']['target']}
- **Scan ID**: {report_data['scan']['id']}
- **Status**: {report_data['scan']['status']}
- **Started**: {report_data['scan']['started_at']}
- **Completed**: {report_data['scan']['completed_at']}
- **Duration**: {report_data['scan']['duration']}

## Vulnerability Summary
- **Total Vulnerabilities**: {report_data['summary']['total_vulnerabilities']}

### Severity Breakdown
"""
    
    # Add severity breakdown
    for severity, count in report_data['summary']['severity_breakdown'].items():
        md += f"- **{severity.title()}**: {count}\n"
    
    md += "\n## Scan Types Used\n"
    for scan_type in report_data['summary']['scan_types_used']:
        md += f"- {scan_type}\n"
    
    # Add vulnerabilities by severity
    for severity in ['critical', 'high', 'medium', 'low', 'info']:
        if severity in report_data['severity_groups'] and report_data['severity_groups'][severity]:
            md += f"\n## {severity.title()} Severity Vulnerabilities\n\n"
            
            for vuln in report_data['severity_groups'][severity]:
                md += f"### {vuln['title']}\n\n"
                md += f"**URL**: {vuln['url']}\n\n"
                md += f"**Type**: {vuln['type']}\n\n"
                md += f"**Description**: {vuln['description']}\n\n"
                
                if vuln['recommendation']:
                    md += f"**Recommendation**: {vuln['recommendation']}\n\n"
                
                md += "---\n\n"
    
    md += f"\n---\n*Report generated on {report_data['metadata']['generated_at']} by {report_data['metadata']['generator']}*"
    
    return md


def generate_pdf_report(report_data):
    """Generate PDF format report using reportlab"""
    try:
        from reportlab.lib.pagesizes import letter, A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib import colors
        from io import BytesIO
        
        buffer = BytesIO()
        
        # Create PDF document
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.darkblue
        )
        story.append(Paragraph("Vulnerability Scan Report", title_style))
        story.append(Spacer(1, 20))
        
        # Scan summary
        story.append(Paragraph("Scan Summary", styles['Heading2']))
        summary_data = [
            ['Target', report_data['scan']['target']],
            ['Scan ID', str(report_data['scan']['id'])],
            ['Status', report_data['scan']['status']],
            ['Started', report_data['scan']['started_at'] or 'N/A'],
            ['Completed', report_data['scan']['completed_at'] or 'N/A'],
            ['Duration', report_data['scan']['duration'] or 'N/A']
        ]
        
        summary_table = Table(summary_data, colWidths=[2*inch, 4*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 20))
        
        # Vulnerability summary
        story.append(Paragraph("Vulnerability Summary", styles['Heading2']))
        story.append(Paragraph(f"Total Vulnerabilities Found: {report_data['summary']['total_vulnerabilities']}", styles['Normal']))
        story.append(Spacer(1, 10))
        
        # Severity breakdown
        severity_data = [['Severity', 'Count']]
        for severity, count in report_data['summary']['severity_breakdown'].items():
            severity_data.append([severity.title(), str(count)])
        
        severity_table = Table(severity_data, colWidths=[2*inch, 1*inch])
        severity_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(severity_table)
        story.append(Spacer(1, 20))
        
        # Detailed vulnerabilities
        story.append(Paragraph("Detailed Vulnerabilities", styles['Heading2']))
        
        for vuln in report_data['vulnerabilities']:
            story.append(Paragraph(f"Title: {vuln['title']}", styles['Heading3']))
            story.append(Paragraph(f"Severity: {vuln['severity'].title()}", styles['Normal']))
            story.append(Paragraph(f"URL: {vuln['url']}", styles['Normal']))
            story.append(Paragraph(f"Type: {vuln['type']}", styles['Normal']))
            story.append(Paragraph(f"Description: {vuln['description']}", styles['Normal']))
            
            if vuln['recommendation']:
                story.append(Paragraph(f"Recommendation: {vuln['recommendation']}", styles['Normal']))
            
            story.append(Spacer(1, 15))
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()
        
    except ImportError:
        # Fallback if reportlab is not installed
        logger.warning("reportlab not installed, generating simple PDF")
        return generate_simple_pdf(report_data)


def generate_simple_pdf(report_data):
    """Generate a simple PDF without reportlab"""
    # This is a placeholder - in production, you'd want to ensure reportlab is installed
    # or use another PDF generation library
    content = f"""
VULNERABILITY SCAN REPORT

Target: {report_data['scan']['target']}
Scan ID: {report_data['scan']['id']}
Total Vulnerabilities: {report_data['summary']['total_vulnerabilities']}

Generated: {report_data['metadata']['generated_at']}
"""
    return content.encode('utf-8')


def get_severity_breakdown(vulnerabilities):
    """Get vulnerability count by severity"""
    breakdown = {}
    for vuln in vulnerabilities:
        severity = vuln.severity or 'info'
        breakdown[severity] = breakdown.get(severity, 0) + 1
    return breakdown
