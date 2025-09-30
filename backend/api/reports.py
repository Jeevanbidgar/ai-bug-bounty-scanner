"""
Reports API router for AI Bug Bounty Scanner
"""

from typing import List
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
import structlog

from backend.database import get_db
from backend.models import Report, ReportCreate, ReportResponse, ReportFormat

logger = structlog.get_logger()
router = APIRouter()

@router.get("/", response_model=List[ReportResponse])
async def get_reports(
    skip: int = 0,
    limit: int = 100,
    scan_id: str = None,
    db: AsyncSession = Depends(get_db)
):
    """Get all reports with optional filtering"""
    try:
        query = select(Report).order_by(desc(Report.generated))

        if scan_id:
            query = query.where(Report.scan_id == scan_id)

        if skip:
            query = query.offset(skip)
        if limit:
            query = query.limit(limit)

        result = await db.execute(query)
        reports = result.scalars().all()

        return [ReportResponse(**report.to_dict()) for report in reports]

    except Exception as e:
        logger.error("Failed to get reports", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve reports")

@router.get("/{report_id}")
async def get_report(report_id: str, db: AsyncSession = Depends(get_db)):
    """Get a specific report"""
    try:
        result = await db.execute(select(Report).where(Report.id == report_id))
        report = result.scalar_one_or_none()

        if not report:
            raise HTTPException(status_code=404, detail="Report not found")

        # Return report with additional details
        report_data = report.to_dict()
        report_data['content'] = report.content

        return report_data

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get report", report_id=report_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve report")

@router.post("/")
async def create_report(
    report_data: ReportCreate,
    db: AsyncSession = Depends(get_db)
):
    """Create a new report"""
    try:
        from backend.models import Scan

        # Verify scan exists
        result = await db.execute(select(Scan).where(Scan.id == report_data.scan_id))
        scan = result.scalar_one_or_none()

        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Generate report content (placeholder for now)
        report_content = await generate_report_content(scan, report_data.format)

        # Create report record
        report = Report(
            scan_id=report_data.scan_id,
            title=report_data.title or f"Security Report - {scan.target}",
            format=report_data.format.value,
            content=report_content,
            summary=f"Security assessment report for {scan.target}"
        )

        db.add(report)
        await db.commit()
        await db.refresh(report)

        logger.info("Created report", report_id=report.id, scan_id=report_data.scan_id)

        return ReportResponse(**report.to_dict())

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to create report", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to create report")

@router.get("/{report_id}/download")
async def download_report(report_id: str, db: AsyncSession = Depends(get_db)):
    """Download a report file"""
    try:
        result = await db.execute(select(Report).where(Report.id == report_id))
        report = result.scalar_one_or_none()

        if not report:
            raise HTTPException(status_code=404, detail="Report not found")

        # For now, return the content as JSON
        # In production, this would return the actual file
        if report.file_path and os.path.exists(report.file_path):
            return FileResponse(
                report.file_path,
                media_type='application/octet-stream',
                filename=f"security_report_{report_id}.{report.format.lower()}"
            )
        else:
            # Return content as JSON if no file exists
            return {
                "report_id": report_id,
                "title": report.title,
                "content": report.content,
                "format": report.format,
                "generated": report.generated.isoformat()
            }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to download report", report_id=report_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to download report")

@router.delete("/{report_id}")
async def delete_report(report_id: str, db: AsyncSession = Depends(get_db)):
    """Delete a report"""
    try:
        result = await db.execute(select(Report).where(Report.id == report_id))
        report = result.scalar_one_or_none()

        if not report:
            raise HTTPException(status_code=404, detail="Report not found")

        # Delete file if it exists
        if report.file_path and os.path.exists(report.file_path):
            try:
                os.remove(report.file_path)
            except Exception as e:
                logger.warning("Failed to delete report file", file_path=report.file_path, error=str(e))

        await db.delete(report)
        await db.commit()

        logger.info("Deleted report", report_id=report_id)
        return {"message": "Report deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to delete report", report_id=report_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to delete report")

async def generate_report_content(scan, format: ReportFormat) -> str:
    """Generate report content based on scan data and format"""
    try:
        from backend.models import Vulnerability

        # Get scan vulnerabilities
        from sqlalchemy import select
        result = await db.execute(
            select(Vulnerability).where(Vulnerability.scan_id == scan.id)
        )
        vulnerabilities = result.scalars().all()

        if format == ReportFormat.JSON:
            return json.dumps({
                "scan": scan.to_dict(),
                "vulnerabilities": [v.to_dict() for v in vulnerabilities],
                "summary": {
                    "total_vulnerabilities": len(vulnerabilities),
                    "severity_breakdown": {
                        "critical": sum(1 for v in vulnerabilities if v.severity == "Critical"),
                        "high": sum(1 for v in vulnerabilities if v.severity == "High"),
                        "medium": sum(1 for v in vulnerabilities if v.severity == "Medium"),
                        "low": sum(1 for v in vulnerabilities if v.severity == "Low")
                    }
                }
            }, indent=2)

        elif format == ReportFormat.HTML:
            # Generate HTML report
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Security Report - {scan.target}</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 40px; }}
                    .header {{ background: #f5f5f5; padding: 20px; border-radius: 5px; }}
                    .vulnerability {{ margin: 20px 0; padding: 15px; border-left: 4px solid #007cba; }}
                    .critical {{ border-color: #dc3545; }}
                    .high {{ border-color: #fd7e14; }}
                    .medium {{ border-color: #ffc107; }}
                    .low {{ border-color: #28a745; }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>Security Assessment Report</h1>
                    <h2>Target: {scan.target}</h2>
                    <p><strong>Scan Date:</strong> {scan.started.strftime('%Y-%m-%d %H:%M:%S')}</p>
                    <p><strong>Scan Type:</strong> {scan.scan_type}</p>
                    <p><strong>Total Vulnerabilities:</strong> {len(vulnerabilities)}</p>
                </div>
            """

            for vuln in vulnerabilities:
                severity_class = vuln.severity.lower()
                html_content += f"""
                <div class="vulnerability {severity_class}">
                    <h3>{vuln.title}</h3>
                    <p><strong>Severity:</strong> {vuln.severity}</p>
                    <p><strong>CVSS Score:</strong> {vuln.cvss or 'N/A'}</p>
                    <p>{vuln.description}</p>
                    {f'<p><strong>URL:</strong> {vuln.url}</p>' if vuln.url else ''}
                    {f'<p><strong>Remediation:</strong> {vuln.remediation}</p>' if vuln.remediation else ''}
                </div>
                """

            html_content += "</body></html>"
            return html_content

        else:
            # Default to simple text format
            content = f"""
Security Assessment Report
========================

Target: {scan.target}
Scan Date: {scan.started.strftime('%Y-%m-%d %H:%M:%S')}
Scan Type: {scan.scan_type}
Total Vulnerabilities: {len(vulnerabilities)}

Vulnerabilities:
"""
            for vuln in vulnerabilities:
                content += f"""
- {vuln.title} ({vuln.severity})
  {vuln.description}
  {'URL: ' + vuln.url if vuln.url else ''}
  {'Remediation: ' + vuln.remediation if vuln.remediation else ''}
"""

            return content

    except Exception as e:
        logger.error("Failed to generate report content", error=str(e))
        return f"Error generating report content: {str(e)}"
