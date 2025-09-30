"""
Dramatiq tasks for background processing

This module defines all background tasks that can be executed
asynchronously using the Dramatiq task queue.
"""

import asyncio
import json
import os
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
import structlog

import dramatiq
from dramatiq.brokers.redis import RedisBroker
from dramatiq.results import Results
from dramatiq.results.backends.redis import RedisBackend

# Configure structured logging
logger = structlog.get_logger()

# Configure Redis broker
redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
broker = RedisBroker(url=redis_url)
dramatiq.set_broker(broker)

# Configure results backend
results_backend = RedisBackend(url=redis_url)
dramatiq.set_results_backend(results_backend)

# Set actor options
dramatiq.set_encoder(json.JSONEncoder)
dramatiq.set_decoder(json.JSONDecoder)

@dramatiq.actor(queue_name="scans", max_retries=3, time_limit=3600000)  # 1 hour timeout
def execute_scan_task(scan_id: str, target: str, scan_type: str, agents: List[str]):
    """Execute a security scan as a background task"""
    try:
        logger.info("Starting scan task", scan_id=scan_id, target=target)

        # Import here to avoid circular imports
        from backend.services.scan_service import ScanService
        from backend.database import async_session_maker

        async def run_scan():
            async with async_session_maker() as session:
                scan_service = ScanService()
                await scan_service.run_scan(scan_id, session)

        # Run the async scan
        asyncio.run(run_scan())

        logger.info("Scan task completed", scan_id=scan_id)
        return {"status": "completed", "scan_id": scan_id}

    except Exception as e:
        logger.error("Scan task failed", scan_id=scan_id, error=str(e))
        raise

@dramatiq.actor(queue_name="tools", max_retries=2, time_limit=1800000)  # 30 min timeout
def execute_tool_task(tool_name: str, target: str, **kwargs):
    """Execute a single security tool as a background task"""
    try:
        logger.info("Starting tool task", tool=tool_name, target=target)

        # Import here to avoid circular imports
        from backend.services.tool_service import ToolService

        async def run_tool():
            tool_service = ToolService()
            result = await tool_service.run_tool(tool_name, target, **kwargs)
            return result

        # Run the tool
        result = asyncio.run(run_tool())

        logger.info("Tool task completed", tool=tool_name, success=result.get('success', False))
        return result

    except Exception as e:
        logger.error("Tool task failed", tool=tool_name, error=str(e))
        raise

@dramatiq.actor(queue_name="recon", max_retries=2, time_limit=7200000)  # 2 hour timeout
def execute_recon_plan_task(plan_data: Dict[str, Any], target: str):
    """Execute a complete reconnaissance plan as a background task"""
    try:
        logger.info("Starting recon plan task", target=target, plan=plan_data.get('name'))

        # Import here to avoid circular imports
        from backend.adapters.adapter_manager import AdapterManager

        async def run_recon():
            adapter_manager = AdapterManager()
            result = await adapter_manager.execute_recon_plan(plan_data, target)
            return result

        # Run the reconnaissance plan
        result = asyncio.run(run_recon())

        logger.info("Recon plan task completed", target=target, phases=len(result.get('phases', [])))
        return result

    except Exception as e:
        logger.error("Recon plan task failed", target=target, error=str(e))
        raise

@dramatiq.actor(queue_name="reports", max_retries=1, time_limit=600000)  # 10 min timeout
def generate_report_task(scan_id: str, report_format: str = "html", title: Optional[str] = None):
    """Generate a security report as a background task"""
    try:
        logger.info("Starting report generation", scan_id=scan_id, format=report_format)

        # Import here to avoid circular imports
        from backend.database import async_session_maker
        from backend.models import Scan, Report

        async def generate_report():
            async with async_session_maker() as session:
                # Get scan data
                from sqlalchemy import select
                result = await session.execute(select(Scan).where(Scan.id == scan_id))
                scan = result.scalar_one_or_none()

                if not scan:
                    raise ValueError(f"Scan not found: {scan_id}")

                # Generate report content
                report_content = await _generate_report_content(scan, report_format, session)

                # Create report record
                report = Report(
                    scan_id=scan_id,
                    title=title or f"Security Report - {scan.target}",
                    format=report_format.upper(),
                    content=report_content,
                    summary=f"Generated {report_format} report for {scan.target}"
                )

                session.add(report)
                await session.commit()

                return report.id

        # Generate the report
        report_id = asyncio.run(generate_report())

        logger.info("Report generation completed", scan_id=scan_id, report_id=report_id)
        return {"status": "completed", "report_id": report_id}

    except Exception as e:
        logger.error("Report generation failed", scan_id=scan_id, error=str(e))
        raise

@dramatiq.actor(queue_name="cleanup", max_retries=3, time_limit=300000)  # 5 min timeout
def cleanup_old_scans_task(days_old: int = 30):
    """Clean up old scan data as a background task"""
    try:
        logger.info("Starting cleanup task", days_old=days_old)

        # Import here to avoid circular imports
        from backend.database import async_session_maker
        from backend.models import Scan
        from datetime import datetime, timedelta
        from sqlalchemy import select, delete

        async def cleanup():
            async with async_session_maker() as session:
                # Calculate cutoff date
                cutoff_date = datetime.now() - timedelta(days=days_old)

                # Find old scans
                result = await session.execute(
                    select(Scan).where(Scan.started < cutoff_date)
                )
                old_scans = result.scalars().all()

                deleted_count = 0
                for scan in old_scans:
                    await session.delete(scan)
                    deleted_count += 1

                await session.commit()

                return deleted_count

        # Run cleanup
        deleted_count = asyncio.run(cleanup())

        logger.info("Cleanup completed", deleted_scans=deleted_count)
        return {"status": "completed", "deleted_scans": deleted_count}

    except Exception as e:
        logger.error("Cleanup task failed", error=str(e))
        raise

async def _generate_report_content(scan, report_format: str, session) -> str:
    """Generate report content based on scan data"""
    try:
        from backend.models import Vulnerability
        from sqlalchemy import select

        # Get scan vulnerabilities
        result = await session.execute(
            select(Vulnerability).where(Vulnerability.scan_id == scan.id)
        )
        vulnerabilities = result.scalars().all()

        if report_format.lower() == "json":
            return json.dumps({
                "scan": {
                    "id": scan.id,
                    "target": scan.target,
                    "scan_type": scan.scan_type,
                    "started": scan.started.isoformat() if scan.started else None,
                    "completed": scan.completed.isoformat() if scan.completed else None,
                    "status": scan.status
                },
                "vulnerabilities": [
                    {
                        "id": v.id,
                        "title": v.title,
                        "severity": v.severity,
                        "cvss": v.cvss,
                        "description": v.description,
                        "url": v.url,
                        "discovered_by": v.discovered_by
                    }
                    for v in vulnerabilities
                ],
                "summary": {
                    "total_vulnerabilities": len(vulnerabilities),
                    "severity_breakdown": {
                        "critical": sum(1 for v in vulnerabilities if v.severity.lower() == "critical"),
                        "high": sum(1 for v in vulnerabilities if v.severity.lower() == "high"),
                        "medium": sum(1 for v in vulnerabilities if v.severity.lower() == "medium"),
                        "low": sum(1 for v in vulnerabilities if v.severity.lower() == "low")
                    }
                }
            }, indent=2)

        elif report_format.lower() == "html":
            # Generate HTML report
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Security Report - {scan.target}</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
                    .header {{ background: #f5f5f5; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
                    .vulnerability {{ margin: 20px 0; padding: 15px; border-left: 4px solid #007cba; background: #f9f9f9; }}
                    .severity-critical {{ border-color: #dc3545; background: #fff5f5; }}
                    .severity-high {{ border-color: #fd7e14; background: #fff8f0; }}
                    .severity-medium {{ border-color: #ffc107; background: #fffef0; }}
                    .severity-low {{ border-color: #28a745; background: #f0fff4; }}
                    .summary {{ background: #e7f3ff; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>Security Assessment Report</h1>
                    <h2>Target: {scan.target}</h2>
                    <p><strong>Scan Date:</strong> {scan.started.strftime('%Y-%m-%d %H:%M:%S') if scan.started else 'Unknown'}</p>
                    <p><strong>Scan Type:</strong> {scan.scan_type}</p>
                    <p><strong>Status:</strong> {scan.status}</p>
                </div>

                <div class="summary">
                    <h3>Summary</h3>
                    <p><strong>Total Vulnerabilities:</strong> {len(vulnerabilities)}</p>
                    <p><strong>Critical Issues:</strong> {sum(1 for v in vulnerabilities if v.severity.lower() == 'critical')}</p>
                    <p><strong>High Severity:</strong> {sum(1 for v in vulnerabilities if v.severity.lower() == 'high')}</p>
                    <p><strong>Medium Severity:</strong> {sum(1 for v in vulnerabilities if v.severity.lower() == 'medium')}</p>
                    <p><strong>Low Severity:</strong> {sum(1 for v in vulnerabilities if v.severity.lower() == 'low')}</p>
                </div>
            """

            for vuln in vulnerabilities:
                severity_class = f"severity-{vuln.severity.lower()}"
                html_content += f"""
                <div class="vulnerability {severity_class}">
                    <h4>{vuln.title}</h4>
                    <p><strong>Severity:</strong> {vuln.severity}</p>
                    <p><strong>CVSS Score:</strong> {vuln.cvss or 'N/A'}</p>
                    <p>{vuln.description}</p>
                    {f'<p><strong>URL:</strong> {vuln.url}</p>' if vuln.url else ''}
                    {f'<p><strong>Discovered by:</strong> {vuln.discovered_by}</p>' if vuln.discovered_by else ''}
                </div>
                """

            html_content += "</body></html>"
            return html_content

        else:
            # Default to text format
            content = f"""
Security Assessment Report
========================

Target: {scan.target}
Scan Date: {scan.started.strftime('%Y-%m-%d %H:%M:%S') if scan.started else 'Unknown'}
Scan Type: {scan.scan_type}
Status: {scan.status}

Summary:
--------
Total Vulnerabilities: {len(vulnerabilities)}
Critical Issues: {sum(1 for v in vulnerabilities if v.severity.lower() == 'critical')}
High Severity: {sum(1 for v in vulnerabilities if v.severity.lower() == 'high')}
Medium Severity: {sum(1 for v in vulnerabilities if v.severity.lower() == 'medium')}
Low Severity: {sum(1 for v in vulnerabilities if v.severity.lower() == 'low')}

Vulnerabilities:
---------------
"""
            for vuln in vulnerabilities:
                content += f"""
{vuln.title} ({vuln.severity})
  CVSS: {vuln.cvss or 'N/A'}
  Description: {vuln.description}
  {'URL: ' + vuln.url if vuln.url else ''}
  {'Discovered by: ' + vuln.discovered_by if vuln.discovered_by else ''}
"""

            return content

    except Exception as e:
        logger.error("Failed to generate report content", error=str(e))
        return f"Error generating report content: {str(e)}"

# Task status checking functions
def get_task_status(message_id: str) -> Optional[Dict[str, Any]]:
    """Get the status of a task by message ID"""
    try:
        result = dramatiq.results.backend.get_result(message_id)
        if result:
            return {
                "status": "completed",
                "result": result
            }
        else:
            # Check if task is still pending/failed
            return {
                "status": "pending"
            }
    except Exception:
        return {
            "status": "failed",
            "error": "Task not found or failed"
        }

def get_queue_stats() -> Dict[str, Any]:
    """Get queue statistics"""
    try:
        # Get queue lengths
        queue_lengths = {}
        for queue_name in ['scans', 'tools', 'recon', 'reports', 'cleanup']:
            try:
                length = broker.get_queue(queue_name).length()
                queue_lengths[queue_name] = length
            except:
                queue_lengths[queue_name] = 0

        return {
            "queues": queue_lengths,
            "total_pending": sum(queue_lengths.values()),
            "redis_connected": True
        }
    except Exception as e:
        return {
            "error": str(e),
            "redis_connected": False
        }
