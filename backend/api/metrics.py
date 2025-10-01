"""
Metrics API endpoint for Prometheus scraping and system statistics.
"""

from fastapi import APIRouter, Response, Depends
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
import structlog
from typing import Dict, Any

from backend.database import get_db
from backend.models import Scan, Vulnerability, ScanStatus
from backend.tool_discovery import tool_discovery_service

logger = structlog.get_logger(__name__)

router = APIRouter()


@router.get("/metrics")
async def prometheus_metrics():
    """
    Prometheus metrics endpoint.
    Returns metrics in Prometheus text format for scraping.
    """
    try:
        metrics_data = generate_latest()
        return Response(content=metrics_data, media_type=CONTENT_TYPE_LATEST)
    except Exception as e:
        logger.error("metrics_endpoint_error", error=str(e))
        return Response(content="", media_type=CONTENT_TYPE_LATEST, status_code=500)


@router.get("/")
async def get_system_metrics(db: AsyncSession = Depends(get_db)) -> Dict[str, Any]:
    """
    Get system metrics and statistics.
    Returns comprehensive system health and activity metrics.
    """
    try:
        # Get scan statistics
        total_scans_result = await db.execute(select(func.count(Scan.id)))
        total_scans = total_scans_result.scalar() or 0
        
        active_scans_result = await db.execute(
            select(func.count(Scan.id)).where(Scan.status == ScanStatus.RUNNING.value)
        )
        active_scans = active_scans_result.scalar() or 0
        
        # Get vulnerability statistics
        total_vulns_result = await db.execute(select(func.count(Vulnerability.id)))
        total_vulnerabilities = total_vulns_result.scalar() or 0
        
        critical_vulns_result = await db.execute(
            select(func.count(Vulnerability.id)).where(Vulnerability.severity == 'Critical')
        )
        critical_issues = critical_vulns_result.scalar() or 0
        
        # Get tool availability
        tools = await tool_discovery_service.list_tools()
        tools_available = sum(1 for tool in tools if tool.installed)
        tools_total = len(tools)
        
        # Determine system health
        health_status = "healthy"
        if active_scans > 10:
            health_status = "degraded"
        elif tools_available < (tools_total * 0.5):
            health_status = "warning"
        
        return {
            "total_scans": total_scans,
            "active_scans": active_scans,
            "completed_scans": total_scans - active_scans,
            "total_vulnerabilities": total_vulnerabilities,
            "critical_issues": critical_issues,
            "tools_available": tools_available,
            "tools_total": tools_total,
            "tools_unavailable": tools_total - tools_available,
            "system_health": health_status,
            "health_details": {
                "scan_capacity": f"{active_scans}/10",
                "tool_availability": f"{tools_available}/{tools_total}",
                "database": "connected"
            }
        }
        
    except Exception as e:
        logger.error("Failed to get system metrics", error=str(e))
        return {
            "total_scans": 0,
            "active_scans": 0,
            "total_vulnerabilities": 0,
            "critical_issues": 0,
            "tools_available": 0,
            "system_health": "error",
            "error": str(e)
        }
