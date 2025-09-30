"""
Health check API router
"""

from datetime import datetime
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func, select
import structlog

from backend.database import get_db
from backend.models import SystemStats, Scan, Vulnerability, Tool

logger = structlog.get_logger()
router = APIRouter()

@router.get("/")
async def health_check():
    """Basic health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "ai-bug-bounty-scanner-api"
    }

@router.get("/detailed", response_model=SystemStats)
async def detailed_health_check(db: AsyncSession = Depends(get_db)):
    """Detailed health check with system statistics"""
    try:
        # Get scan statistics
        total_scans_result = await db.execute(
            select(func.count(Scan.id))
        )
        total_scans = total_scans_result.scalar()

        active_scans_result = await db.execute(
            select(func.count(Scan.id)).where(Scan.status == "running")
        )
        active_scans = active_scans_result.scalar()

        # Get vulnerability statistics
        total_vulns_result = await db.execute(
            select(func.count(Vulnerability.id))
        )
        total_vulnerabilities = total_vulns_result.scalar()

        critical_issues_result = await db.execute(
            select(func.count(Vulnerability.id)).where(
                Vulnerability.severity == "Critical"
            )
        )
        critical_issues = critical_issues_result.scalar()

        # Get tool statistics
        tools_result = await db.execute(
            select(func.count(Tool.id))
        )
        tools_available = tools_result.scalar()

        # Determine system health
        if critical_issues > 10:
            system_health = "critical"
        elif active_scans > 5:
            system_health = "busy"
        elif total_scans == 0:
            system_health = "new"
        else:
            system_health = "healthy"

        return SystemStats(
            total_scans=total_scans,
            active_scans=active_scans,
            total_vulnerabilities=total_vulnerabilities,
            critical_issues=critical_issues,
            tools_available=tools_available,
            system_health=system_health
        )

    except Exception as e:
        logger.error("Failed to get detailed health stats", error=str(e))
        # Return basic stats on error
        return SystemStats(
            total_scans=0,
            active_scans=0,
            total_vulnerabilities=0,
            critical_issues=0,
            tools_available=0,
            system_health="error"
        )
