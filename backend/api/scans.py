"""
Scans API router for AI Bug Bounty Scanner
"""

from typing import List, Optional
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, desc
import structlog
import json
import os
from datetime import datetime, timezone
import asyncio

from backend.database import get_db
from backend.models import (
    Scan, ScanCreate, ScanResponse, ScanStatus, ScanType,
    Vulnerability, Report
)
from backend.services.scan_service import ScanService
from backend.services.tool_service import ToolService

logger = structlog.get_logger()
router = APIRouter()

@router.get("/", response_model=List[ScanResponse])
async def get_scans(
    skip: int = 0,
    limit: int = 100,
    status: Optional[ScanStatus] = None,
    db: AsyncSession = Depends(get_db)
):
    """Get all scans with optional filtering"""
    try:
        from sqlalchemy.orm import selectinload
        
        # Eagerly load vulnerabilities to avoid lazy loading issues
        query = select(Scan).options(selectinload(Scan.vulnerabilities)).order_by(desc(Scan.started))

        if status:
            query = query.where(Scan.status == status.value)

        if skip:
            query = query.offset(skip)
        if limit:
            query = query.limit(limit)

        result = await db.execute(query)
        scans = result.scalars().all()

        return [ScanResponse(**scan.to_dict()) for scan in scans]

    except Exception as e:
        logger.error("Failed to get scans", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve scans")

@router.post("/", response_model=ScanResponse)
async def create_scan(
    scan_data: ScanCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    """Create a new scan"""
    try:
        logger.info("Creating scan", target=scan_data.target, scan_type=scan_data.scan_type)

        # Validate target
        if not scan_data.target:
            raise HTTPException(status_code=400, detail="Target is required")

        # Create scan configuration
        agents = scan_data.agents or []
        logger.info("Scan configuration", agents=agents, scan_type=scan_data.scan_type)

        # Convert string to enum for comparison
        try:
            scan_type_enum = ScanType(scan_data.scan_type)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid scan type: {scan_data.scan_type}")

        if scan_type_enum != ScanType.CUSTOM and not agents:
            # Use default agents based on scan type
            if scan_type_enum == ScanType.QUICK:
                agents = ["subfinder", "nuclei"]
            elif scan_type_enum == ScanType.FULL:
                agents = ["subfinder", "amass", "nmap", "nuclei", "sqlmap"]

        logger.info("Final agents list", agents=agents)

        # Create scan record
        try:
            scan = Scan(
                target=scan_data.target,
                scan_type=scan_type_enum.value,
                agents=json.dumps(agents),
                status=ScanStatus.PENDING.value,
                started=datetime.now(timezone.utc)
            )

            logger.info("Created scan object", scan_id=scan.id)
            db.add(scan)

            logger.info("Committing scan to database...")
            await db.commit()

            logger.info("Refreshing scan from database...")
            await db.refresh(scan)

            logger.info("Scan saved to database", scan_id=scan.id, target=scan_data.target)
        except Exception as db_error:
            logger.error("Database operation failed", error=str(db_error))
            raise HTTPException(status_code=500, detail=f"Database error: {str(db_error)}")

        # Eagerly load vulnerabilities for to_dict()
        await db.refresh(scan, ['vulnerabilities'])
        
        # Start scan in background if auto-start is enabled
        if os.getenv("AUTO_START_SCANS", "false").lower() == "true":
            background_tasks.add_task(start_scan_background, scan.id)

        return ScanResponse(**scan.to_dict())

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to create scan", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to create scan")

@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Get a specific scan by ID"""
    try:
        from sqlalchemy.orm import selectinload
        
        # Eagerly load vulnerabilities
        result = await db.execute(
            select(Scan)
            .options(selectinload(Scan.vulnerabilities))
            .where(Scan.id == scan_id)
        )
        scan = result.scalar_one_or_none()

        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        return ScanResponse(**scan.to_dict())

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get scan", scan_id=scan_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve scan")

@router.post("/{scan_id}/start")
async def start_scan(scan_id: str, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    """Start a scan"""
    try:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()

        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        if scan.status == ScanStatus.RUNNING.value:
            raise HTTPException(status_code=400, detail="Scan is already running")

        # Update scan status
        scan.status = ScanStatus.RUNNING.value
        scan.started = datetime.now(timezone.utc)
        await db.commit()

        # Start scan in background with its own session
        background_tasks.add_task(start_scan_background, scan.id)

        logger.info("Started scan", scan_id=scan_id)
        return {
            "message": "Scan started successfully",
            "scan_id": scan_id,
            "status": "running"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to start scan", scan_id=scan_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to start scan")

@router.post("/{scan_id}/stop")
async def stop_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Stop a running scan"""
    try:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()

        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        if scan.status != ScanStatus.RUNNING.value:
            raise HTTPException(status_code=400, detail="Scan is not running")

        # Update scan status to cancelled
        scan.status = ScanStatus.CANCELLED.value
        scan.completed = datetime.now(timezone.utc)
        await db.commit()

        logger.info("Stopped scan", scan_id=scan_id)
        return {
            "message": "Scan stopped successfully",
            "scan_id": scan_id,
            "status": "cancelled"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to stop scan", scan_id=scan_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to stop scan")

@router.delete("/{scan_id}")
async def delete_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Delete a scan"""
    try:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()

        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        await db.delete(scan)
        await db.commit()

        logger.info("Deleted scan", scan_id=scan_id)
        return {"message": "Scan deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to delete scan", scan_id=scan_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to delete scan")

@router.get("/{scan_id}/vulnerabilities", response_model=List[dict])
async def get_scan_vulnerabilities(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Get vulnerabilities for a specific scan"""
    try:
        result = await db.execute(
            select(Vulnerability).where(Vulnerability.scan_id == scan_id)
        )
        vulnerabilities = result.scalars().all()

        return [vuln.to_dict() for vuln in vulnerabilities]

    except Exception as e:
        logger.error("Failed to get scan vulnerabilities", scan_id=scan_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve vulnerabilities")

@router.get("/{scan_id}/reports", response_model=List[dict])
async def get_scan_reports(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Get reports for a specific scan"""
    try:
        result = await db.execute(
            select(Report).where(Report.scan_id == scan_id)
        )
        reports = result.scalars().all()

        return [report.to_dict() for report in reports]

    except Exception as e:
        logger.error("Failed to get scan reports", scan_id=scan_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve reports")

# Background task functions
async def run_scan_async(scan_id: str, db: AsyncSession):
    """Run scan in background task"""
    try:
        scan_service = ScanService()
        await scan_service.run_scan(scan_id, db)
    except Exception as e:
        logger.error("Background scan failed", scan_id=scan_id, error=str(e))
        # Update scan status to failed
        try:
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            if scan:
                scan.status = ScanStatus.FAILED.value
                await db.commit()
        except Exception as update_error:
            logger.error("Failed to update scan status", error=str(update_error))

async def start_scan_background(scan_id: str):
    """Start scan in background task with its own database session"""
    from backend.database import async_session_maker
    
    try:
        # Create a new database session for this background task
        async with async_session_maker() as db:
            await run_scan_async(scan_id, db)
    except Exception as e:
        logger.error("Failed to start background scan", scan_id=scan_id, error=str(e))
