"""
Recon API router for AI Bug Bounty Scanner
"""

from typing import List, Dict, Any
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import structlog

from backend.database import get_db
from backend.models import ReconPlan, ReconPlanResponse
from backend.services.recon_service import ReconService

logger = structlog.get_logger()
router = APIRouter()

@router.get("/plans", response_model=List[ReconPlanResponse])
async def get_recon_plans(db: AsyncSession = Depends(get_db)):
    """Get all reconnaissance plans"""
    try:
        result = await db.execute(select(ReconPlan))
        plans = result.scalars().all()

        return [ReconPlanResponse(**plan.to_dict()) for plan in plans]

    except Exception as e:
        logger.error("Failed to get recon plans", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve recon plans")

@router.get("/plans/{plan_id}")
async def get_recon_plan(plan_id: str, db: AsyncSession = Depends(get_db)):
    """Get a specific reconnaissance plan"""
    try:
        result = await db.execute(select(ReconPlan).where(ReconPlan.id == plan_id))
        plan = result.scalar_one_or_none()

        if not plan:
            raise HTTPException(status_code=404, detail="Recon plan not found")

        return ReconPlanResponse(**plan.to_dict())

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get recon plan", plan_id=plan_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve recon plan")

@router.get("/templates")
async def get_recon_templates():
    """Get available reconnaissance plan templates"""
    try:
        recon_service = ReconService()
        templates = recon_service.get_builtin_templates()

        return {
            "templates": [
                {
                    "name": name,
                    "description": template.description,
                    "target_type": template.target_type,
                    "phases": len(template.phases),
                    "estimated_duration": template.estimated_duration
                }
                for name, template in templates.items()
            ]
        }

    except Exception as e:
        logger.error("Failed to get recon templates", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve templates")

@router.post("/plans/generate")
async def generate_recon_plan(request: Dict[str, Any]):
    """Generate a reconnaissance plan for a target"""
    try:
        target = request.get("target")
        template_name = request.get("template", "auto")

        if not target:
            raise HTTPException(status_code=400, detail="Target is required")

        recon_service = ReconService()
        plan = recon_service.generate_plan_for_target(target, template_name)

        if not plan:
            raise HTTPException(status_code=400, detail="Could not generate plan for target")

        return {
            "plan": plan.to_dict(),
            "generated_for": target
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to generate recon plan", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to generate recon plan")

@router.post("/plans/{plan_id}/execute")
async def execute_recon_plan(plan_id: str, request: Dict[str, Any], db: AsyncSession = Depends(get_db)):
    """Execute a reconnaissance plan"""
    try:
        # Get the plan
        result = await db.execute(select(ReconPlan).where(ReconPlan.id == plan_id))
        plan = result.scalar_one_or_none()

        if not plan:
            raise HTTPException(status_code=404, detail="Recon plan not found")

        # Create scan from plan
        target = request.get("target")
        if not target:
            raise HTTPException(status_code=400, detail="Target is required")

        from backend.models import Scan, ScanCreate, ScanType

        scan_data = ScanCreate(
            target=target,
            scan_type=ScanType.CUSTOM,
            agents=[tool.get("tool") for phase in plan.phases for tool in phase.tools]
        )

        # Create scan
        from backend.api.scans import create_scan
        scan_response = await create_scan(scan_data, None, db)

        return {
            "message": "Recon plan execution started",
            "scan_id": scan_response.id,
            "plan_id": plan_id
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to execute recon plan", plan_id=plan_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to execute recon plan")
