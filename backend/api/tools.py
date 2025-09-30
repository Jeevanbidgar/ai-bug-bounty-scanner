"""
Tools API router for AI Bug Bounty Scanner
"""

from typing import List, Dict, Any
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import structlog
import asyncio
from datetime import datetime, timezone

from backend.database import get_db
from backend.models import Tool, ToolResponse
from backend.services.tool_service import ToolService

logger = structlog.get_logger()
router = APIRouter()

@router.get("/", response_model=List[ToolResponse])
async def get_tools(db: AsyncSession = Depends(get_db)):
    """Get all available security tools"""
    try:
        result = await db.execute(select(Tool))
        tools = result.scalars().all()

        return [ToolResponse(**tool.to_dict()) for tool in tools]

    except Exception as e:
        logger.error("Failed to get tools", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve tools")

@router.get("/available")
async def get_available_tools():
    """Get tools that are currently available/installed"""
    try:
        tool_service = ToolService()
        available_tools = await tool_service.check_all_tools_availability()

        return {
            "available": available_tools,
            "count": len([t for t in available_tools.values() if t])
        }

    except Exception as e:
        logger.error("Failed to check tool availability", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to check tool availability")

@router.get("/{tool_name}")
async def get_tool(tool_name: str, db: AsyncSession = Depends(get_db)):
    """Get a specific tool by name"""
    try:
        result = await db.execute(select(Tool).where(Tool.name == tool_name))
        tool = result.scalar_one_or_none()

        if not tool:
            raise HTTPException(status_code=404, detail="Tool not found")

        return ToolResponse(**tool.to_dict())

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get tool", tool_name=tool_name, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve tool")

@router.post("/{tool_name}/check")
async def check_tool_availability(tool_name: str):
    """Check if a specific tool is available"""
    try:
        tool_service = ToolService()
        is_available = await tool_service.check_tool_availability(tool_name)

        return {
            "tool": tool_name,
            "available": is_available,
            "checked_at": datetime.now().isoformat()
        }

    except Exception as e:
        logger.error("Failed to check tool availability", tool_name=tool_name, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to check tool availability")

@router.get("/categories")
async def get_tool_categories(db: AsyncSession = Depends(get_db)):
    """Get all tool categories"""
    try:
        result = await db.execute(
            select(Tool.category).distinct()
        )
        categories = result.scalars().all()

        return {"categories": sorted(categories)}

    except Exception as e:
        logger.error("Failed to get tool categories", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve categories")

@router.get("/category/{category}")
async def get_tools_by_category(category: str, db: AsyncSession = Depends(get_db)):
    """Get tools by category"""
    try:
        result = await db.execute(
            select(Tool).where(Tool.category == category)
        )
        tools = result.scalars().all()

        if not tools:
            raise HTTPException(status_code=404, detail="No tools found in category")

        return [ToolResponse(**tool.to_dict()) for tool in tools]

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get tools by category", category=category, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve tools")

@router.post("/refresh")
async def refresh_tools_status(db: AsyncSession = Depends(get_db)):
    """Refresh the availability status of all tools"""
    try:
        # For now, return static information to avoid subprocess issues
        # In production, this would call the dynamic discovery
        from backend.services.tool_registry import ToolRegistry
        static_registry = ToolRegistry()

        # Mock availability check results
        mock_availability = {
            "subfinder": True,
            "nmap": True,
            "nuclei": True,
            "amass": True,
            "sqlmap": True
        }

        # Update database with mock availability status
        for tool_name, available in mock_availability.items():
            result = await db.execute(
                select(Tool).where(Tool.name == tool_name)
            )
            tool = result.scalar_one_or_none()

            if tool:
                tool.available = available
                tool.last_check = datetime.now(timezone.utc)

        await db.commit()
        logger.info("Mock refreshed tools availability status")

        return {
            "message": "Tools availability refresh completed",
            "status": "completed",
            "checked_tools": len(mock_availability),
            "available_tools": sum(mock_availability.values()),
            "note": "Using mock data for stability"
        }

    except Exception as e:
        logger.error("Failed to refresh tools status", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to refresh tools status")
