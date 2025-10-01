"""
Tools API router for AI Bug Bounty Scanner
"""

from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
from pydantic import BaseModel

from fastapi import APIRouter, BackgroundTasks, HTTPException
import structlog

from backend.schemas import ToolResponse
from backend.tool_discovery import ToolRecord, tool_discovery_service

logger = structlog.get_logger()
router = APIRouter()


class AddManualToolRequest(BaseModel):
    """Request model for manually adding a tool"""
    tool_name: str
    tool_path: str
    category: str = "custom"


class AddManualToolResponse(BaseModel):
    """Response model for manual tool addition"""
    success: bool
    tool: Optional[ToolResponse] = None
    error: Optional[str] = None


def _record_to_response(record: ToolRecord) -> ToolResponse:
    """Convert a ToolRecord to a ToolResponse schema."""
    return ToolResponse(
        name=record.name,
        description=record.description,
        category=record.category,
        status=record.status,
        installed=record.installed,
        available=record.installed,
        version=record.version,
        raw_version=record.raw_version,
        path=record.path,
        command_template=list(record.command_template),
        output_format=record.output_format,
        os_dependencies=list(record.os_dependencies),
        missing_dependencies=list(record.missing_dependencies),
        last_check=record.last_checked,
        last_seen=record.last_seen,
        last_error=record.last_error,
    )

@router.get("/", response_model=List[ToolResponse])
async def get_tools(background_tasks: BackgroundTasks) -> List[ToolResponse]:
    try:
        records = await tool_discovery_service.list_tools(background_tasks=background_tasks)
        return [_record_to_response(record) for record in records]
    except Exception as exc:
        logger.error("Failed to get tools", error=str(exc))
        raise HTTPException(status_code=500, detail="Failed to retrieve tools")

@router.get("/available")
async def get_available_tools(background_tasks: BackgroundTasks) -> Dict[str, Any]:
    try:
        records = await tool_discovery_service.list_tools(background_tasks=background_tasks)
        available = [record for record in records if record.installed]
        return {
            "available": [_record_to_response(record) for record in available],
            "count": len(available),
        }
    except Exception as exc:
        logger.error("Failed to check tool availability", error=str(exc))
        raise HTTPException(status_code=500, detail="Failed to check tool availability")

@router.get("/categories")
async def get_tool_categories(background_tasks: BackgroundTasks) -> Dict[str, List[str]]:
    try:
        records = await tool_discovery_service.list_tools(background_tasks=background_tasks)
        categories = sorted({record.category for record in records})
        return {"categories": categories}
    except Exception as exc:
        logger.error("Failed to get tool categories", error=str(exc))
        raise HTTPException(status_code=500, detail="Failed to retrieve categories")

@router.get("/category/{category}")
async def get_tools_by_category(category: str, background_tasks: BackgroundTasks) -> List[ToolResponse]:
    try:
        records = await tool_discovery_service.list_tools(background_tasks=background_tasks)
        category_records = [record for record in records if record.category == category]
        if not category_records:
            raise HTTPException(status_code=404, detail="No tools found in category")
        return [_record_to_response(record) for record in category_records]
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Failed to get tools by category", category=category, error=str(exc))
        raise HTTPException(status_code=500, detail="Failed to retrieve tools")

@router.post("/refresh")
async def refresh_tools_status() -> Dict[str, Any]:
    try:
        refreshed = await tool_discovery_service.refresh_all(force=True)
        available_count = sum(1 for record in refreshed.values() if record.installed)
        logger.info("Refreshed %d tools, %d available", len(refreshed), available_count)
        return {
            "message": "Tools availability refresh completed",
            "status": "completed",
            "checked_tools": len(refreshed),
            "available_tools": available_count,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as exc:
        logger.error("Failed to refresh tools status", error=str(exc))
        raise HTTPException(status_code=500, detail="Failed to refresh tools status")

# Manual tool management endpoints
@router.post("/tools/manual/add", response_model=AddManualToolResponse)
async def add_manual_tool(request: AddManualToolRequest) -> AddManualToolResponse:
    """Manually add a tool with a custom path

    This endpoint allows users to add tools that weren't automatically discovered
    but are installed in non-standard locations.
    """
    try:
        # Add the tool manually
        tool_record = tool_discovery_service.add_manual_tool(
            tool_name=request.tool_name,
            tool_path=request.tool_path,
            category=request.category
        )

        return AddManualToolResponse(
            success=True,
            tool=_record_to_response(tool_record)
        )

    except Exception as e:
        logger.warning("Failed to add manual tool", tool=request.tool_name, error=str(e))
        return AddManualToolResponse(
            success=False,
            error=str(e)
        )
    except Exception as e:
        logger.error("Unexpected error adding manual tool", tool=request.tool_name, error=str(e))
        return AddManualToolResponse(
            success=False,
            error=f"Unexpected error: {str(e)}"
        )


@router.delete("/tools/manual/{tool_name}")
async def remove_manual_tool(tool_name: str) -> Dict[str, Any]:
    """Remove a manually added tool"""
    try:
        success = tool_discovery_service.remove_manual_tool(tool_name)

        if success:
            return {
                "success": True,
                "message": f"Tool '{tool_name}' removed successfully"
            }
        else:
            raise HTTPException(status_code=404, detail=f"Manual tool '{tool_name}' not found")

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to remove manual tool", tool_name=tool_name, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to remove manual tool")


@router.get("/tools/manual/list")
async def list_manual_tools() -> Dict[str, Any]:
    """List all manually added tools"""
    try:
        manual_tools = tool_discovery_service.list_manual_tools()
        return {
            "manual_tools": manual_tools,
            "count": len(manual_tools)
        }
    except Exception as e:
        logger.error("Failed to list manual tools", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve manual tools")


@router.get("/{tool_name}")
async def get_tool(tool_name: str, background_tasks: BackgroundTasks) -> ToolResponse:
    """Get details of a specific tool"""
    try:
        record = await tool_discovery_service.get_tool(tool_name, background_tasks=background_tasks)
        if record is None:
            raise HTTPException(status_code=404, detail="Tool not found")
        return _record_to_response(record)
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Failed to get tool", tool_name=tool_name, error=str(exc))
        raise HTTPException(status_code=500, detail="Failed to retrieve tool")


@router.post("/{tool_name}/check")
async def check_tool_availability(tool_name: str, background_tasks: BackgroundTasks) -> Dict[str, Any]:
    """Check availability of a specific tool"""
    try:
        record = await tool_discovery_service.get_tool(tool_name, background_tasks=background_tasks)
        if record is None:
            raise HTTPException(status_code=404, detail="Tool not found")
        return {
            "tool": tool_name,
            "available": record.installed,
            "installed": record.installed,
            "version": record.version,
            "path": record.path,
            "checked_at": record.last_checked,
            "status": record.status,
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Failed to check tool availability", tool_name=tool_name, error=str(exc))
        raise HTTPException(status_code=500, detail="Failed to check tool availability")
