"""
Workflow API endpoints for AI Bug Bounty Scanner

Provides endpoints for executing workflows, checking status, and managing templates.
"""

from typing import Dict, Any, Optional
import structlog
from fastapi import APIRouter, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from backend.database import get_db, async_session_maker
from backend.models import (
    WorkflowTemplate,
    WorkflowExecutionResponse,
    WorkflowExecutionStatus,
    WorkflowTemplateResponse,
    WorkflowExecuteRequest
)
from backend.services.workflow_loader import workflow_loader
from backend.services.executor import workflow_executor
from backend.tool_discovery import tool_discovery_service

logger = structlog.get_logger()
router = APIRouter()

@router.get("/", response_model=list[WorkflowTemplateResponse])
async def list_workflows(check_compatibility: bool = False) -> list[Dict[str, Any]]:
    """List all available workflow templates
    
    Args:
        check_compatibility: If True, include tool compatibility information
    """
    try:
        workflows = workflow_loader.load_all_workflows()
        workflow_summaries = []
        
        # Get available tools if compatibility check is requested
        available_tools_list = []
        if check_compatibility:
            await tool_discovery_service.ensure_ready()
            tool_records = await tool_discovery_service.list_tools()
            available_tools_list = [
                tool.name for tool in tool_records 
                if tool.installed and tool.status == 'available'
            ]
        
        for workflow in workflows.values():
            summary = workflow_loader.get_workflow_summary(workflow)
            
            if check_compatibility:
                # Add compatibility information
                compatibility = workflow_loader.check_workflow_compatibility(
                    workflow, 
                    available_tools_list
                )
                summary['compatibility'] = compatibility
            
            workflow_summaries.append(summary)
        
        return workflow_summaries
    except Exception as e:
        logger.error("Failed to list workflows", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to retrieve workflows")

@router.get("/{workflow_id}", response_model=WorkflowTemplateResponse)
async def get_workflow(workflow_id: str) -> Dict[str, Any]:
    """Get details of a specific workflow template"""
    try:
        workflow = workflow_loader.load_workflow(workflow_id)
        return workflow_loader.get_workflow_summary(workflow)
    except Exception as e:
        logger.error("Failed to get workflow", workflow_id=workflow_id, error=str(e))
        raise HTTPException(status_code=404, detail=f"Workflow '{workflow_id}' not found")

@router.post("/execute", response_model=WorkflowExecutionResponse)
async def execute_workflow(
    request: WorkflowExecuteRequest,
    background_tasks: BackgroundTasks
) -> WorkflowExecutionResponse:
    """Execute a workflow template"""
    try:
        # Validate inputs
        if not request.workflow_id and not request.template:
            raise HTTPException(status_code=400, detail="Either workflow_id or template must be provided")

        # Load workflow template
        if request.workflow_id:
            workflow = workflow_loader.load_workflow(request.workflow_id)
        else:
            workflow = request.template

        # Validate inputs match workflow requirements
        required_inputs = set(workflow.inputs.keys())
        provided_inputs = set(request.inputs.keys())

        if not required_inputs.issubset(provided_inputs):
            missing = required_inputs - provided_inputs
            raise HTTPException(
                status_code=400,
                detail=f"Missing required inputs: {missing}"
            )

        # Execute workflow
        execution_id = await workflow_executor.execute_workflow(
            workflow_id=workflow.id,
            inputs=request.inputs,
            working_directory=request.working_directory
        )

        return WorkflowExecutionResponse(
            execution_id=execution_id,
            status="running",
            message="Workflow execution started"
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to execute workflow", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to execute workflow")

@router.get("/{execution_id}/status", response_model=WorkflowExecutionStatus)
async def get_execution_status(execution_id: str) -> WorkflowExecutionStatus:
    """Get status of a workflow execution"""
    try:
        status = await workflow_executor.get_execution_status(execution_id)
        if not status:
            raise HTTPException(status_code=404, detail=f"Execution '{execution_id}' not found")

        return WorkflowExecutionStatus(**status)
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get execution status", execution_id=execution_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get execution status")

@router.post("/{execution_id}/stop")
async def stop_execution(execution_id: str) -> Dict[str, str]:
    """Stop a running workflow execution"""
    try:
        # For now, just mark as cancelled
        # In a full implementation, you'd need to signal the running processes
        logger.info("Stopping execution", execution_id=execution_id)
        return {"message": "Execution stopped"}
    except Exception as e:
        logger.error("Failed to stop execution", execution_id=execution_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to stop execution")

@router.get("/{execution_id}/artifacts")
async def get_execution_artifacts(execution_id: str) -> Dict[str, Any]:
    """Get artifacts from a workflow execution"""
    try:
        # Check database for artifacts
        async with async_session_maker() as db:
            from backend.models import WorkflowArtifact

            result = await db.execute(
                select(WorkflowArtifact).where(WorkflowArtifact.execution_id == execution_id)
            )
            artifacts = result.scalars().all()

            return {
                "execution_id": execution_id,
                "artifacts": [artifact.to_dict() for artifact in artifacts]
            }
    except Exception as e:
        logger.error("Failed to get execution artifacts", execution_id=execution_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get execution artifacts")

@router.get("/{execution_id}/findings")
async def get_execution_findings(execution_id: str) -> Dict[str, Any]:
    """Get findings from a workflow execution"""
    try:
        # Check database for findings
        async with async_session_maker() as db:
            from backend.models import WorkflowFinding

            result = await db.execute(
                select(WorkflowFinding).where(WorkflowFinding.execution_id == execution_id)
            )
            findings = result.scalars().all()

            return {
                "execution_id": execution_id,
                "findings": [finding.to_dict() for finding in findings]
            }
    except Exception as e:
        logger.error("Failed to get execution findings", execution_id=execution_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get execution findings")