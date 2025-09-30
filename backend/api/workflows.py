"""
Workflow API endpoints for AI Bug Bounty Scanner
"""

from typing import List, Dict, Any
from fastapi import APIRouter, HTTPException
from ..plugins.plugin_loader import plugin_loader
from ..workflow_engine import workflow_engine

router = APIRouter(prefix="/workflows", tags=["workflows"])

@router.get("/")
async def list_workflows() -> Dict[str, Any]:
    """List all available workflow templates"""
    workflows = plugin_loader._loaded_workflows
    return {
        "workflows": [
            {
                "name": workflow.name,
                "description": workflow.description,
                "category": workflow.category,
                "step_count": len(workflow.steps),
                "tags": workflow.tags
            }
            for workflow in workflows.values()
        ]
    }

@router.get("/{workflow_name}")
async def get_workflow(workflow_name: str) -> Dict[str, Any]:
    """Get details of a specific workflow"""
    workflow = plugin_loader.get_workflow_template(workflow_name)
    if not workflow:
        raise HTTPException(status_code=404, detail="Workflow not found")

    return {
        "name": workflow.name,
        "description": workflow.description,
        "category": workflow.category,
        "steps": workflow.steps,
        "parameters": workflow.parameters,
        "tags": workflow.tags
    }

@router.post("/execute")
async def execute_workflow(
    workflow_name: str,
    target: str,
    parameters: Dict[str, Any] = None
) -> Dict[str, Any]:
    """Execute a workflow"""
    try:
        result = await workflow_engine.execute_workflow(workflow_name, target, parameters)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/executions/{execution_id}")
async def get_execution_status(execution_id: str) -> Dict[str, Any]:
    """Get status of a workflow execution"""
    status = workflow_engine.get_execution_status(execution_id)
    if not status:
        raise HTTPException(status_code=404, detail="Execution not found")

    return status

@router.get("/categories")
async def list_workflow_categories() -> Dict[str, Any]:
    """List workflow categories"""
    workflows = plugin_loader._loaded_workflows
    categories = set()

    for workflow in workflows.values():
        categories.add(workflow.category)

    return {
        "categories": sorted(list(categories))
    }
