"""
Workflow orchestration engine for AI Bug Bounty Scanner
Executes complex multi-tool workflows with dependency management
"""

import asyncio
import json
import uuid
import logging
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime

from .plugins.plugin_loader import plugin_loader, ToolPlugin, WorkflowTemplate
from .database import AsyncSessionLocal
from .models import Scan, WorkflowExecution, WorkflowStep

logger = logging.getLogger(__name__)

@dataclass
class WorkflowStep:
    """Represents a single step in a workflow"""
    id: str
    tool_name: str
    parameters: Dict[str, Any]
    depends_on: List[str] = field(default_factory=list)
    output_key: Optional[str] = None
    condition: Optional[str] = None

@dataclass
class WorkflowExecution:
    """Represents a workflow execution instance"""
    id: str
    workflow_name: str
    target: str
    status: str = "pending"
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    steps: List[WorkflowStep] = field(default_factory=list)
    results: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

class WorkflowEngine:
    """Orchestrates complex multi-tool workflows"""

    def __init__(self):
        self.plugin_loader = plugin_loader
        self.active_executions: Dict[str, WorkflowExecution] = {}

    async def execute_workflow(self, workflow_name: str, target: str, parameters: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute a workflow template"""
        parameters = parameters or {}

        # Load workflow template
        template = self.plugin_loader.get_workflow_template(workflow_name)
        if not template:
            raise ValueError(f"Workflow template '{workflow_name}' not found")

        # Create execution instance
        execution = WorkflowExecution(
            id=str(uuid.uuid4()),
            workflow_name=workflow_name,
            target=target,
            started_at=datetime.utcnow()
        )

        self.active_executions[execution.id] = execution

        try:
            logger.info(f"Starting workflow execution: {workflow_name} for target {target}")

            # Parse and validate workflow steps
            steps = self._parse_workflow_steps(template, target, parameters)

            # Execute steps with dependency resolution
            results = await self._execute_steps(execution, steps)

            # Store execution record
            await self._store_execution(execution, results)

            execution.status = "completed"
            execution.completed_at = datetime.utcnow()

            logger.info(f"Workflow execution completed: {execution.id}")
            return {
                "execution_id": execution.id,
                "status": "completed",
                "results": results,
                "summary": self._generate_summary(results)
            }

        except Exception as e:
            logger.error(f"Workflow execution failed: {e}")
            execution.status = "failed"
            execution.error = str(e)
            execution.completed_at = datetime.utcnow()

            return {
                "execution_id": execution.id,
                "status": "failed",
                "error": str(e)
            }

    def _parse_workflow_steps(self, template: WorkflowTemplate, target: str, parameters: Dict[str, Any]) -> List[WorkflowStep]:
        """Parse workflow template into executable steps"""
        steps = []

        for step_data in template.steps:
            step = WorkflowStep(
                id=str(uuid.uuid4()),
                tool_name=step_data.get('tool'),
                parameters=self._resolve_parameters(step_data.get('parameters', {}), target, parameters),
                depends_on=step_data.get('depends_on', []),
                output_key=step_data.get('output_key'),
                condition=step_data.get('condition')
            )
            steps.append(step)

        return steps

    def _resolve_parameters(self, param_template: Dict[str, Any], target: str, global_params: Dict[str, Any]) -> Dict[str, Any]:
        """Resolve parameter placeholders"""
        resolved = {}

        for key, value in param_template.items():
            if isinstance(value, str):
                # Replace placeholders
                resolved_value = value.replace("{target}", target)
                # Add other placeholders from global params
                for param_key, param_value in global_params.items():
                    resolved_value = resolved_value.replace(f"{{{param_key}}}", str(param_value))
                resolved[key] = resolved_value
            else:
                resolved[key] = value

        # Always include target
        resolved['target'] = target

        return resolved

    async def _execute_steps(self, execution: WorkflowExecution, steps: List[WorkflowStep]) -> Dict[str, Any]:
        """Execute workflow steps with dependency resolution"""
        results = {}
        completed_steps = set()

        while len(completed_steps) < len(steps):
            # Find steps that can be executed (dependencies satisfied)
            executable_steps = [
                step for step in steps
                if step.id not in completed_steps
                and all(dep in completed_steps for dep in step.depends_on)
            ]

            if not executable_steps:
                # Check for circular dependencies or missing dependencies
                missing_deps = []
                for step in steps:
                    if step.id not in completed_steps:
                        for dep in step.depends_on:
                            if dep not in completed_steps:
                                missing_deps.append(f"{step.id} -> {dep}")

                raise ValueError(f"Workflow has unsatisfied dependencies: {missing_deps}")

            # Execute steps in parallel
            tasks = []
            for step in executable_steps:
                if step.condition:
                    # Evaluate condition
                    if not self._evaluate_condition(step.condition, results):
                        logger.info(f"Skipping step {step.id} due to condition")
                        completed_steps.add(step.id)
                        continue

                task = asyncio.create_task(self._execute_step(step))
                tasks.append((step, task))

            # Wait for all tasks to complete
            for step, task in tasks:
                try:
                    step_result = await task
                    results[step.id] = step_result

                    if step.output_key:
                        results[step.output_key] = step_result

                    completed_steps.add(step.id)
                    logger.info(f"Step {step.id} completed successfully")

                except Exception as e:
                    logger.error(f"Step {step.id} failed: {e}")
                    execution.status = "failed"
                    execution.error = f"Step {step.id} failed: {str(e)}"
                    raise

        return results

    async def _execute_step(self, step: WorkflowStep) -> Dict[str, Any]:
        """Execute a single workflow step"""
        tool_plugin = self.plugin_loader.get_tool_plugin(step.tool_name)
        if not tool_plugin:
            raise ValueError(f"Tool plugin '{step.tool_name}' not found")

        # Get tool adapter
        from .adapters.adapter_manager import AdapterManager
        adapter_manager = AdapterManager()
        adapter = adapter_manager.get_adapter(step.tool_name)

        if not adapter:
            raise ValueError(f"No adapter found for tool '{step.tool_name}'")

        # Execute tool
        logger.info(f"Executing tool {step.tool_name} with parameters: {step.parameters}")
        result = await adapter.execute(step.parameters)

        return {
            "tool": step.tool_name,
            "parameters": step.parameters,
            "result": result,
            "timestamp": datetime.utcnow().isoformat()
        }

    def _evaluate_condition(self, condition: str, results: Dict[str, Any]) -> bool:
        """Evaluate a conditional expression"""
        # Simple condition evaluation
        # This could be enhanced with a proper expression parser
        try:
            # For now, just check if a previous step produced output
            if "has_output" in condition:
                return any("output" in result for result in results.values())
            return True
        except:
            return True

    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a summary of workflow results"""
        summary = {
            "total_steps": len(results),
            "successful_steps": len([r for r in results.values() if r.get("result", {}).get("success", False)]),
            "failed_steps": len([r for r in results.values() if not r.get("result", {}).get("success", True)]),
            "tools_used": list(set([r.get("tool") for r in results.values()])),
            "execution_time": "calculated_later"  # Would need to track start/end times
        }

        return summary

    async def _store_execution(self, execution: WorkflowExecution, results: Dict[str, Any]):
        """Store workflow execution in database"""
        async with AsyncSessionLocal() as db:
            # Create workflow execution record
            db_execution = WorkflowExecution(
                id=execution.id,
                workflow_name=execution.workflow_name,
                target=execution.target,
                status=execution.status,
                started_at=execution.started_at,
                completed_at=execution.completed_at,
                results=json.dumps(results),
                error=execution.error
            )
            db.add(db_execution)

            # Store individual step results
            for step_id, step_result in results.items():
                db_step = WorkflowStep(
                    id=str(uuid.uuid4()),
                    execution_id=execution.id,
                    tool_name=step_result.get("tool", ""),
                    parameters=json.dumps(step_result.get("parameters", {})),
                    result=json.dumps(step_result.get("result", {})),
                    status="completed" if step_result.get("result", {}).get("success", False) else "failed"
                )
                db.add(db_step)

            await db.commit()

    def get_execution_status(self, execution_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a workflow execution"""
        execution = self.active_executions.get(execution_id)
        if not execution:
            return None

        return {
            "id": execution.id,
            "workflow_name": execution.workflow_name,
            "target": execution.target,
            "status": execution.status,
            "started_at": execution.started_at.isoformat() if execution.started_at else None,
            "completed_at": execution.completed_at.isoformat() if execution.completed_at else None,
            "progress": len([s for s in execution.steps if s.id in [r.get("step_id") for r in execution.results.values()]]) / len(execution.steps) if execution.steps else 0
        }

# Global workflow engine instance
workflow_engine = WorkflowEngine()
