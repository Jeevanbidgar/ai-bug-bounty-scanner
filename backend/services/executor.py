"""
Async DAG executor for workflow execution in AI Bug Bounty Scanner

Implements a directed acyclic graph executor that runs workflow steps concurrently,
handles dependencies, timeouts, retries, and artifact propagation.
"""

import asyncio
import json
import logging
import os
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from enum import Enum

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from backend.database import async_session_maker
from backend.models import (
    WorkflowExecution,
    WorkflowStep,
    WorkflowArtifact,
    WorkflowFinding
)
from backend.services.workflow_loader import workflow_loader

logger = logging.getLogger(__name__)

class StepStatus(Enum):
    """Status of a workflow step"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

@dataclass
class StepExecution:
    """Runtime state of a workflow step"""
    step_id: str
    step_name: str
    command: List[str]
    env: Dict[str, str]
    timeout: int
    retry_policy: Dict[str, Any]
    outputs: List[Dict[str, Any]]
    working_directory: Optional[str]
    status: StepStatus = StepStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    error_message: Optional[str] = None
    artifacts: List[str] = field(default_factory=list)
    attempts: int = 0

@dataclass
class WorkflowExecutionContext:
    """Context for a complete workflow execution"""
    execution_id: str
    workflow_id: str
    workflow_name: str
    inputs: Dict[str, str]
    working_directory: Optional[str]
    steps: Dict[str, StepExecution] = field(default_factory=dict)
    artifacts: Dict[str, Any] = field(default_factory=dict)
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "running"

class WorkflowExecutor:
    """Executes workflows using async DAG execution"""

    def __init__(self):
        self.active_executions: Dict[str, WorkflowExecutionContext] = {}

    async def execute_workflow(
        self,
        workflow_id: str,
        inputs: Dict[str, str],
        working_directory: Optional[str] = None,
        websocket_manager = None
    ) -> str:
        """Execute a workflow and return execution ID

        Args:
            workflow_id: ID of workflow template to execute
            inputs: Input parameters for the workflow
            working_directory: Optional working directory
            websocket_manager: WebSocket manager for real-time updates

        Returns:
            Execution ID
        """
        # Load workflow template
        workflow = workflow_loader.load_workflow(workflow_id)

        # Create execution context
        execution_id = f"exec_{int(time.time())}_{workflow_id}"
        context = WorkflowExecutionContext(
            execution_id=execution_id,
            workflow_id=workflow_id,
            workflow_name=workflow.name,
            inputs=inputs,
            working_directory=working_directory
        )

        # Initialize step executions
        for step in workflow.steps:
            step_exec = StepExecution(
                step_id=step.id,
                step_name=step.name,
                command=step.run,
                env=step.env,
                timeout=step.timeout,
                retry_policy={
                    'max_attempts': step.retry.max_attempts,
                    'delay': step.retry.delay,
                    'backoff_factor': step.retry.backoff_factor
                },
                outputs=[output.dict() for output in step.outputs],
                working_directory=step.working_directory
            )
            context.steps[step.id] = step_exec

        self.active_executions[execution_id] = context

        if websocket_manager:
            # Initialize WebSocket connections for this execution
            self._websockets[execution_id] = []

        # Start execution in background
        asyncio.create_task(self._execute_workflow_async(context, websocket_manager))

        return execution_id

    async def _execute_workflow_async(
        self,
        context: WorkflowExecutionContext
    ) -> None:
        """Execute workflow asynchronously"""
        try:
            await self._persist_execution(context)

            # Execute steps in DAG order
            await self._execute_dag(context, websocket_manager)

            # Update final status
            context.status = "completed"

        except Exception as e:
            logger.error(f"Workflow execution failed: {e}")
            context.status = "failed"
            context.error_message = str(e)

        finally:
            context.completed = datetime.now(timezone.utc)
            await self._persist_execution(context)

            # WebSocket connections removed - using Tauri events only

    async def _execute_dag(
        self,
        context: WorkflowExecutionContext
    ) -> None:
        """Execute workflow steps in dependency order"""

        # Build dependency graph
        dependency_graph = self._build_dependency_graph(context)
        ready_steps = self._get_ready_steps(context.steps, dependency_graph)

        while ready_steps:
            # Execute ready steps concurrently
            tasks = []
            for step_id in ready_steps:
                step_exec = context.steps[step_id]
                task = asyncio.create_task(
                    self._execute_step(step_exec, context)
                )
                tasks.append((step_id, task))

            # Wait for all current steps to complete
            for step_id, task in tasks:
                try:
                    await task
                except Exception as e:
                    logger.error(f"Step {step_id} failed: {e}")
                    context.steps[step_id].status = StepStatus.FAILED
                    context.steps[step_id].error_message = str(e)

            # Update ready steps for next iteration
            ready_steps = self._get_ready_steps(context.steps, dependency_graph)

        # Check if all steps completed successfully
        failed_steps = [step_id for step_id, step in context.steps.items()
                       if step.status == StepStatus.FAILED]

        if failed_steps:
            raise Exception(f"Workflow failed: steps {failed_steps} failed")

    def _build_dependency_graph(self, context: WorkflowExecutionContext) -> Dict[str, Set[str]]:
        """Build dependency graph for topological sorting"""
        graph = {step_id: set() for step_id in context.steps.keys()}

        for step_id, step_exec in context.steps.items():
            # Find the step template to get dependencies
            workflow = workflow_loader.load_workflow(context.workflow_id)
            template_step = next(s for s in workflow.steps if s.id == step_exec.step_id)
            graph[step_id] = set(template_step.needs)

        return graph

    def _get_ready_steps(
        self,
        steps: Dict[str, StepExecution],
        dependency_graph: Dict[str, Set[str]]
    ) -> List[str]:
        """Get steps that are ready to execute (no pending dependencies)"""
        ready = []

        for step_id, dependencies in dependency_graph.items():
            step = steps[step_id]

            if step.status != StepStatus.PENDING:
                continue

            # Check if all dependencies are completed
            all_deps_completed = all(
                steps[dep_id].status == StepStatus.COMPLETED
                for dep_id in dependencies
            )

            if all_deps_completed:
                ready.append(step_id)

        return ready

    async def _execute_step(
        self,
        step_exec: StepExecution,
        context: WorkflowExecutionContext
    ) -> None:
        """Execute a single workflow step"""

        step_exec.status = StepStatus.RUNNING
        step_exec.started_at = datetime.now(timezone.utc)

        await self._persist_step(step_exec, context.execution_id)

        # Emit step started event via Tauri (handled in Rust backend)
        # This will be sent to the frontend via Tauri events

        try:
            # Execute the command
            await self._run_command(step_exec, context)

            step_exec.status = StepStatus.COMPLETED
            step_exec.completed_at = datetime.now(timezone.utc)

        except Exception as e:
            logger.error(f"Step {step_exec.step_id} failed: {e}")
            step_exec.status = StepStatus.FAILED
            step_exec.error_message = str(e)
            step_exec.completed_at = datetime.now(timezone.utc)

            # Check if we should retry
            if step_exec.attempts < step_exec.retry_policy['max_attempts']:
                step_exec.attempts += 1
                step_exec.status = StepStatus.PENDING

                # Wait before retry
                delay = step_exec.retry_policy['delay'] * (step_exec.retry_policy['backoff_factor'] ** (step_exec.attempts - 1))
                await asyncio.sleep(delay)

                # Retry the step
                await self._execute_step(step_exec, context)
                return

        await self._persist_step(step_exec, context.execution_id)

        # Step events are now handled via Tauri events in the Rust backend

    async def _run_command(
        self,
        step_exec: StepExecution,
        context: WorkflowExecutionContext
    ) -> None:
        """Execute a command with timeout and output capture"""

        # Prepare environment
        env = os.environ.copy()
        env.update(step_exec.env)

        # Set working directory
        working_dir = step_exec.working_directory or context.working_directory or os.getcwd()

        # Create subprocess
        process = await asyncio.create_subprocess_exec(
            *step_exec.command,
            cwd=working_dir,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=1024*1024  # 1MB buffer limit
        )

        # Capture output with timeout
        try:
            stdout_chunks = []
            stderr_chunks = []

            async def read_stream(stream, chunks_list):
                while True:
                    try:
                        chunk = await asyncio.wait_for(stream.read(1024), timeout=1.0)
                        if not chunk:
                            break
                        chunks_list.append(chunk.decode('utf-8', errors='replace'))
                    except asyncio.TimeoutError:
                        continue  # Continue reading

            # Read stdout and stderr concurrently
            stdout_task = asyncio.create_task(read_stream(process.stdout, stdout_chunks))
            stderr_task = asyncio.create_task(read_stream(process.stderr, stderr_chunks))

            # Wait for process to complete with timeout
            try:
                await asyncio.wait_for(process.wait(), timeout=step_exec.timeout)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                raise Exception(f"Command timed out after {step_exec.timeout} seconds")

            # Wait for output reading to complete
            await stdout_task
            await stderr_task

            # Store results
            step_exec.stdout = ''.join(stdout_chunks)
            step_exec.stderr = ''.join(stderr_chunks)
            step_exec.exit_code = process.returncode

            if process.returncode != 0:
                raise Exception(f"Command failed with exit code {process.returncode}")

            # Process artifacts
            await self._process_step_artifacts(step_exec, context)

        finally:
            # Clean up
            if process.stdout:
                process.stdout.close()
            if process.stderr:
                process.stderr.close()

    async def _process_step_artifacts(
        self,
        step_exec: StepExecution,
        context: WorkflowExecutionContext
    ) -> None:
        """Process and store artifacts from step execution"""

        # For now, just collect file outputs
        # In a real implementation, you would:
        # 1. Check for expected output files
        # 2. Validate output formats
        # 3. Parse structured data (JSONL, etc.)
        # 4. Store artifacts in database

        step_exec.artifacts = []  # Placeholder for artifact processing

        # Example: Look for nuclei JSONL files
        if 'nuclei' in step_exec.command[0].lower():
            # Process nuclei outputs
            await self._process_nuclei_outputs(step_exec, context)

    async def _process_nuclei_outputs(
        self,
        step_exec: StepExecution,
        context: WorkflowExecutionContext
    ) -> None:
        """Process nuclei outputs and create findings"""

        from backend.services.nuclei_parser import nuclei_parser

        # Determine working directory from context or step
        working_dir = Path(context.working_directory or "./results")

        nuclei_files = [
            "nuclei.jsonl",
            "nuclei-export.json",
            "nuclei.json"
        ]

        for filename in nuclei_files:
            file_path = working_dir / filename
            if file_path.exists():
                try:
                    # Parse nuclei output
                    findings_data = nuclei_parser.parse_nuclei_output(str(file_path))

                    # Store findings in database
                    async with async_session_maker() as db:
                        for finding_data in findings_data:
                            finding = WorkflowFinding(
                                execution_id=context.execution_id,
                                step_id=step_exec.step_id,
                                finding_type=finding_data['finding_type'],
                                title=finding_data['title'],
                                severity=finding_data['severity'],
                                description=finding_data['description'],
                                url=finding_data['url'],
                                cvss=finding_data['cvss'],
                                cwe=finding_data['cwe'],
                                tags=json.dumps(finding_data['tags']),
                                evidence=json.dumps(finding_data['evidence']),
                                raw_data=json.dumps(finding_data['raw_data'])
                            )
                            db.add(finding)

                        await db.commit()

                    logger.info(f"Stored {len(findings_data)} findings from {filename}")
                    step_exec.artifacts.append(filename)

                except Exception as e:
                    logger.error(f"Failed to process nuclei file {filename}: {e}")

    async def _persist_execution(self, context: WorkflowExecutionContext) -> None:
        """Persist workflow execution to database"""
        async with async_session_maker() as db:
            try:
                # Update or create execution record
                result = await db.execute(
                    select(WorkflowExecution).where(WorkflowExecution.id == context.execution_id)
                )
                execution = result.scalar_one_or_none()

                if execution:
                    # Update existing execution
                    execution.status = context.status
                    execution.completed = context.completed
                    execution.error_message = context.error_message
                else:
                    # Create new execution
                    execution = WorkflowExecution(
                        id=context.execution_id,
                        workflow_id=context.workflow_id,
                        workflow_name=context.workflow_name,
                        status=context.status,
                        started=context.start_time,
                        completed=context.completed,
                        inputs=json.dumps(context.inputs),
                        error_message=context.error_message
                    )
                    db.add(execution)

                await db.commit()

            except Exception as e:
                logger.error(f"Failed to persist execution {context.execution_id}: {e}")

    async def _persist_step(self, step_exec: StepExecution, execution_id: str) -> None:
        """Persist step execution to database"""
        async with async_session_maker() as db:
            try:
                # Update or create step record
                result = await db.execute(
                    select(WorkflowStep).where(
                        WorkflowStep.execution_id == execution_id,
                        WorkflowStep.step_id == step_exec.step_id
                    )
                )
                step_record = result.scalar_one_or_none()

                if step_record:
                    # Update existing step
                    step_record.status = step_exec.status.value
                    step_record.started = step_exec.started_at
                    step_record.completed = step_exec.completed_at
                    step_record.command = json.dumps(step_exec.command)
                    step_record.exit_code = step_exec.exit_code
                    step_record.stdout = step_exec.stdout
                    step_record.stderr = step_exec.stderr
                    step_record.error_message = step_exec.error_message
                    step_record.artifacts = json.dumps(step_exec.artifacts)
                else:
                    # Create new step
                    step_record = WorkflowStep(
                        execution_id=execution_id,
                        step_id=step_exec.step_id,
                        step_name=step_exec.step_name,
                        status=step_exec.status.value,
                        started=step_exec.started_at,
                        completed=step_exec.completed_at,
                        command=json.dumps(step_exec.command),
                        exit_code=step_exec.exit_code,
                        stdout=step_exec.stdout,
                        stderr=step_exec.stderr,
                        error_message=step_exec.error_message,
                        artifacts=json.dumps(step_exec.artifacts)
                    )
                    db.add(step_record)

                await db.commit()

            except Exception as e:
                logger.error(f"Failed to persist step {step_exec.step_id}: {e}")

    async def get_execution_status(self, execution_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a workflow execution"""
        if execution_id in self.active_executions:
            context = self.active_executions[execution_id]
            return {
                'id': context.execution_id,
                'workflow_id': context.workflow_id,
                'workflow_name': context.workflow_name,
                'status': context.status,
                'started': context.start_time.isoformat(),
                'completed': context.completed.isoformat() if context.completed else None,
                'inputs': context.inputs,
                'error_message': context.error_message,
                'steps': [
                    {
                        'step_id': step.step_id,
                        'step_name': step.step_name,
                        'status': step.status.value,
                        'started': step.started_at.isoformat() if step.started_at else None,
                        'completed': step.completed_at.isoformat() if step.completed_at else None,
                        'exit_code': step.exit_code,
                        'artifacts': step.artifacts
                    }
                    for step in context.steps.values()
                ]
            }

        # Check database for completed executions
        async with async_session_maker() as db:
            try:
                result = await db.execute(
                    select(WorkflowExecution).where(WorkflowExecution.id == execution_id)
                )
                execution = result.scalar_one_or_none()

                if execution:
                    return execution.to_dict()

            except Exception as e:
                logger.error(f"Failed to get execution status from DB: {e}")

        return None

    # WebSocket methods removed - using Tauri events only

# Global workflow executor instance
workflow_executor = WorkflowExecutor()
