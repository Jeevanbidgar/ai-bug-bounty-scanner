"""
YAML workflow loader with validation for AI Bug Bounty Scanner

Loads and validates workflow templates from YAML files, ensuring they conform
to the expected schema and contain safe, valid command specifications.
"""

import os
import yaml
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from pydantic import ValidationError

from backend.models import (
    WorkflowTemplate,
    WorkflowStepModel,
    WorkflowStepOutput,
    WorkflowStepRetry
)

logger = logging.getLogger(__name__)

class WorkflowLoaderError(Exception):
    """Raised when workflow loading or validation fails"""
    pass

class WorkflowLoader:
    """Loads and validates workflow templates from YAML files"""

    def __init__(self, workflows_dir: Optional[str] = None):
        """Initialize the workflow loader

        Args:
            workflows_dir: Directory containing workflow YAML files.
                          Defaults to 'app/workflows/' relative to project root.
        """
        if workflows_dir is None:
            # Default to app/workflows/ directory
            project_root = Path(__file__).parent.parent.parent
            workflows_dir = project_root / "app" / "workflows"

        self.workflows_dir = Path(workflows_dir)
        self.workflows_dir.mkdir(exist_ok=True)

        logger.info(f"Workflow loader initialized with directory: {self.workflows_dir}")

    def load_workflow(self, workflow_id: str) -> WorkflowTemplate:
        """Load and validate a single workflow by ID

        Args:
            workflow_id: ID of the workflow to load

        Returns:
            Validated WorkflowTemplate object

        Raises:
            WorkflowLoaderError: If workflow loading or validation fails
        """
        try:
            # Find the workflow file
            workflow_file = self._find_workflow_file(workflow_id)
            if not workflow_file:
                raise WorkflowLoaderError(f"Workflow '{workflow_id}' not found")

            # Load and parse YAML
            with open(workflow_file, 'r', encoding='utf-8') as f:
                raw_data = yaml.safe_load(f)

            if not raw_data:
                raise WorkflowLoaderError(f"Empty or invalid YAML in {workflow_file}")

            # Validate and convert to Pydantic model
            return self._validate_workflow(raw_data, workflow_id)

        except yaml.YAMLError as e:
            raise WorkflowLoaderError(f"Invalid YAML in workflow '{workflow_id}': {e}")
        except ValidationError as e:
            raise WorkflowLoaderError(f"Workflow validation failed for '{workflow_id}': {e}")
        except Exception as e:
            raise WorkflowLoaderError(f"Failed to load workflow '{workflow_id}': {e}")

    def load_all_workflows(self) -> Dict[str, WorkflowTemplate]:
        """Load and validate all available workflows

        Returns:
            Dictionary mapping workflow IDs to WorkflowTemplate objects

        Raises:
            WorkflowLoaderError: If any workflow fails to load
        """
        workflows = {}
        errors = []

        # Find all YAML files in the workflows directory
        for yaml_file in self.workflows_dir.glob("*.yaml"):
            try:
                workflow_id = yaml_file.stem  # Remove .yaml extension

                # Skip files that start with underscore (templates, examples, etc.)
                if workflow_id.startswith('_'):
                    continue

                workflow = self.load_workflow(workflow_id)
                workflows[workflow_id] = workflow

                logger.info(f"Loaded workflow: {workflow_id} ({workflow.name})")

            except WorkflowLoaderError as e:
                errors.append(f"{yaml_file.name}: {e}")
                logger.error(f"Failed to load workflow {yaml_file.name}: {e}")

        if errors:
            error_msg = f"Failed to load {len(errors)} workflows:\n" + "\n".join(errors)
            raise WorkflowLoaderError(error_msg)

        logger.info(f"Successfully loaded {len(workflows)} workflows")
        return workflows

    def _find_workflow_file(self, workflow_id: str) -> Optional[Path]:
        """Find the YAML file for a given workflow ID"""
        yaml_file = self.workflows_dir / f"{workflow_id}.yaml"
        return yaml_file if yaml_file.exists() else None

    def _validate_workflow(self, raw_data: Dict[str, Any], workflow_id: str) -> WorkflowTemplate:
        """Validate raw workflow data against Pydantic models"""

        # Extract and validate steps first
        steps_data = raw_data.get('steps', [])
        if not steps_data:
            raise WorkflowLoaderError("Workflow must contain at least one step")

        # Validate each step
        steps = []
        for step_data in steps_data:
            step = self._validate_step(step_data)
            steps.append(step)

        # Validate outputs
        outputs_data = raw_data.get('outputs', [])
        outputs = [WorkflowStepOutput(**output) for output in outputs_data]

        # Create workflow template
        try:
            workflow = WorkflowTemplate(
                id=workflow_id,
                name=raw_data.get('name', workflow_id),
                description=raw_data.get('description', ''),
                category=raw_data.get('category', 'general'),
                version=raw_data.get('version', '1.0.0'),
                author=raw_data.get('author'),
                tags=raw_data.get('tags', []),
                inputs=raw_data.get('inputs', {}),
                steps=steps,
                outputs=outputs
            )
        except ValidationError as e:
            raise WorkflowLoaderError(f"Workflow validation failed: {e}")

        # Validate DAG structure (no cycles, valid dependencies)
        self._validate_dag_structure(workflow)

        return workflow

    def _validate_step(self, step_data: Dict[str, Any]) -> WorkflowStepModel:
        """Validate a single workflow step"""

        # Validate needs (dependencies)
        needs = step_data.get('needs', [])
        if not isinstance(needs, list):
            raise WorkflowLoaderError("Step 'needs' must be a list")

        # Validate run command
        run = step_data.get('run', [])
        if not isinstance(run, list):
            raise WorkflowLoaderError("Step 'run' must be a list (argv array)")

        if not run:
            raise WorkflowLoaderError("Step must have a 'run' command")

        # Validate outputs
        outputs_data = step_data.get('outputs', [])
        outputs = []
        for output_data in outputs_data:
            try:
                output = WorkflowStepOutput(**output_data)
                outputs.append(output)
            except ValidationError as e:
                raise WorkflowLoaderError(f"Invalid step output: {e}")

        # Validate retry policy
        retry_data = step_data.get('retry', {})
        retry = WorkflowStepRetry(**retry_data)

        # Validate environment variables
        env = step_data.get('env', {})
        if not isinstance(env, dict):
            raise WorkflowLoaderError("Step 'env' must be a dictionary")

        try:
            step = WorkflowStepModel(
                id=step_data['id'],
                name=step_data.get('name', step_data['id']),
                description=step_data.get('description'),
                needs=needs,
                run=run,
                env=env,
                timeout=step_data.get('timeout', 300),
                retry=retry,
                outputs=outputs,
                working_directory=step_data.get('working_directory')
            )
        except ValidationError as e:
            raise WorkflowLoaderError(f"Step validation failed: {e}")

        return step

    def _validate_dag_structure(self, workflow: WorkflowTemplate) -> None:
        """Validate that the workflow DAG has no cycles and valid dependencies"""

        step_ids = {step.id for step in workflow.steps}
        step_map = {step.id: step for step in workflow.steps}

        # Check that all dependencies exist
        for step in workflow.steps:
            for need in step.needs:
                if need not in step_ids:
                    raise WorkflowLoaderError(f"Step '{step.id}' depends on unknown step '{need}'")

        # Check for cycles using DFS
        visited = set()
        rec_stack = set()

        def has_cycle(step_id: str) -> bool:
            if step_id in rec_stack:
                return True
            if step_id in visited:
                return False

            visited.add(step_id)
            rec_stack.add(step_id)

            step = step_map[step_id]
            for need in step.needs:
                if has_cycle(need):
                    return True

            rec_stack.remove(step_id)
            return False

        # Check each step for cycles
        for step_id in step_ids:
            if step_id not in visited:
                if has_cycle(step_id):
                    raise WorkflowLoaderError(f"Workflow contains cycle involving step '{step_id}'")

    def render_workflow_commands(self, workflow: WorkflowTemplate, inputs: Dict[str, str]) -> Dict[str, List[str]]:
        """Render workflow commands with variable interpolation

        Args:
            workflow: Workflow template to render
            inputs: Input parameters for variable substitution

        Returns:
            Dictionary mapping step IDs to rendered argv arrays
        """
        rendered_commands = {}

        for step in workflow.steps:
            # Interpolate variables in the run command
            rendered_argv = []
            for arg in step.run:
                # Simple variable interpolation: {{variable_name}}
                interpolated = arg
                for key, value in inputs.items():
                    interpolated = interpolated.replace(f"{{{{{key}}}}}", value)
                rendered_argv.append(interpolated)

            # Interpolate variables in environment variables
            rendered_env = {}
            for key, value in step.env.items():
                interpolated_value = value
                for input_key, input_value in inputs.items():
                    interpolated_value = interpolated_value.replace(f"{{{{{input_key}}}}}", input_value)
                rendered_env[key] = interpolated_value

            # Store the rendered command (for display purposes)
            rendered_commands[step.id] = rendered_argv

        return rendered_commands

    def get_workflow_summary(self, workflow: WorkflowTemplate) -> Dict[str, Any]:
        """Get a summary of workflow information for UI display"""
        return {
            'id': workflow.id,
            'name': workflow.name,
            'description': workflow.description,
            'category': workflow.category,
            'version': workflow.version,
            'author': workflow.author,
            'tags': workflow.tags,
            'steps_count': len(workflow.steps),
            'outputs_count': len(workflow.outputs),
            'inputs': workflow.inputs
        }

    def get_required_tools(self, workflow: WorkflowTemplate) -> List[str]:
        """Extract list of tools required by a workflow
        
        Args:
            workflow: Workflow template to analyze
            
        Returns:
            List of tool names (command names) required by the workflow
        """
        required_tools = set()
        
        for step in workflow.steps:
            if step.run and len(step.run) > 0:
                # The first element in the run array is the command/tool name
                tool_name = step.run[0]
                required_tools.add(tool_name)
        
        return sorted(list(required_tools))
    
    def check_workflow_compatibility(self, workflow: WorkflowTemplate, available_tools: List[str]) -> Dict[str, Any]:
        """Check if a workflow can run with the available tools
        
        Args:
            workflow: Workflow template to check
            available_tools: List of available tool names
            
        Returns:
            Dictionary with compatibility information:
            {
                'compatible': bool,
                'required_tools': List[str],
                'available_tools': List[str],
                'missing_tools': List[str],
                'compatibility_percentage': float
            }
        """
        required_tools = self.get_required_tools(workflow)
        available_tools_set = set(available_tools)
        required_tools_set = set(required_tools)
        
        available = list(required_tools_set.intersection(available_tools_set))
        missing = list(required_tools_set - available_tools_set)
        
        compatibility_percentage = (len(available) / len(required_tools) * 100) if required_tools else 100.0
        
        return {
            'compatible': len(missing) == 0,
            'required_tools': required_tools,
            'available_tools': available,
            'missing_tools': missing,
            'compatibility_percentage': compatibility_percentage
        }

# Global workflow loader instance
workflow_loader = WorkflowLoader()
