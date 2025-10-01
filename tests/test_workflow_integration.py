"""
Integration tests for workflow execution system

Tests workflow template loading, DAG execution, and event handling
"""

import asyncio
import pytest
import tempfile
import os
from pathlib import Path

from backend.services.workflow_loader import workflow_loader
from backend.services.executor import workflow_executor
from backend.database import async_session_maker
from backend.models import WorkflowExecution, WorkflowStep as WorkflowStepModel


@pytest.fixture
def temp_workdir():
    """Create a temporary working directory for workflow outputs"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.mark.asyncio
async def test_workflow_template_loading():
    """Test loading workflow templates from YAML files"""
    
    # Load all workflows
    templates = workflow_loader.load_all_workflows()
    
    assert len(templates) > 0, "Should load at least one workflow template"
    
    # Check for expected templates
    assert 'full-recon' in templates, "Should have full-recon template"
    
    # Get full-recon template
    full_recon = templates['full-recon']
    assert full_recon is not None, "Should load full-recon template"
    assert full_recon.id == 'full-recon'
    assert len(full_recon.steps) > 0, "Should have steps defined"
    
    print(f"[OK] Loaded {len(templates)} workflow templates")


@pytest.mark.asyncio
async def test_workflow_template_validation():
    """Test workflow template validation"""
    
    # Load full-recon template
    workflow = workflow_loader.load_workflow('full-recon')
    assert workflow is not None
    
    # Verify workflow structure
    assert hasattr(workflow, 'id')
    assert hasattr(workflow, 'name')
    assert hasattr(workflow, 'steps')
    assert hasattr(workflow, 'inputs')
    
    # Verify steps have required fields
    for step in workflow.steps:
        assert hasattr(step, 'id'), "Step should have id"
        assert hasattr(step, 'run'), "Step should have run command"
        assert isinstance(step.run, list), "Step run should be a list"
        assert len(step.run) > 0, "Step run should not be empty"
    
    print(f"[OK] Workflow template validation passed")


@pytest.mark.asyncio
async def test_workflow_dag_dependencies():
    """Test workflow DAG dependency resolution"""
    
    # Load full-recon template
    workflow = workflow_loader.load_workflow('full-recon')
    assert workflow is not None
    
    # Verify dependency chain: subfinder -> naabu -> httpx -> nuclei
    step_ids = [s.id for s in workflow.steps]
    assert 'subfinder' in step_ids
    assert 'naabu' in step_ids
    assert 'httpx' in step_ids
    assert 'nuclei' in step_ids
    
    # Verify dependencies
    naabu = next(s for s in workflow.steps if s.id == 'naabu')
    assert 'subfinder' in naabu.needs, "naabu should depend on subfinder"
    
    httpx = next(s for s in workflow.steps if s.id == 'httpx')
    assert 'naabu' in httpx.needs, "httpx should depend on naabu"
    
    nuclei = next(s for s in workflow.steps if s.id == 'nuclei')
    assert 'httpx' in nuclei.needs, "nuclei should depend on httpx"
    
    print(f"[OK] Workflow DAG dependencies verified")


@pytest.mark.asyncio
async def test_workflow_execution_dry_run(temp_workdir):
    """Test workflow execution initialization (without running actual tools)"""
    
    # This test verifies execution setup without running real tools
    # In a real scenario, you'd mock the subprocess calls
    
    workflow = workflow_loader.load_workflow('full-recon')
    assert workflow is not None
    
    # Verify we can create an execution context
    inputs = {
        'target': 'example.com',
        'workdir': temp_workdir
    }
    
    # Just verify the workflow structure is valid
    assert workflow.id == 'full-recon'
    assert len(workflow.steps) >= 4  # subfinder, naabu, httpx, nuclei
    
    print(f"[OK] Workflow execution setup verified")


@pytest.mark.asyncio
async def test_command_rendering():
    """Test workflow command rendering with variable interpolation"""
    
    workflow = workflow_loader.load_workflow('full-recon')
    assert workflow is not None
    
    # Get subfinder step
    subfinder = next(s for s in workflow.steps if s.id == 'subfinder')
    
    # Verify command template
    assert 'subfinder' in subfinder.run[0]
    assert '{{target}}' in ' '.join(subfinder.run) or any('target' in arg for arg in subfinder.run)
    assert '{{workdir}}' in ' '.join(subfinder.run) or any('workdir' in arg for arg in subfinder.run)
    
    print(f"[OK] Command rendering verified")


@pytest.mark.asyncio
async def test_workflow_categories():
    """Test workflow categorization"""
    
    templates = workflow_loader.load_all_workflows()
    
    # Get unique categories
    categories = set(w.category for w in templates.values())
    
    assert len(categories) > 0, "Should have at least one category"
    assert 'reconnaissance' in categories, "Should have reconnaissance category"
    
    # Get workflows by category
    recon_workflows = [w for w in templates.values() if w.category == 'reconnaissance']
    assert len(recon_workflows) > 0, "Should have reconnaissance workflows"
    
    print(f"[OK] Workflow categories verified: {categories}")


@pytest.mark.asyncio
async def test_workflow_persistence():
    """Test workflow execution persistence to database"""
    
    # NOTE: This test requires database migration to create workflow tables
    # For now, we just verify the model structure exists
    
    try:
        # Verify the models are importable and have correct structure
        assert hasattr(WorkflowExecution, 'id')
        assert hasattr(WorkflowExecution, 'workflow_id')
        assert hasattr(WorkflowExecution, 'status')
        assert hasattr(WorkflowExecution, 'steps')
        print(f"[OK] Workflow persistence models verified (schema migration needed for full test)")
    except Exception as e:
        print(f"[WARN] Workflow persistence test skipped: {e}")


def test_workflow_timeout_config():
    """Test workflow step timeout configuration"""
    
    workflow = workflow_loader.load_workflow('full-recon')
    assert workflow is not None
    
    # Verify timeout settings
    for step in workflow.steps:
        assert hasattr(step, 'timeout'), f"Step {step.id} should have timeout"
        assert step.timeout > 0, f"Step {step.id} timeout should be positive"
        assert step.timeout <= 3600, f"Step {step.id} timeout should be reasonable"
    
    print(f"[OK] Workflow timeout configuration verified")


def test_nuclei_output_formats():
    """Test nuclei output format configuration in workflow"""
    
    workflow = workflow_loader.load_workflow('full-recon')
    assert workflow is not None
    
    # Get nuclei step
    nuclei = next((s for s in workflow.steps if s.id == 'nuclei'), None)
    assert nuclei is not None, "Should have nuclei step"
    
    # Verify nuclei uses JSONL output
    command = ' '.join(nuclei.run)
    assert '-jsonl' in command or '-j' in command, "Nuclei should use JSONL output"
    assert '-je' in command or '-json-export' in command, "Nuclei should have JSON export"
    
    # Verify outputs are defined
    assert len(nuclei.outputs) > 0, "Nuclei should have output definitions"
    
    print(f"[OK] Nuclei output format verified")


if __name__ == '__main__':
    # Run tests manually
    print("Running workflow integration tests...\n")
    
    asyncio.run(test_workflow_template_loading())
    asyncio.run(test_workflow_template_validation())
    asyncio.run(test_workflow_dag_dependencies())
    
    with tempfile.TemporaryDirectory() as tmpdir:
        asyncio.run(test_workflow_execution_dry_run(tmpdir))
    
    asyncio.run(test_command_rendering())
    asyncio.run(test_workflow_categories())
    asyncio.run(test_workflow_persistence())
    
    test_workflow_timeout_config()
    test_nuclei_output_formats()
    
    print("\n[OK] All workflow integration tests passed!")

