"""
Test workflow filtering based on available tools
"""

import asyncio
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'backend')))

from services.workflow_loader import workflow_loader
from tool_discovery import tool_discovery_service


async def test_workflow_tool_filtering():
    """Test that workflows are correctly filtered based on available tools"""
    
    print("=" * 60)
    print("Testing Workflow Tool Filtering")
    print("=" * 60)
    print()
    
    # Step 1: Load all workflows
    print("📦 Loading workflows...")
    try:
        workflows = workflow_loader.load_all_workflows()
        print(f"✅ Loaded {len(workflows)} workflows")
    except Exception as e:
        print(f"❌ Failed to load workflows: {e}")
        return
    
    print()
    
    # Step 2: Discover available tools
    print("🔍 Discovering available tools...")
    try:
        await tool_discovery_service.ensure_ready()
        tool_records = await tool_discovery_service.list_tools()
        available_tools = [
            tool.name for tool in tool_records 
            if tool.installed and tool.status == 'available'
        ]
        print(f"✅ Found {len(available_tools)} available tools:")
        for tool in sorted(available_tools):
            print(f"   - {tool}")
    except Exception as e:
        print(f"❌ Failed to discover tools: {e}")
        return
    
    print()
    
    # Step 3: Check compatibility for each workflow
    print("🔬 Checking workflow compatibility...")
    print()
    
    compatible_workflows = []
    incompatible_workflows = []
    
    for workflow_id, workflow in workflows.items():
        # Get required tools
        required_tools = workflow_loader.get_required_tools(workflow)
        
        # Check compatibility
        compatibility = workflow_loader.check_workflow_compatibility(workflow, available_tools)
        
        print(f"📋 Workflow: {workflow.name}")
        print(f"   ID: {workflow_id}")
        print(f"   Category: {workflow.category}")
        print(f"   Required Tools: {', '.join(required_tools)}")
        print(f"   Available: {', '.join(compatibility['available_tools'])}")
        
        if compatibility['missing_tools']:
            print(f"   ❌ Missing: {', '.join(compatibility['missing_tools'])}")
            print(f"   ⚠️  Compatibility: {compatibility['compatibility_percentage']:.1f}%")
            print(f"   Status: INCOMPATIBLE")
            incompatible_workflows.append(workflow_id)
        else:
            print(f"   ✅ Compatibility: 100%")
            print(f"   Status: COMPATIBLE")
            compatible_workflows.append(workflow_id)
        
        print()
    
    # Step 4: Summary
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print()
    print(f"Total Workflows: {len(workflows)}")
    print(f"Compatible Workflows: {len(compatible_workflows)}")
    print(f"Incompatible Workflows: {len(incompatible_workflows)}")
    print()
    
    if compatible_workflows:
        print("✅ Compatible Workflows:")
        for wf_id in compatible_workflows:
            print(f"   - {workflows[wf_id].name}")
        print()
    
    if incompatible_workflows:
        print("❌ Incompatible Workflows:")
        for wf_id in incompatible_workflows:
            workflow = workflows[wf_id]
            compatibility = workflow_loader.check_workflow_compatibility(workflow, available_tools)
            print(f"   - {workflow.name}")
            print(f"     Missing: {', '.join(compatibility['missing_tools'])}")
        print()
    
    # Step 5: Test API response format
    print("=" * 60)
    print("Testing API Response Format")
    print("=" * 60)
    print()
    
    print("Simulating API response with compatibility info...")
    workflow_summaries = []
    for workflow in workflows.values():
        summary = workflow_loader.get_workflow_summary(workflow)
        compatibility = workflow_loader.check_workflow_compatibility(workflow, available_tools)
        summary['compatibility'] = compatibility
        workflow_summaries.append(summary)
    
    print(f"✅ Generated {len(workflow_summaries)} workflow summaries with compatibility data")
    print()
    
    # Sample output
    if workflow_summaries:
        sample = workflow_summaries[0]
        print("Sample workflow summary:")
        print(f"  ID: {sample['id']}")
        print(f"  Name: {sample['name']}")
        print(f"  Category: {sample['category']}")
        print(f"  Steps: {sample['steps_count']}")
        print(f"  Compatibility:")
        print(f"    - Compatible: {sample['compatibility']['compatible']}")
        print(f"    - Required Tools: {sample['compatibility']['required_tools']}")
        print(f"    - Missing Tools: {sample['compatibility']['missing_tools']}")
        print(f"    - Percentage: {sample['compatibility']['compatibility_percentage']:.1f}%")
    
    print()
    print("=" * 60)
    print("✅ All Tests Completed")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(test_workflow_tool_filtering())

