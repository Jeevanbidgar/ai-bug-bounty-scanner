#!/usr/bin/env python3
"""
Test script to check plugin loader functionality
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_plugin_loader():
    print("Testing plugin loader...")

    try:
        from backend.plugins.plugin_loader import PluginLoader
        loader = PluginLoader()

        print("Loading tool plugins...")
        tools = loader.load_tool_plugins()

        print(f"[OK] Loaded {len(tools)} tools:")
        for name, tool in tools.items():
            print(f"  - {name}: {tool.description} ({tool.category})")

        print("Loading workflow templates...")
        workflows = loader.load_workflow_templates()

        print(f"[OK] Loaded {len(workflows)} workflows:")
        for name, workflow in workflows.items():
            print(f"  - {name}: {workflow.description}")

        return True

    except Exception as e:
        print(f"[FAIL] Plugin loader test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    result = test_plugin_loader()
    if result:
        print("Plugin loader test PASSED")
    else:
        print("Plugin loader test FAILED")

