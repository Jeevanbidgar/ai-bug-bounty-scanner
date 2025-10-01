#!/usr/bin/env python3
"""
Test script to check if plugin_loader works when imported like main.py does
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import like main.py does
from backend.plugins.plugin_loader import plugin_loader

def test_main_integration():
    print("Testing plugin_loader as imported by main.py...")

    try:
        print(f"Current working directory: {os.getcwd()}")
        print(f"Plugin loader path: {plugin_loader.plugin_dir}")

        print("Loading tool plugins...")
        tools = plugin_loader.load_tool_plugins()

        print(f"[OK] Loaded {len(tools)} tools:")
        for name, tool in tools.items():
            print(f"  - {name}: {tool.description} ({tool.category})")

        print(f"Tools in _loaded_tools: {len(plugin_loader._loaded_tools)}")

        return True

    except Exception as e:
        print(f"[FAIL] Integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    result = test_main_integration()
    if result:
        print("Main integration test PASSED")
    else:
        print("Main integration test FAILED")

