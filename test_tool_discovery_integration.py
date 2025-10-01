#!/usr/bin/env python3
"""
Test script to check tool discovery with plugin loader integration
"""
import sys
import os
import asyncio
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

async def test_tool_discovery_integration():
    print("Testing tool discovery with plugin loader integration...")

    try:
        # Import like main.py does
        from backend.plugins.plugin_loader import plugin_loader

        print("Loading plugins first...")
        tools = plugin_loader.load_tool_plugins()
        print(f"[OK] Plugin loader loaded {len(tools)} tools")

        print("Creating ToolDiscoveryService with plugin_loader...")
        from backend.tool_discovery import ToolDiscoveryService
        discovery = ToolDiscoveryService(plugin_loader)

        print("Ensuring service is ready...")
        await discovery.ensure_ready()

        print("Running tool discovery...")
        discovered = await discovery.refresh_all(force=True)

        print(f"[OK] Discovered {len(discovered)} tools:")
        for name, tool_record in discovered.items():
            status = "INSTALLED" if tool_record.installed else "NOT INSTALLED"
            version_info = f"v{tool_record.version}" if tool_record.version else "no version"
            print(f"  - {name}: {status} ({tool_record.category}) {version_info}")
            
            if tool_record.missing_dependencies:
                print(f"      [!] Missing dependencies: {', '.join(tool_record.missing_dependencies)}")

        installed_count = sum(1 for t in discovered.values() if t.installed)
        print(f"[OK] Total installed tools: {installed_count}")

        return True

    except Exception as e:
        print(f"[FAIL] Integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    result = asyncio.run(test_tool_discovery_integration())
    if result:
        print("Tool discovery integration test PASSED")
    else:
        print("Tool discovery integration test FAILED")

