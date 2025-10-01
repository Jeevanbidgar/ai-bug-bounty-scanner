#!/usr/bin/env python3
"""
Test script to check tool discovery functionality
"""
import sys
import os
import asyncio
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

async def test_tool_discovery():
    print("Testing tool discovery...")

    try:
        from backend.plugins.plugin_loader import plugin_loader
        print(f"[OK] Loaded {len(plugin_loader._loaded_tools)} tool plugins")

        from backend.tool_discovery import tool_discovery_service
        
        print("Ensuring service is ready...")
        await tool_discovery_service.ensure_ready()

        print("Listing tools (with cache)...")
        tools_list = await tool_discovery_service.list_tools()

        print(f"[OK] Discovered {len(tools_list)} tools:")
        for tool_record in tools_list:
            status = "INSTALLED" if tool_record.installed else "NOT INSTALLED"
            version_info = f"v{tool_record.version}" if tool_record.version else "no version"
            print(f"  - {tool_record.name}: {status} ({tool_record.category}) {version_info}")

        installed_count = sum(1 for t in tools_list if t.installed)
        print(f"[OK] Total installed tools: {installed_count}")

        return True

    except Exception as e:
        print(f"[FAIL] Tool discovery failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    result = asyncio.run(test_tool_discovery())
    if result:
        print("Tool discovery test PASSED")
    else:
        print("Tool discovery test FAILED")

