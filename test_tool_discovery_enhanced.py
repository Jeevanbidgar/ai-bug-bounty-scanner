"""
Test enhanced tool discovery with comprehensive tool list
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'backend')))

from tool_discovery import tool_discovery_service


async def main():
    print("=" * 70)
    print("Enhanced Tool Discovery Test")
    print("=" * 70)
    print()
    
    print("Initializing tool discovery...")
    await tool_discovery_service.ensure_ready()
    
    print("Discovering tools...")
    tools = await tool_discovery_service.list_tools()
    
    print(f"\n✅ Total tools checked: {len(tools)}")
    
    available_tools = [t for t in tools if t.installed and t.status == 'available']
    unavailable_tools = [t for t in tools if not t.installed or t.status != 'available']
    
    print(f"✅ Available tools: {len(available_tools)}")
    print(f"❌ Unavailable tools: {len(unavailable_tools)}")
    print()
    
    # Check for specific tools mentioned by user
    print("=" * 70)
    print("Checking for user-mentioned tools:")
    print("=" * 70)
    
    tools_to_check = ['httpx', 'katana', 'assetfinder']
    for tool_name in tools_to_check:
        tool = next((t for t in tools if t.name == tool_name), None)
        if tool:
            if tool.installed and tool.status == 'available':
                print(f"✅ {tool_name}: FOUND at {tool.path}")
            else:
                print(f"❌ {tool_name}: NOT AVAILABLE (Status: {tool.status})")
        else:
            print(f"⚠️  {tool_name}: Not in discovery list")
    
    print()
    print("=" * 70)
    print("Available Security Tools:")
    print("=" * 70)
    
    # Group by category
    by_category = {}
    for tool in available_tools:
        cat = tool.category
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append(tool)
    
    for category in sorted(by_category.keys()):
        tools_in_cat = by_category[category]
        print(f"\n📂 {category.upper()} ({len(tools_in_cat)} tools):")
        for tool in sorted(tools_in_cat, key=lambda x: x.name):
            version_str = f" v{tool.version}" if tool.version else ""
            print(f"  ✓ {tool.name}{version_str}")
            print(f"    Path: {tool.path}")
    
    print()
    print("=" * 70)
    print("Sample of Unavailable Tools (first 10):")
    print("=" * 70)
    for tool in sorted(unavailable_tools, key=lambda x: x.name)[:10]:
        print(f"  ✗ {tool.name} - {tool.description}")
    
    if len(unavailable_tools) > 10:
        print(f"  ... and {len(unavailable_tools) - 10} more")
    
    print()
    print("=" * 70)
    print("✅ Tool Discovery Complete!")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())

