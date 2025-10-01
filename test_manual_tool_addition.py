"""
Test manual tool addition functionality
"""

import asyncio
import sys
import os
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'backend')))

from tool_discovery import tool_discovery_service


async def test_manual_tool_addition():
    """Test manually adding tools to the system"""

    print("=" * 70)
    print("Manual Tool Addition Test")
    print("=" * 70)
    print()

    # First, let's see what tools are currently available
    print("Current available tools before manual addition:")
    await tool_discovery_service.ensure_ready()
    tools_before = await tool_discovery_service.list_tools()
    available_before = [t for t in tools_before if t.installed and t.status == 'available']

    print(f"Available tools: {len(available_before)}")
    for tool in available_before[:5]:  # Show first 5
        print(f"  ✓ {tool.name} - {tool.path}")
    if len(available_before) > 5:
        print(f"  ... and {len(available_before) - 5} more")
    print()

    # Test adding a fake tool that doesn't exist
    print("Testing manual tool addition with fake tool...")
    try:
        fake_tool = tool_discovery_service.add_manual_tool(
            tool_name="fake-tool",
            tool_path="/usr/bin/fake-tool",
            category="testing"
        )
        print("❌ ERROR: Should have failed for non-existent path!")
    except Exception as e:
        print(f"✅ Correctly rejected fake tool: {e}")
    print()

    # Test adding a real tool (if it exists)
    real_tools_to_test = [
        ("python", "/usr/bin/python3", "utility"),
        ("curl", "/usr/bin/curl", "utility"),
    ]

    for tool_name, tool_path, category in real_tools_to_test:
        print(f"Testing manual addition of {tool_name}...")

        # Check if the tool exists at the path
        import os
        if os.path.exists(tool_path) and os.access(tool_path, os.X_OK):
            try:
                added_tool = tool_discovery_service.add_manual_tool(
                    tool_name=tool_name,
                    tool_path=tool_path,
                    category=category
                )
                print(f"✅ Successfully added {tool_name}")
                print(f"   Path: {added_tool.path}")
                print(f"   Version: {added_tool.version}")
                print(f"   Category: {added_tool.category}")
            except Exception as e:
                print(f"❌ Failed to add {tool_name}: {e}")
        else:
            print(f"⚠️  Tool {tool_name} not found at {tool_path}, skipping")
    print()

    # Check if manual tools are tracked
    print("Checking manual tools tracking...")
    manual_tools = tool_discovery_service.list_manual_tools()
    print(f"Manual tools in cache: {manual_tools}")
    print()

    # Test removal
    if manual_tools:
        print("Testing manual tool removal...")
        for tool_name in manual_tools:
            success = tool_discovery_service.remove_manual_tool(tool_name)
            if success:
                print(f"✅ Removed manual tool: {tool_name}")
            else:
                print(f"❌ Failed to remove manual tool: {tool_name}")
    print()

    # Show final state
    print("Final state after manual tool operations:")
    tools_after = await tool_discovery_service.list_tools()
    available_after = [t for t in tools_after if t.installed and t.status == 'available']

    print(f"Available tools: {len(available_after)} (was {len(available_before)})")

    # Check for tools that were added
    added_tools = set(t.name for t in available_after) - set(t.name for t in available_before)
    if added_tools:
        print(f"Newly available tools: {added_tools}")
    else:
        print("No new tools added")

    print()
    print("=" * 70)
    print("✅ Manual Tool Addition Test Complete!")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(test_manual_tool_addition())

