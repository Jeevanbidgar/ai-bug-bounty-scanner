"""
Debug tool discovery to see why httpx isn't being found
"""

import asyncio
import sys
import os
import shutil

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'backend')))

from tool_discovery import tool_discovery_service


async def debug_tool_discovery():
    print("Debugging tool discovery...")
    print()

    # Check if httpx is in PATH using shutil.which (Python's version of 'which')
    httpx_path = shutil.which("httpx")
    print(f"shutil.which('httpx'): {httpx_path}")

    # Check if httpx.exe is in PATH (Windows specific)
    httpx_exe_path = shutil.which("httpx.exe")
    print(f"shutil.which('httpx.exe'): {httpx_exe_path}")
    print()

    # Check what PATH contains
    path_dirs = os.environ.get("PATH", "").split(os.pathsep)
    print("PATH directories:")
    for i, dir_path in enumerate(path_dirs[:10]):  # First 10 for brevity
        print(f"  {i+1}: {dir_path}")
    print()

    # Check if go/bin is in PATH
    go_bin_found = any("go" in dir_path and "bin" in dir_path for dir_path in path_dirs)
    print(f"go/bin directory in PATH: {go_bin_found}")
    print()

    # Check if httpx exists in go/bin
    go_bin_path = r"C:\Users\jeevan\go\bin"
    httpx_in_go_bin = os.path.exists(os.path.join(go_bin_path, "httpx.exe"))
    print(f"httpx.exe exists in go/bin: {httpx_in_go_bin}")
    print()

    # Check tool discovery service
    print("Initializing tool discovery service...")
    await tool_discovery_service.ensure_ready()

    # Check if httpx is in the tool definitions
    print("Checking tool definitions...")
    definitions = tool_discovery_service._build_definitions()
    httpx_in_definitions = "httpx" in definitions
    print(f"httpx in tool definitions: {httpx_in_definitions}")

    if httpx_in_definitions:
        definition = definitions["httpx"]
        print(f"httpx definition: {definition.name} - {definition.command_candidates}")
    print()

    # Try to get the httpx tool record
    print("Getting httpx tool record...")
    httpx_record = await tool_discovery_service.get_tool("httpx")
    if httpx_record:
        print(f"httpx record found: {httpx_record.name}")
        print(f"  Status: {httpx_record.status}")
        print(f"  Installed: {httpx_record.installed}")
        print(f"  Path: {httpx_record.path}")
        print(f"  Version: {httpx_record.version}")
    else:
        print("httpx record not found")

    print()
    print("Checking all available tools...")
    all_tools = await tool_discovery_service.list_tools()
    available_tools = [t for t in all_tools if t.installed and t.status == 'available']

    print(f"Total tools checked: {len(all_tools)}")
    print(f"Available tools: {len(available_tools)}")

    # Look for httpx specifically
    httpx_tools = [t for t in all_tools if t.name == "httpx"]
    if httpx_tools:
        httpx_tool = httpx_tools[0]
        print(f"httpx tool found: {httpx_tool.name}")
        print(f"  Status: {httpx_tool.status}")
        print(f"  Installed: {httpx_tool.installed}")
        print(f"  Path: {httpx_tool.path}")
    else:
        print("httpx not found in tools list")


if __name__ == "__main__":
    asyncio.run(debug_tool_discovery())

