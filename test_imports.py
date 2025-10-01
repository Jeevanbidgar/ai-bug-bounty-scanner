#!/usr/bin/env python3
"""
Test script to check backend imports
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    print("Testing tool_discovery service import...")
    from backend.tool_discovery import tool_discovery_service
    print("[OK] tool_discovery_service import OK")
except Exception as e:
    print(f"[FAIL] tool_discovery_service import failed: {e}")

try:
    print("Testing plugin_loader import...")
    from backend.plugins.plugin_loader import plugin_loader
    print("[OK] plugin_loader import OK")
except Exception as e:
    print(f"[FAIL] plugin_loader import failed: {e}")

try:
    print("Testing tool_discovery import...")
    from backend.tool_discovery import ToolDiscoveryService
    print("[OK] ToolDiscoveryService import OK")
except Exception as e:
    print(f"[FAIL] ToolDiscoveryService import failed: {e}")

print("Import testing complete.")
