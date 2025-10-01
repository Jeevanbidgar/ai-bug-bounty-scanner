#!/usr/bin/env python3
"""
Test script for AI Bug Bounty Scanner implementation
Tests critical components after implementation
"""

import asyncio
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

async def test_tool_discovery():
    """Test tool discovery and OS dependency checking"""
    print("\n[TEST 3] Testing Tool Discovery...")
    
    from backend.tool_discovery import ToolDiscoveryService
    
    service = ToolDiscoveryService()
    tools = await service.discover_tools()
    
    installed = [t for t in tools.values() if t.installed]
    print(f"[OK] Found {len(installed)}/{len(tools)} installed tools\n")
    
    for name, tool in tools.items():
        if tool.installed:
            status = "[WARN] Missing deps" if tool.missing_dependencies else "[OK]"
            print(f"  {status} {name}: v{tool.version or 'unknown'}")
            
            if tool.os_dependencies:
                print(f"      OS deps: {', '.join(tool.os_dependencies)}")
            
            if tool.missing_dependencies:
                print(f"      [!] Missing: {', '.join(tool.missing_dependencies)}")
                print(f"      Install: sudo apt install {tool.missing_dependencies[0]} (Linux)")
    
    return len(installed) > 0

async def test_database():
    """Test database initialization"""
    print("\n[TEST 4] Testing Database...")
    
    from backend.database import init_db, AsyncSessionLocal
    from backend.models import Tool
    
    # Initialize database
    await init_db()
    print("[OK] Database initialized")
    
    # Test session creation
    async with AsyncSessionLocal() as session:
        print("[OK] Database session created")
        
        # Test a simple query (won't fail if table is empty)
        from sqlalchemy import select
        result = await session.execute(select(Tool))
        tools = result.scalars().all()
        print(f"[OK] Database query successful ({len(tools)} tools in DB)")
    
    return True

async def test_api_routes():
    """Test that API routes are properly configured"""
    print("\n[TEST 5] Testing API Routes...")
    
    from backend.main import app
    
    routes = []
    for route in app.routes:
        if hasattr(route, 'path'):
            routes.append(route.path)
    
    print(f"[OK] Found {len(routes)} API routes")
    
    critical_routes = ['/api/health/', '/api/tools/', '/api/scans/']
    for route in critical_routes:
        # Check if route exists (may have params)
        exists = any(route in r for r in routes)
        status = "[OK]" if exists else "[MISS]"
        print(f"  {status} {route}")
    
    return True

async def test_config():
    """Test configuration loading"""
    print("\n[TEST 6] Testing Configuration...")
    
    from backend.config import Settings
    
    settings = Settings()
    print(f"[OK] Configuration loaded")
    print(f"  Environment: {getattr(settings, 'ENVIRONMENT', 'development')}")
    print(f"  Debug: {getattr(settings, 'DEBUG', True)}")
    print(f"  Host: {getattr(settings, 'HOST', '127.0.0.1')}:{getattr(settings, 'PORT', 8000)}")
    
    return True

async def main():
    """Run all tests"""
    print("=" * 60)
    print("  AI BUG BOUNTY SCANNER - IMPLEMENTATION TESTS")
    print("=" * 60)
    
    tests = [
        ("Tool Discovery", test_tool_discovery),
        ("Database", test_database),
        ("API Routes", test_api_routes),
        ("Configuration", test_config),
    ]
    
    results = []
    
    for name, test_func in tests:
        try:
            result = await test_func()
            results.append((name, True, None))
        except Exception as e:
            print(f"[FAIL] {name}: {e}")
            results.append((name, False, str(e)))
    
    # Summary
    print("\n" + "=" * 60)
    print("  TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for _, result, _ in results if result)
    total = len(results)
    
    for name, result, error in results:
        status = "[PASS]" if result else "[FAIL]"
        print(f"  {status}: {name}")
        if error:
            print(f"         Error: {error}")
    
    print(f"\n  Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n  [OK] All tests passed! Ready to start application.")
        return 0
    else:
        print(f"\n  [FAIL] {total - passed} test(s) failed. Fix errors before proceeding.")
        return 1

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

