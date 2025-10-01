#!/usr/bin/env python3
"""Test application status and functionality"""
import asyncio

try:
    from backend.main import app
    print('✅ Backend app imports successfully')
    print('✅ All imports working')

    # Test basic app functionality
    from fastapi.testclient import TestClient
    client = TestClient(app)

    # Test health endpoint
    health = client.get('/api/health/')
    if health.status_code == 200:
        print('✅ Health endpoint working')
        print(f'   Status: {health.json()}')
    else:
        print(f'❌ Health endpoint failed: {health.status_code}')

    # Test if tools are discovered
    from backend.tool_discovery import tool_discovery_service

    async def check_tools():
        try:
            tools = await tool_discovery_service.list_tools()
            print(f'✅ Tool discovery working: {len(tools)} tools found')
            available = [t for t in tools if t.installed]
            print(f'✅ {len(available)}/{len(tools)} tools available')
            return True
        except Exception as e:
            print(f'❌ Tool discovery failed: {e}')
            return False

    asyncio.run(check_tools())

except Exception as e:
    print(f'❌ Application startup failed: {e}')
    import traceback
    traceback.print_exc()
