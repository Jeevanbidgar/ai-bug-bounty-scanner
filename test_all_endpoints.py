#!/usr/bin/env python3
"""
Comprehensive endpoint testing script
Tests all API endpoints one by one and reports results
"""
import sys
import os
import asyncio
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Test results tracking
results = {
    "passed": [],
    "failed": [],
    "skipped": []
}

def log_test(endpoint, status, details=""):
    """Log test result"""
    symbol = "[OK]" if status == "passed" else "[FAIL]" if status == "failed" else "[SKIP]"
    print(f"{symbol} {endpoint}")
    if details:
        print(f"    {details}")
    results[status].append({"endpoint": endpoint, "details": details})

async def test_health_endpoint():
    """Test GET /api/health/"""
    try:
        from fastapi.testclient import TestClient
        from backend.main import app
        
        client = TestClient(app)
        response = client.get("/api/health/")
        
        if response.status_code == 200:
            data = response.json()
            log_test("GET /api/health/", "passed", f"Status: {data.get('status')}")
            return True
        else:
            log_test("GET /api/health/", "failed", f"Status code: {response.status_code}")
            return False
    except Exception as e:
        log_test("GET /api/health/", "failed", str(e))
        return False

async def test_tools_endpoints():
    """Test /api/tools/ endpoints"""
    from fastapi.testclient import TestClient
    from backend.main import app
    
    client = TestClient(app)
    
    # Test 1: GET /api/tools/
    try:
        response = client.get("/api/tools/")
        if response.status_code == 200:
            tools = response.json()
            log_test("GET /api/tools/", "passed", f"Found {len(tools)} tools")
        else:
            log_test("GET /api/tools/", "failed", f"Status: {response.status_code}")
    except Exception as e:
        log_test("GET /api/tools/", "failed", str(e))
    
    # Test 2: GET /api/tools/available
    try:
        response = client.get("/api/tools/available")
        if response.status_code == 200:
            data = response.json()
            log_test("GET /api/tools/available", "passed", f"Available: {data.get('count')}")
        else:
            log_test("GET /api/tools/available", "failed", f"Status: {response.status_code}")
    except Exception as e:
        log_test("GET /api/tools/available", "failed", str(e))
    
    # Test 3: GET /api/tools/{tool_name}
    try:
        response = client.get("/api/tools/nuclei")
        if response.status_code == 200:
            tool = response.json()
            log_test("GET /api/tools/{tool_name}", "passed", f"Tool: {tool.get('name')}")
        else:
            log_test("GET /api/tools/{tool_name}", "failed", f"Status: {response.status_code}")
    except Exception as e:
        log_test("GET /api/tools/{tool_name}", "failed", str(e))
    
    # Test 4: POST /api/tools/{tool_name}/check
    try:
        response = client.post("/api/tools/nuclei/check")
        if response.status_code == 200:
            data = response.json()
            log_test("POST /api/tools/{tool_name}/check", "passed", f"Available: {data.get('available')}")
        else:
            log_test("POST /api/tools/{tool_name}/check", "failed", f"Status: {response.status_code}")
    except Exception as e:
        log_test("POST /api/tools/{tool_name}/check", "failed", str(e))
    
    # Test 5: GET /api/tools/categories
    try:
        response = client.get("/api/tools/categories")
        if response.status_code == 200:
            data = response.json()
            log_test("GET /api/tools/categories", "passed", f"Categories: {len(data.get('categories', []))}")
        else:
            log_test("GET /api/tools/categories", "failed", f"Status: {response.status_code}")
    except Exception as e:
        log_test("GET /api/tools/categories", "failed", str(e))
    
    # Test 6: POST /api/tools/refresh
    try:
        response = client.post("/api/tools/refresh")
        if response.status_code == 200:
            data = response.json()
            log_test("POST /api/tools/refresh", "passed", f"Checked: {data.get('checked_tools')}")
        else:
            log_test("POST /api/tools/refresh", "failed", f"Status: {response.status_code}")
    except Exception as e:
        log_test("POST /api/tools/refresh", "failed", str(e))

async def test_scans_endpoints():
    """Test /api/scans/ endpoints"""
    from fastapi.testclient import TestClient
    from backend.main import app
    
    client = TestClient(app)
    
    # Test 1: GET /api/scans/
    try:
        response = client.get("/api/scans/")
        if response.status_code == 200:
            scans = response.json()
            log_test("GET /api/scans/", "passed", f"Found {len(scans)} scans")
        else:
            log_test("GET /api/scans/", "failed", f"Status: {response.status_code}")
    except Exception as e:
        log_test("GET /api/scans/", "failed", str(e))
    
    # Test 2: POST /api/scans/ (Create scan)
    scan_id = None
    try:
        scan_data = {
            "target": "example.com",
            "scan_type": "Quick Scan",  # Must match ScanType enum
            "agents": ["subfinder", "nuclei"]
        }
        response = client.post("/api/scans/", json=scan_data)
        if response.status_code == 200:
            scan = response.json()
            scan_id = scan.get('id')
            log_test("POST /api/scans/", "passed", f"Created scan: {scan_id}")
        else:
            log_test("POST /api/scans/", "failed", f"Status: {response.status_code}, Response: {response.text}")
    except Exception as e:
        log_test("POST /api/scans/", "failed", str(e))
    
    # Test 3: GET /api/scans/{scan_id}
    if scan_id:
        try:
            response = client.get(f"/api/scans/{scan_id}")
            if response.status_code == 200:
                scan = response.json()
                log_test("GET /api/scans/{scan_id}", "passed", f"Status: {scan.get('status')}")
            else:
                log_test("GET /api/scans/{scan_id}", "failed", f"Status: {response.status_code}")
        except Exception as e:
            log_test("GET /api/scans/{scan_id}", "failed", str(e))
    else:
        log_test("GET /api/scans/{scan_id}", "skipped", "No scan created")
    
    # Test 4: POST /api/scans/{scan_id}/start
    if scan_id:
        try:
            response = client.post(f"/api/scans/{scan_id}/start")
            if response.status_code == 200:
                log_test("POST /api/scans/{scan_id}/start", "passed", "Scan started")
            else:
                log_test("POST /api/scans/{scan_id}/start", "failed", f"Status: {response.status_code}")
        except Exception as e:
            log_test("POST /api/scans/{scan_id}/start", "failed", str(e))
    else:
        log_test("POST /api/scans/{scan_id}/start", "skipped", "No scan created")
    
    # Test 5: POST /api/scans/{scan_id}/stop
    if scan_id:
        try:
            # Check scan status first
            scan_status_resp = client.get(f"/api/scans/{scan_id}")
            current_status = scan_status_resp.json().get('status') if scan_status_resp.status_code == 200 else None
            
            response = client.post(f"/api/scans/{scan_id}/stop")
            # Accept both 200 (stopped) and 400 (already completed/not running)
            if response.status_code == 200:
                log_test("POST /api/scans/{scan_id}/stop", "passed", "Scan stopped successfully")
            elif response.status_code == 400 and "not running" in response.text.lower():
                # Scan completed too fast to stop - this is acceptable
                log_test("POST /api/scans/{scan_id}/stop", "passed", f"Scan already completed (was: {current_status})")
            else:
                log_test("POST /api/scans/{scan_id}/stop", "failed", f"Status: {response.status_code}, Response: {response.text}")
        except Exception as e:
            log_test("POST /api/scans/{scan_id}/stop", "failed", str(e))
    else:
        log_test("POST /api/scans/{scan_id}/stop", "skipped", "No scan created")
    
    # Test 6: DELETE /api/scans/{scan_id}
    if scan_id:
        try:
            response = client.delete(f"/api/scans/{scan_id}")
            if response.status_code == 200:
                log_test("DELETE /api/scans/{scan_id}", "passed", "Scan deleted")
            else:
                log_test("DELETE /api/scans/{scan_id}", "failed", f"Status: {response.status_code}")
        except Exception as e:
            log_test("DELETE /api/scans/{scan_id}", "failed", str(e))
    else:
        log_test("DELETE /api/scans/{scan_id}", "skipped", "No scan created")

async def test_reports_endpoints():
    """Test /api/reports/ endpoints"""
    from fastapi.testclient import TestClient
    from backend.main import app
    
    client = TestClient(app)
    
    # Test 1: GET /api/reports/
    try:
        response = client.get("/api/reports/")
        if response.status_code == 200:
            reports = response.json()
            log_test("GET /api/reports/", "passed", f"Found {len(reports)} reports")
        else:
            log_test("GET /api/reports/", "failed", f"Status: {response.status_code}")
    except Exception as e:
        log_test("GET /api/reports/", "failed", str(e))

async def test_metrics_endpoints():
    """Test /api/metrics/ endpoints"""
    from fastapi.testclient import TestClient
    from backend.main import app
    
    client = TestClient(app)
    
    # Test 1: GET /api/metrics/
    try:
        response = client.get("/api/metrics/")
        if response.status_code == 200:
            metrics = response.json()
            log_test("GET /api/metrics/", "passed", f"Metrics retrieved")
        else:
            log_test("GET /api/metrics/", "failed", f"Status: {response.status_code}")
    except Exception as e:
        log_test("GET /api/metrics/", "failed", str(e))

async def test_workflows_endpoints():
    """Test /api/workflows/ endpoints"""
    from fastapi.testclient import TestClient
    from backend.main import app
    
    client = TestClient(app)
    
    # Test 1: GET /api/workflows/
    try:
        response = client.get("/api/workflows/")
        if response.status_code == 200:
            workflows = response.json()
            log_test("GET /api/workflows/", "passed", f"Found {len(workflows)} workflows")
        else:
            log_test("GET /api/workflows/", "failed", f"Status: {response.status_code}")
    except Exception as e:
        log_test("GET /api/workflows/", "failed", str(e))

async def main():
    print("=" * 70)
    print("COMPREHENSIVE API ENDPOINT TESTING")
    print("=" * 70)
    print()
    
    try:
        print("--- Health Endpoint ---")
        await test_health_endpoint()
        print()
        
        print("--- Tools Endpoints ---")
        await test_tools_endpoints()
        print()
        
        print("--- Scans Endpoints ---")
        await test_scans_endpoints()
        print()
        
        print("--- Reports Endpoints ---")
        await test_reports_endpoints()
        print()
        
        print("--- Metrics Endpoints ---")
        await test_metrics_endpoints()
        print()
        
        print("--- Workflows Endpoints ---")
        await test_workflows_endpoints()
        print()
        
        # Summary
        print("=" * 70)
        print("TEST SUMMARY")
        print("=" * 70)
        print()
        print(f"[OK] Passed:  {len(results['passed'])}")
        print(f"[FAIL] Failed:  {len(results['failed'])}")
        print(f"[SKIP] Skipped: {len(results['skipped'])}")
        print()
        
        if results['failed']:
            print("Failed Endpoints:")
            for item in results['failed']:
                print(f"  - {item['endpoint']}: {item['details']}")
            print()
            return False
        else:
            print("[SUCCESS] All endpoints working correctly!")
            print()
            return True
            
    except Exception as e:
        print()
        print("[ERROR] Test execution failed:")
        print(f"  {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)

