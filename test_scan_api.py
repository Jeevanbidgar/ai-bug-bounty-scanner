#!/usr/bin/env python3
"""
Test script to check scan creation API
"""
import requests
import json

def test_scan_api():
    print("Testing scan creation API...")

    # Test health first
    try:
        health_response = requests.get("http://localhost:8000/api/health/")
        if health_response.status_code == 200:
            print("[OK] Backend is healthy")
        else:
            print(f"[FAIL] Health check failed: {health_response.status_code}")
            return False
    except Exception as e:
        print(f"[FAIL] Cannot connect to backend: {e}")
        return False

    # Test scan creation
    scan_data = {
        "target": "example.com",
        "scan_type": "Quick Scan"
    }

    print(f"Creating scan: {scan_data}")

    try:
        response = requests.post(
            "http://localhost:8000/api/scans/",
            json=scan_data,
            headers={"Content-Type": "application/json"}
        )

        print(f"Response status: {response.status_code}")

        if response.status_code == 200:
            scan_result = response.json()
            print(f"[OK] Scan created: {scan_result.get('id')}")
            return True
        else:
            print(f"[FAIL] Scan creation failed: {response.status_code}")
            print(f"Response: {response.text}")
            return False

    except Exception as e:
        print(f"[FAIL] Request failed: {e}")
        return False

if __name__ == "__main__":
    result = test_scan_api()
    if result:
        print("Scan API test PASSED")
    else:
        print("Scan API test FAILED")


