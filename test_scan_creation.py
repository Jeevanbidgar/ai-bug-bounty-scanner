#!/usr/bin/env python3
"""
Test script to check scan creation
"""
import requests
import json

def test_scan_creation():
    print("Testing scan creation...")

    try:
        # Test health endpoint first
        health_response = requests.get("http://localhost:8000/api/health/")
        if health_response.status_code != 200:
            print(f"[FAIL] Health check failed: {health_response.status_code}")
            return False

        print("[OK] Backend is healthy")

        # Test scan creation
        scan_data = {
            "target": "example.com",
            "scanType": "quick"
        }

        print("Creating scan...")
        response = requests.post(
            "http://localhost:8000/api/scans/",
            json=scan_data,
            headers={"Content-Type": "application/json"}
        )

        if response.status_code == 200:
            scan_result = response.json()
            print(f"[OK] Scan created successfully: {scan_result.get('id')}")
            return True
        else:
            print(f"[FAIL] Scan creation failed: {response.status_code}")
            try:
                error_data = response.json()
                print(f"Error details: {error_data}")
            except:
                print(f"Response text: {response.text}")
            return False

    except Exception as e:
        print(f"[FAIL] Scan creation test failed: {e}")
        return False

if __name__ == "__main__":
    result = test_scan_creation()
    if result:
        print("Scan creation test PASSED")
    else:
        print("Scan creation test FAILED")

