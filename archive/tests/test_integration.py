#!/usr/bin/env python3
"""
Integration Test Script
Tests if frontend and backend are properly connected
"""

import sys
import os
import requests
import time
from datetime import datetime

# Add project root to path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

def test_backend_health():
    """Test if backend is running and healthy"""
    try:
        response = requests.get('http://localhost:5000/health', timeout=5)
        if response.status_code == 200:
            print("✅ Backend is running and healthy")
            return True
        else:
            print(f"❌ Backend health check failed: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"❌ Backend connection failed: {str(e)}")
        return False

def test_api_endpoints():
    """Test if API endpoints are accessible"""
    endpoints = [
        '/api/auth/login',
        '/api/scans',
        '/api/reports',
        '/api/users/profile'
    ]
    
    for endpoint in endpoints:
        try:
            response = requests.get(f'http://localhost:5000{endpoint}', timeout=5)
            # 401 is expected for protected endpoints
            if response.status_code in [200, 401, 405]:
                print(f"✅ API endpoint accessible: {endpoint}")
            else:
                print(f"❌ API endpoint error: {endpoint} - {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"❌ API endpoint failed: {endpoint} - {str(e)}")

def test_frontend():
    """Test if frontend is running"""
    try:
        response = requests.get('http://localhost:3000', timeout=5)
        if response.status_code == 200:
            print("✅ Frontend is running")
            return True
        else:
            print(f"❌ Frontend error: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"❌ Frontend connection failed: {str(e)}")
        return False

def main():
    print("🔍 Testing Frontend-Backend Integration")
    print("=" * 50)
    print(f"Timestamp: {datetime.now()}")
    print()
    
    # Test backend
    print("Testing Backend...")
    backend_ok = test_backend_health()
    
    if backend_ok:
        print("\nTesting API Endpoints...")
        test_api_endpoints()
    
    # Test frontend
    print("\nTesting Frontend...")
    frontend_ok = test_frontend()
    
    print("\n" + "=" * 50)
    if backend_ok and frontend_ok:
        print("🎉 Integration test completed - Both services are running!")
    else:
        print("⚠️  Some services are not running. Please start them:")
        if not backend_ok:
            print("   - Start backend: python app.py")
        if not frontend_ok:
            print("   - Start frontend: cd frontend && npm run dev")

if __name__ == "__main__":
    main()
