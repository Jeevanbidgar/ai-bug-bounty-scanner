#!/usr/bin/env python3
"""Test the stop endpoint specifically"""
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

# Create a scan
scan = client.post('/api/scans/', json={
    'target': 'test.com',
    'scan_type': 'Quick Scan',
    'agents': ['subfinder']
}).json()

print(f"Created scan: {scan['id']}")

# Start the scan
start_resp = client.post(f'/api/scans/{scan["id"]}/start')
print(f"Start response: {start_resp.status_code}")
print(f"Start data: {start_resp.json()}")

# Try to stop it
stop_resp = client.post(f'/api/scans/{scan["id"]}/stop')
print(f"Stop response: {stop_resp.status_code}")
if stop_resp.status_code == 200:
    print(f"Stop data: {stop_resp.json()}")
else:
    print(f"Stop error: {stop_resp.text}")


