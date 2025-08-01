#!/usr/bin/env python3
"""
Test script for API integrations in Enhanced AI Bug Bounty Scanner
Tests AbuseIPDB, Shodan, and VirusTotal API connectivity and functionality
"""

import requests
import json
import asyncio
from datetime import datetime

# API Keys
ABUSEIPDB_KEY = "3f0fa7f9204bd618d24f7b2be233382f0a37cc16ef41c36976b3ee87611c844ecc8b3c2fbe3a3ba3"
SHODAN_KEY = "gB4ThIkHfWApnpDawWLGnq9Tc7TqvuDw"
VIRUSTOTAL_KEY = "a9f4b3641ade0460ce11d4e9c81f066959a97bc62a3f155efb4ccf10b8efda2d"

def test_abuseipdb_api():
    """Test AbuseIPDB API functionality"""
    print("🛡️  Testing AbuseIPDB API...")
    
    headers = {
        'Key': ABUSEIPDB_KEY,
        'Accept': 'application/json'
    }
    
    # Test IPs - mix of clean and potentially suspicious
    test_ips = [
        '8.8.8.8',        # Google DNS (should be clean)
        '1.1.1.1',        # Cloudflare DNS (should be clean)
    ]
    
    for ip in test_ips:
        try:
            response = requests.get(
                'https://api.abuseipdb.com/api/v2/check',
                params={
                    'ipAddress': ip,
                    'maxAgeInDays': 90,
                    'verbose': ''
                },
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                ip_data = data.get('data', {})
                
                print(f"   ✅ {ip}:")
                print(f"      Abuse Score: {ip_data.get('abuseConfidencePercentage', 0)}%")
                print(f"      Country: {ip_data.get('countryCode', 'Unknown')}")
                print(f"      ISP: {ip_data.get('isp', 'Unknown')}")
                print(f"      Total Reports: {ip_data.get('totalReports', 0)}")
                
                if ip_data.get('abuseConfidencePercentage', 0) > 0:
                    print(f"      ⚠️  Potentially malicious IP detected!")
                    
            else:
                print(f"   ❌ {ip}: API Error {response.status_code}")
                
        except Exception as e:
            print(f"   ❌ {ip}: {str(e)}")

def test_shodan_api():
    """Test Shodan API functionality"""
    print("\n🌐 Testing Shodan API...")
    
    # Test API info first
    try:
        response = requests.get(
            'https://api.shodan.io/api-info',
            params={'key': SHODAN_KEY},
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ API Info:")
            print(f"      Plan: {data.get('plan', 'Unknown')}")
            print(f"      Query Credits: {data.get('query_credits', 'Unknown')}")
            print(f"      Scan Credits: {data.get('scan_credits', 'Unknown')}")
        else:
            print(f"   ❌ API Info Error: {response.status_code}")
            return
            
    except Exception as e:
        print(f"   ❌ API Info failed: {e}")
        return
    
    # Test host lookup for common services
    test_hosts = [
        '8.8.8.8',  # Google DNS
        '1.1.1.1',  # Cloudflare DNS
    ]
    
    for host in test_hosts:
        try:
            response = requests.get(
                f'https://api.shodan.io/shodan/host/{host}',
                params={'key': SHODAN_KEY},
                timeout=15
            )
            
            if response.status_code == 200:
                data = response.json()
                print(f"   ✅ {host}:")
                print(f"      Organization: {data.get('org', 'Unknown')}")
                print(f"      Country: {data.get('country_name', 'Unknown')}")
                print(f"      Open Ports: {len(data.get('ports', []))}")
                
                # Show some port details
                for port_data in data.get('data', [])[:3]:  # First 3 services
                    port = port_data.get('port')
                    service = port_data.get('product', port_data.get('_shodan', {}).get('module', 'Unknown'))
                    print(f"         Port {port}: {service}")
                    
            elif response.status_code == 404:
                print(f"   ⚠️  {host}: No data available")
            else:
                print(f"   ❌ {host}: API Error {response.status_code}")
                
        except Exception as e:
            print(f"   ❌ {host}: {str(e)}")

def test_virustotal_api():
    """Test VirusTotal API functionality"""
    print("\n🦠 Testing VirusTotal API...")
    
    # Test domain analysis
    test_domains = [
        'google.com',      # Known clean domain
        'facebook.com',    # Known clean domain
    ]
    
    for domain in test_domains:
        try:
            response = requests.get(
                'https://www.virustotal.com/vtapi/v2/domain/report',
                params={
                    'apikey': VIRUSTOTAL_KEY,
                    'domain': domain
                },
                timeout=15
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('response_code') == 1:
                    # Calculate detection ratio for categories
                    categories = data.get('categories', [])
                    subdomains = len(data.get('subdomains', []))
                    detected_urls = len(data.get('detected_urls', []))
                    
                    print(f"   ✅ {domain}:")
                    print(f"      Categories: {', '.join(categories) if categories else 'None'}")
                    print(f"      Subdomains: {subdomains}")
                    print(f"      Detected URLs: {detected_urls}")
                    
                    if detected_urls > 0:
                        print(f"      ⚠️  {detected_urls} malicious URLs found!")
                else:
                    print(f"   ℹ️  {domain}: No data available")
                    
            elif response.status_code == 204:
                print(f"   ⏱️  {domain}: Rate limit reached")
            else:
                print(f"   ❌ {domain}: API Error {response.status_code}")
                
        except Exception as e:
            print(f"   ❌ {domain}: {str(e)}")

def test_integrated_threat_intelligence():
    """Test the integrated threat intelligence agent"""
    print("\n🧠 Testing Integrated Threat Intelligence Agent...")
    
    try:
        import sys
        import os
        sys.path.append(os.path.dirname(os.path.abspath(__file__)))
        
        from enhancements.threat_intelligence import ThreatIntelligenceAgent
        
        agent = ThreatIntelligenceAgent()
        status = agent.get_agent_status()
        
        print(f"   ✅ Agent Status:")
        print(f"      API Keys Configured: {status['api_keys_configured']}/3")
        print(f"      Available Sources: {len(status['available_sources'])}")
        
        # Test async reputation analysis
        async def test_async_analysis():
            try:
                result = await agent.analyze_target_reputation("https://testphp.vulnweb.com")
                print(f"   ✅ Test Analysis Results:")
                print(f"      Risk Score: {result.get('threat_score', 'Unknown')}")
                print(f"      Domain: {result.get('domain', 'Unknown')}")
                print(f"      IP: {result.get('ip_address', 'Unknown')}")
                return result
            except Exception as e:
                print(f"   ❌ Async analysis failed: {e}")
                return None
        
        # Run async test
        import asyncio
        result = asyncio.run(test_async_analysis())
        
        if result:
            print(f"   🎯 Threat Intelligence working correctly!")
        
    except ImportError as e:
        print(f"   ❌ Could not import threat intelligence agent: {e}")
    except Exception as e:
        print(f"   ❌ Threat intelligence test failed: {e}")

def test_cve_integration():
    """Test CVE database integration"""
    print("\n🚨 Testing CVE Database Integration...")
    
    try:
        response = requests.get('https://cve.circl.lu/api/last/5', timeout=10)
        if response.status_code == 200:
            cve_data = response.json()
            print(f"   ✅ CVE Database accessible")
            print(f"   Recent CVEs: {len(cve_data)}")
            
            # Show latest CVE
            if cve_data:
                latest_cve = cve_data[0]
                print(f"   📋 Latest CVE: {latest_cve.get('id', 'Unknown')}")
                print(f"      CVSS: {latest_cve.get('cvss', 'Unknown')}")
                summary = latest_cve.get('summary', '')[:100] + '...' if len(latest_cve.get('summary', '')) > 100 else latest_cve.get('summary', '')
                print(f"      Summary: {summary}")
        else:
            print(f"   ❌ CVE Database error: {response.status_code}")
    except Exception as e:
        print(f"   ❌ CVE Database test failed: {e}")

def main():
    """Main test function"""
    print("🚀 AI Bug Bounty Scanner - Triple API Integration Test")
    print("=" * 65)
    print(f"🕐 Test Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # Run all tests
    test_abuseipdb_api()
    test_shodan_api()
    test_virustotal_api()
    test_cve_integration()
    test_integrated_threat_intelligence()
    
    print("\n" + "=" * 65)
    print("🎯 Triple API Integration Test Complete!")
    print("\n📋 Summary:")
    print("- AbuseIPDB: IP reputation and abuse scoring")
    print("- Shodan: Internet device and service discovery")
    print("- VirusTotal: Domain/URL malware detection")
    print("- CVE Database: Latest vulnerability intelligence")
    print("- Integrated Agent: Combined threat intelligence")
    
    print("\n🚀 Ready for Ultimate Enhanced Scanning!")
    print("Run 'python backend-app.py' to start the enhanced scanner")

if __name__ == "__main__":
    main()
