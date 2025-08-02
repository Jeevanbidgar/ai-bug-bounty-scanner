# Quick Setup & Test Script for Enhanced AI Bug Bounty Scanner
"""
Run this script to set up and test the enhanced features
"""

import os
import sys
import subprocess
import urllib.request
import json

def check_python_version():
    """Check if Python version is compatible"""
    version = sys.version_info
    print(f"🐍 Python Version: {version.major}.{version.minor}.{version.micro}")
    
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print("❌ Python 3.8+ required for enhanced features")
        return False
    else:
        print("✅ Python version compatible")
        return True

def install_dependencies():
    """Install required dependencies"""
    print("\n📦 Installing dependencies...")
    
    basic_deps = [
        "flask",
        "flask-sqlalchemy", 
        "flask-cors",
        "requests",
        "beautifulsoup4"
    ]
    
    enhanced_deps = [
        "aiohttp",
        "scikit-learn",
        "numpy",
        "pandas",
        "matplotlib"
    ]
    
    optional_deps = [
        "tensorflow",
        "transformers",
        "seaborn"
    ]
    
    # Install basic dependencies
    for dep in basic_deps:
        try:
            print(f"   Installing {dep}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", dep], 
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"   ✅ {dep} installed")
        except subprocess.CalledProcessError:
            print(f"   ❌ Failed to install {dep}")
    
    # Install enhanced dependencies
    for dep in enhanced_deps:
        try:
            print(f"   Installing {dep}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", dep], 
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"   ✅ {dep} installed")
        except subprocess.CalledProcessError:
            print(f"   ⚠️  Failed to install {dep} (optional)")
    
    # Try to install optional ML dependencies
    print(f"   Installing optional ML dependencies...")
    for dep in optional_deps:
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", dep], 
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"   ✅ {dep} installed")
        except subprocess.CalledProcessError:
            print(f"   ⚠️  Failed to install {dep} (optional ML feature)")

def test_enhanced_features():
    """Test if enhanced features are working"""
    print("\n🧪 Testing enhanced features...")
    
    # Test threat intelligence
    try:
        sys.path.append(os.path.dirname(os.path.abspath(__file__)))
        from enhancements.threat_intelligence import ThreatIntelligenceAgent
        
        agent = ThreatIntelligenceAgent()
        status = agent.get_agent_status()
        print(f"✅ Threat Intelligence Agent: {status['api_keys_configured']}/3 API keys")
        
    except Exception as e:
        print(f"❌ Threat Intelligence test failed: {e}")
    
    # Test enhanced security agent
    try:
        from enhancements.enhanced_security_agent import EnhancedSecurityAgent
        agent = EnhancedSecurityAgent()
        status = agent.get_agent_status()
        print(f"✅ Enhanced Security Agent: {len(status['capabilities'])} capabilities")
        
    except Exception as e:
        print(f"❌ Enhanced Security Agent test failed: {e}")
    
    # Test ML agent (optional)
    try:
        from enhancements.ml_agent import MLSecurityAgent
        agent = MLSecurityAgent()
        status = agent.get_agent_status()
        print(f"✅ ML Security Agent: {status['version']}")
        
    except Exception as e:
        print(f"⚠️  ML Security Agent not available: {e}")

def test_api_connectivity():
    """Test API connectivity"""
    print("\n🌐 Testing API connectivity...")
    
    # Test AbuseIPDB API
    abuseipdb_key = "3f0fa7f9204bd618d24f7b2be233382f0a37cc16ef41c36976b3ee87611c844ecc8b3c2fbe3a3ba3"
    shodan_key = "gB4ThIkHfWApnpDawWLGnq9Tc7TqvuDw"
    virustotal_key = "a9f4b3641ade0460ce11d4e9c81f066959a97bc62a3f155efb4ccf10b8efda2d"
    
    try:
        import requests
        headers = {
            'Key': abuseipdb_key,
            'Accept': 'application/json'
        }
        
        # Test with a known clean IP (Google DNS)
        response = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            params={'ipAddress': '8.8.8.8', 'maxAgeInDays': 90},
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            print("✅ AbuseIPDB API working")
            print(f"   Test IP 8.8.8.8 abuse score: {data.get('data', {}).get('abuseConfidencePercentage', 0)}%")
        else:
            print(f"⚠️  AbuseIPDB API response: {response.status_code}")
            
    except Exception as e:
        print(f"❌ AbuseIPDB API test failed: {e}")
    
    # Test Shodan API
    try:
        response = requests.get(
            'https://api.shodan.io/api-info',
            params={'key': shodan_key},
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            print("✅ Shodan API working")
            print(f"   API Plan: {data.get('plan', 'Unknown')}")
            print(f"   Query Credits: {data.get('query_credits', 'Unknown')}")
        else:
            print(f"⚠️  Shodan API response: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Shodan API test failed: {e}")
    
    # Test VirusTotal API
    try:
        response = requests.get(
            'https://www.virustotal.com/vtapi/v2/domain/report',
            params={'apikey': virustotal_key, 'domain': 'google.com'},
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            print("✅ VirusTotal API working")
            if data.get('response_code') == 1:
                print(f"   Domain analysis successful")
            else:
                print(f"   Domain not found in database")
        elif response.status_code == 204:
            print("✅ VirusTotal API working (rate limited)")
        else:
            print(f"⚠️  VirusTotal API response: {response.status_code}")
            
    except Exception as e:
        print(f"❌ VirusTotal API test failed: {e}")
    
    # Test CVE database
    try:
        response = requests.get('https://cve.circl.lu/api/last/1', timeout=10)
        if response.status_code == 200:
            cve_data = response.json()
            print(f"✅ CVE Database working - {len(cve_data)} recent CVEs")
        else:
            print(f"⚠️  CVE Database response: {response.status_code}")
    except Exception as e:
        print(f"❌ CVE Database test failed: {e}")

def create_test_scan():
    """Create a test scan to verify everything works"""
    print("\n🚀 Creating test scan...")
    
    try:
        # Import the backend modules
        sys.path.append(os.path.dirname(os.path.abspath(__file__)))
     
        # So, use importlib to import it dynamically
        import importlib.util
        backend_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend-app.py")
        spec = importlib.util.spec_from_file_location("backend_app", backend_path)
        backend_app = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(backend_app)
        app = backend_app.app
        db = backend_app.db        
        # Test database creation
        with app.app_context():
            db.create_all()
            print("✅ Database setup successful")
            
    except Exception as e:
        print(f"❌ Backend test failed: {e}")

def main():
    """Main setup function"""
    print("🚀 AI Bug Bounty Scanner - Enhanced Setup & Test")
    print("=" * 60)
    
    # Check Python version
    if not check_python_version():
        return
    
    # Install dependencies
    install_dependencies()
    
    # Test enhanced features
    test_enhanced_features()
    
    # Test API connectivity
    test_api_connectivity()
    
    # Final instructions
    print("\n🎉 Setup Complete!")
    print("\n📋 Next Steps:")
    print("1. Start backend: python backend-app.py")
    print("2. Start frontend: python -m http.server 3000")
    print("3. Open browser: http://localhost:3000")
    print("4. Try an Enhanced Scan on https://testphp.vulnweb.com")
    
    print("\n💡 Enhanced Features Available:")
    print("- 🔬 Advanced XSS/SQLi detection (15+ payloads)")
    print("- 🛡️  Triple threat intelligence (AbuseIPDB + Shodan + VirusTotal)")
    print("- 🔍 SSL/TLS security analysis")
    print("- 🚨 CVE database integration")
    print("- 🌐 Internet device intelligence")
    print("- 🦠 Malware & domain reputation")
    print("- 📊 Enhanced reporting")

if __name__ == "__main__":
    main()
