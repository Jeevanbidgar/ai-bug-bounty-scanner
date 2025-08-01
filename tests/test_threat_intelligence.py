# Test Threat Intelligence Integration
"""
Quick test script to verify threat intelligence functionality
"""

import asyncio
import sys
import os

# Add the parent directory to the path so we can import the modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from enhancements.threat_intelligence import ThreatIntelligenceAgent
    print("✅ Threat Intelligence module imported successfully")
except ImportError as e:
    print(f"❌ Failed to import threat intelligence: {e}")
    print("Install dependencies: pip install aiohttp requests")
    sys.exit(1)

async def test_threat_intelligence():
    """Test threat intelligence functionality"""
    
    print("\n🛡️ Testing Threat Intelligence Agent...")
    
    # Initialize the agent
    threat_agent = ThreatIntelligenceAgent()
    
    # Check agent status
    status = threat_agent.get_agent_status()
    print(f"📊 Agent Status: {status['status']}")
    print(f"🔑 API Keys Configured: {status['api_keys_configured']}/3")
    print(f"📡 Threat Feeds Active: {status['threat_feeds_active']}")
    
    # Test targets for demonstration
    test_targets = [
        "https://testphp.vulnweb.com",  # Safe test target
        "https://google.com",          # Clean reputation
        "http://malware.testing.google.test"  # Google's malware test domain
    ]
    
    for target in test_targets:
        print(f"\n🎯 Testing target: {target}")
        try:
            # Analyze target reputation
            reputation_data = await threat_agent.analyze_target_reputation(target)
            
            print(f"   📍 Domain: {reputation_data['domain']}")
            print(f"   🌐 IP Address: {reputation_data['ip_address']}")
            print(f"   ⚠️  Threat Score: {reputation_data['threat_score']}/100")
            
            # Show IP reputation details if available
            ip_rep = reputation_data.get('reputation_sources', {}).get('ip', {})
            if ip_rep.get('score', 0) > 0:
                print(f"   🚨 IP Abuse Score: {ip_rep['score']}%")
                print(f"   📊 Abuse Reports: {ip_rep['abuse_reports']}")
                print(f"   🌍 Country: {ip_rep['country']}")
                print(f"   🏢 ISP: {ip_rep['isp']}")
            
            # Show recommendations
            recommendations = reputation_data.get('recommendations', [])
            if recommendations:
                print(f"   💡 Recommendations:")
                for rec in recommendations[:3]:  # Show first 3 recommendations
                    print(f"      - {rec}")
            
            # Show CVE matches
            cve_matches = reputation_data.get('cve_matches', [])
            if cve_matches:
                print(f"   🔍 CVE Matches Found: {len(cve_matches)}")
                
        except Exception as e:
            print(f"   ❌ Error analyzing {target}: {e}")
    
    # Test latest vulnerabilities
    print(f"\n🔍 Testing CVE Database Integration...")
    try:
        latest_vulns = await threat_agent.get_latest_vulnerabilities(['web application', 'http'])
        print(f"   📈 Found {len(latest_vulns)} recent vulnerabilities")
        
        if latest_vulns:
            print(f"   📝 Sample vulnerability:")
            sample = latest_vulns[0]
            print(f"      - ID: {sample.get('id', 'N/A')}")
            print(f"      - Severity: {sample.get('severity', 'N/A')}")
            print(f"      - CVSS: {sample.get('cvss', 'N/A')}")
            print(f"      - Summary: {sample.get('summary', 'N/A')[:100]}...")
            
    except Exception as e:
        print(f"   ❌ Error testing CVE database: {e}")
    
    # Test vulnerability enrichment
    print(f"\n🔬 Testing Vulnerability Enrichment...")
    try:
        sample_vuln = {
            'title': 'Cross-Site Scripting (XSS)',
            'severity': 'High',
            'cvss': 7.5,
            'description': 'XSS vulnerability found in web application'
        }
        
        enriched = await threat_agent.enrich_vulnerability_data(sample_vuln)
        threat_intel = enriched.get('threat_intel', {})
        
        print(f"   💡 Mitigation Priority: {threat_intel.get('mitigation_priority', 'N/A')}")
        print(f"   🎯 Attack Patterns: {threat_intel.get('attack_patterns', [])}")
        print(f"   🔧 Exploitability: {threat_intel.get('exploitability', {}).get('exploit_complexity', 'N/A')}")
        
    except Exception as e:
        print(f"   ❌ Error testing vulnerability enrichment: {e}")
    
    print(f"\n✅ Threat Intelligence testing completed!")

def main():
    """Main test function"""
    
    print("🚀 AI Bug Bounty Scanner - Threat Intelligence Test")
    print("=" * 60)
    
    # Check if we have the required dependencies
    try:
        import aiohttp
        import requests
        print("✅ Required dependencies found")
    except ImportError as e:
        print(f"❌ Missing dependencies: {e}")
        print("Install with: pip install aiohttp requests")
        return
    
    # Run the async test
    try:
        asyncio.run(test_threat_intelligence())
    except KeyboardInterrupt:
        print("\n⚠️  Test interrupted by user")
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
