#!/usr/bin/env python3
"""
Quick test for the scanning agents
"""

import asyncio
import time
from agents import ReconAgent, WebAppAgent

async def quick_test():
    """Quick test of scanning agents"""
    
    print("🚀 Quick Scanning Test")
    print("=" * 40)
    
    target = "https://httpbin.org"
    
    # Test Recon Agent
    print(f"🔍 Testing Recon Agent on {target}...")
    start_time = time.time()
    
    try:
        recon_agent = ReconAgent()
        recon_results = await recon_agent.scan_target(target)
        recon_time = time.time() - start_time
        
        print(f"✅ Recon completed in {recon_time:.1f}s")
        print(f"  Vulnerabilities: {len(recon_results.get('vulnerabilities', []))}")
        print(f"  Open ports: {recon_results.get('port_info', {}).get('open_ports', [])}")
        
    except Exception as e:
        print(f"❌ Recon failed: {e}")
    
    # Test Web App Agent
    print(f"\n🌐 Testing Web App Agent on {target}...")
    start_time = time.time()
    
    try:
        webapp_agent = WebAppAgent()
        webapp_results = await webapp_agent.scan_target(target)
        webapp_time = time.time() - start_time
        
        print(f"✅ Web App scan completed in {webapp_time:.1f}s")
        print(f"  Vulnerabilities: {len(webapp_results.get('vulnerabilities', []))}")
        print(f"  Pages crawled: {webapp_results.get('crawl_data', {}).get('pages_crawled', 0)}")
        
    except Exception as e:
        print(f"❌ Web App scan failed: {e}")
    
    print("\n✅ Quick test completed!")

if __name__ == "__main__":
    asyncio.run(quick_test())
