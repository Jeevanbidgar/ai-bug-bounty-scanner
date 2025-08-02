#!/usr/bin/env python3
"""
Test script for the Discovery Agent

This script validates the Discovery Agent's functionality by testing it against
known applications and verifying that it correctly discovers and analyzes
application structure, forms, and technology stacks.
"""

import asyncio
import json
import logging
import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agents.discovery_agent import DiscoveryAgent

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

async def test_discovery_agent():
    """Test the Discovery Agent with various targets"""
    
    # Test targets
    test_targets = [
        {
            'url': 'http://localhost/dvwa',
            'name': 'DVWA (Local)',
            'credentials': {'username': 'admin', 'password': 'password'},
            'expected_forms': ['login'],
            'expected_tech': ['php', 'mysql']
        },
        {
            'url': 'https://httpbin.org',
            'name': 'HTTPBin (Public Test)',
            'credentials': None,
            'expected_forms': [],
            'expected_tech': []
        }
    ]
    
    for target in test_targets:
        logger.info(f"\n{'='*60}")
        logger.info(f"Testing Discovery Agent against: {target['name']}")
        logger.info(f"Target URL: {target['url']}")
        logger.info(f"{'='*60}")
        
        try:
            # Initialize Discovery Agent
            discovery_agent = DiscoveryAgent()
            
            # Run discovery scan
            logger.info("🔍 Starting discovery scan...")
            results = await discovery_agent.scan_target(
                target['url'], 
                target['credentials']
            )
            
            # Validate results
            await validate_discovery_results(results, target)
            
            # Display summary
            display_discovery_summary(results)
            
        except Exception as e:
            logger.error(f"❌ Discovery test failed for {target['name']}: {e}")
            logger.error(f"Error details: {type(e).__name__}: {str(e)}")

async def validate_discovery_results(results, target):
    """Validate discovery results against expected outcomes"""
    logger.info("\n📊 Validating discovery results...")
    
    discovery_context = results.get('discovery_context')
    if not discovery_context:
        logger.error("❌ No discovery context found in results")
        return False
    
    # Validate basic discovery
    pages_discovered = discovery_context.get('pages_discovered', [])
    forms_discovered = discovery_context.get('forms_discovered', [])
    technology_stack = discovery_context.get('technology_stack', {})
    
    logger.info(f"📄 Pages discovered: {len(pages_discovered)}")
    logger.info(f"📝 Forms discovered: {len(forms_discovered)}")
    
    # Validate form discovery
    if target['expected_forms']:
        form_types = [form.get('form_type', '') for form in forms_discovered]
        for expected_form in target['expected_forms']:
            if expected_form in form_types:
                logger.info(f"✅ Expected form type '{expected_form}' found")
            else:
                logger.warning(f"⚠️ Expected form type '{expected_form}' not found")
    
    # Validate technology stack
    if target['expected_tech']:
        web_server = technology_stack.get('web_server', '').lower()
        web_framework = technology_stack.get('web_framework', '').lower()
        programming_language = technology_stack.get('programming_language', '').lower()
        
        for expected_tech in target['expected_tech']:
            if (expected_tech in web_server or 
                expected_tech in web_framework or 
                expected_tech in programming_language):
                logger.info(f"✅ Expected technology '{expected_tech}' found")
            else:
                logger.warning(f"⚠️ Expected technology '{expected_tech}' not found")
    
    # Validate authentication system
    auth_system = discovery_context.get('authentication_system', {})
    if target['credentials']:
        if auth_system.get('login_url'):
            logger.info("✅ Authentication system detected")
        else:
            logger.warning("⚠️ Authentication system not detected")
    
    # Validate site map
    site_map = discovery_context.get('site_map', {})
    if site_map.get('pages'):
        logger.info(f"✅ Site map built with {len(site_map['pages'])} pages")
    else:
        logger.warning("⚠️ Site map not built")
    
    # Validate input vectors
    input_vectors = discovery_context.get('input_vectors', [])
    if input_vectors:
        logger.info(f"✅ Input vectors identified: {len(input_vectors)}")
    else:
        logger.info("ℹ️ No input vectors identified (may be normal for static sites)")
    
    return True

def display_discovery_summary(results):
    """Display a summary of discovery results"""
    logger.info("\n📋 Discovery Summary:")
    logger.info("-" * 40)
    
    discovery_summary = results.get('discovery_summary', {})
    
    summary_items = [
        ('Total Pages', discovery_summary.get('total_pages', 0)),
        ('Total Forms', discovery_summary.get('total_forms', 0)),
        ('Input Vectors', discovery_summary.get('total_input_vectors', 0)),
        ('API Endpoints', discovery_summary.get('total_api_endpoints', 0)),
        ('Auth Required', discovery_summary.get('authentication_required', False)),
        ('Tech Stack ID', discovery_summary.get('technology_stack_identified', False)),
        ('Discovery Time', f"{discovery_summary.get('discovery_completion_time', 0):.2f}s"),
        ('URLs Discovered', discovery_summary.get('urls_discovered', 0)),
        ('Pages Analyzed', discovery_summary.get('pages_analyzed', 0))
    ]
    
    for label, value in summary_items:
        logger.info(f"{label:20}: {value}")
    
    # Display technology stack if available
    discovery_context = results.get('discovery_context', {})
    tech_stack = discovery_context.get('technology_stack', {})
    
    if any([tech_stack.get('web_server'), tech_stack.get('web_framework'), tech_stack.get('programming_language')]):
        logger.info("\n⚙️ Technology Stack:")
        logger.info("-" * 20)
        if tech_stack.get('web_server'):
            logger.info(f"Web Server: {tech_stack['web_server']}")
        if tech_stack.get('web_framework'):
            logger.info(f"Framework: {tech_stack['web_framework']}")
        if tech_stack.get('programming_language'):
            logger.info(f"Language: {tech_stack['programming_language']}")
        if tech_stack.get('database'):
            logger.info(f"Database: {tech_stack['database']}")
        if tech_stack.get('cms'):
            logger.info(f"CMS: {tech_stack['cms']}")

async def test_discovery_agent_validation():
    """Test specific validation scenarios"""
    logger.info("\n🧪 Testing Discovery Agent validation scenarios...")
    
    # Test with invalid URL
    logger.info("\nTesting with invalid URL...")
    try:
        discovery_agent = DiscoveryAgent()
        results = await discovery_agent.scan_target("http://invalid-domain-that-does-not-exist-12345.com")
        logger.error("❌ Should have failed with invalid URL")
    except Exception as e:
        logger.info(f"✅ Correctly failed with invalid URL: {e}")
    
    # Test with localhost (if available)
    logger.info("\nTesting with localhost...")
    try:
        discovery_agent = DiscoveryAgent()
        results = await discovery_agent.scan_target("http://localhost")
        logger.info("✅ Localhost test completed")
    except Exception as e:
        logger.warning(f"⚠️ Localhost test failed (may be expected): {e}")

def main():
    """Main test function"""
    logger.info("🚀 Starting Discovery Agent Tests")
    logger.info("=" * 60)
    
    try:
        # Run main discovery tests
        asyncio.run(test_discovery_agent())
        
        # Run validation tests
        asyncio.run(test_discovery_agent_validation())
        
        logger.info("\n✅ All Discovery Agent tests completed!")
        
    except KeyboardInterrupt:
        logger.info("\n⏹️ Tests interrupted by user")
    except Exception as e:
        logger.error(f"\n❌ Test suite failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()