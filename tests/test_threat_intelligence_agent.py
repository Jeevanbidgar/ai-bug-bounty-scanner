# tests/test_threat_intelligence_agent.py
"""
Test suite for the ThreatIntelligenceAgent to ensure it gathers threat intelligence.
"""

import unittest
import asyncio
import sys
import os

# Add the parent directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Conditional import to handle cases where enhancements are not available
try:
    from enhancements.threat_intelligence import ThreatIntelligenceAgent
    ENHANCEMENTS_AVAILABLE = True
except ImportError:
    ENHANCEMENTS_AVAILABLE = False

@unittest.skipIf(not ENHANCEMENTS_AVAILABLE, "Threat Intelligence module not available")
class TestThreatIntelligenceAgent(unittest.TestCase):
    """Test cases for the threat intelligence agent"""

    def test_gather_intelligence_returns_data(self):
        """
        Test if the threat intelligence agent can gather data for a domain.
        """
        async def run_gather():
            # Create agent inside async context
            agent = ThreatIntelligenceAgent()
            domain = "vulnweb.com"
            
            try:
                # Run the intelligence gathering using analyze_target_reputation
                results = await agent.analyze_target_reputation(f"http://{domain}")
                
                # Check that we get some intelligence data back
                self.assertIn('domain', results)
                self.assertIn('threat_score', results)
                
                # Check basic structure
                self.assertIsInstance(results['threat_score'], int)
                self.assertGreaterEqual(results['threat_score'], 0)
                self.assertLessEqual(results['threat_score'], 100)
                
            finally:
                # ThreatIntelligenceAgent doesn't have a close method, so we skip cleanup
                pass

        # Run the async test
        asyncio.run(run_gather())

if __name__ == '__main__':
    unittest.main()
