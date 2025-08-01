# tests/test_recon_agent.py
"""
Test suite for the ReconAgent to ensure it finds vulnerabilities.
"""

import unittest
import asyncio
import sys
import os

# Add the parent directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.recon_agent import ReconAgent

class TestReconAgent(unittest.TestCase):
    """Test cases for the reconnaissance agent"""

    def setUp(self):
        """Set up the test environment"""
        self.agent = ReconAgent()
        # Test target known to have open ports and specific configurations
        self.target_url = "http://testphp.vulnweb.com/"

    def test_scan_target_finds_vulnerabilities(self):
        """
        Test if the recon agent can scan a target and identify potential vulnerabilities.
        """
        async def run_scan():
            # Run the scan
            results = await self.agent.scan_target(self.target_url)
            
            # Check for vulnerabilities
            self.assertIn('vulnerabilities', results)
            self.assertGreater(len(results['vulnerabilities']), 0, "Recon Agent should find at least one vulnerability.")
            
            # Verify that port scan found open ports
            self.assertIn('port_info', results)
            self.assertGreater(len(results['port_info'].get('open_ports', [])), 0, "Port scan should find open ports.")
            
            # Verify technology detection
            self.assertIn('technologies', results)
            self.assertNotEqual(results['technologies'].get('server', 'unknown'), 'unknown', "Technology detection should identify the server.")

        # Run the async test
        asyncio.run(run_scan())

if __name__ == '__main__':
    unittest.main()
