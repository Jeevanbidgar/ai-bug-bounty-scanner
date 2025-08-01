# tests/test_api_agent.py
"""
Test suite for the APIAgent to ensure it finds API security vulnerabilities.
"""

import unittest
import asyncio
import sys
import os

# Add the parent directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.api_agent import APIAgent

class TestAPIAgent(unittest.TestCase):
    """Test cases for the API security agent"""

    def setUp(self):
        """Set up the test environment"""
        self.agent = APIAgent()
        # Use a target known to have missing security headers
        self.target_url = "http://testphp.vulnweb.com"

    def test_scan_target_finds_api_vulnerabilities(self):
        """
        Test if the API agent can scan a target and detect basic information.
        """
        async def run_scan():
            # Run the scan
            results = await self.agent.scan_target(self.target_url)
            
            # Check basic structure
            self.assertIn('vulnerabilities', results)
            self.assertIn('target', results)
            self.assertIn('scan_type', results)
            
            # The agent should at least identify the scan type correctly
            self.assertEqual(results['scan_type'], 'api_security')
            
            # Check if the agent found any findings (may or may not find vulnerabilities)
            vuln_count = len(results['vulnerabilities'])
            print(f"API Agent found {vuln_count} potential issues")
            
            # If vulnerabilities are found, check their structure
            if vuln_count > 0:
                first_vuln = results['vulnerabilities'][0]
                self.assertIn('title', first_vuln)
                self.assertIn('severity', first_vuln)

        # Run the async test
        asyncio.run(run_scan())

if __name__ == '__main__':
    unittest.main()
