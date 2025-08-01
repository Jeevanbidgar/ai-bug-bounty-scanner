# tests/test_webapp_agent.py
"""
Test suite for the WebAppAgent to ensure it finds web application vulnerabilities.
"""

import unittest
import asyncio
import sys
import os

# Add the parent directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.webapp_agent import WebAppAgent

class TestWebAppAgent(unittest.TestCase):
    """Test cases for the web application security agent"""

    def setUp(self):
        """Set up the test environment"""
        self.agent = WebAppAgent()
        # A target known to be vulnerable to XSS and SQLi
        self.target_url = "http://testphp.vulnweb.com/listproducts.php?cat=1"

    def test_scan_target_finds_xss_and_sql_injection(self):
        """
        Test if the web app agent can find XSS and SQL injection vulnerabilities.
        """
        async def run_scan():
            # Run the scan
            results = await self.agent.scan_target(self.target_url)
            
            # Check for vulnerabilities
            self.assertIn('vulnerabilities', results)
            self.assertGreater(len(results['vulnerabilities']), 0, "WebApp Agent should find vulnerabilities.")
            
            # Check for specific vulnerability types
            vuln_titles = [v['title'] for v in results['vulnerabilities']]
            self.assertTrue(any("Cross-Site Scripting" in title for title in vuln_titles), "Should find at least one XSS vulnerability.")
            self.assertTrue(any("SQL Injection" in title for title in vuln_titles), "Should find at least one SQL Injection vulnerability.")

        # Run the async test
        asyncio.run(run_scan())

if __name__ == '__main__':
    unittest.main()
