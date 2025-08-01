# tests/test_network_agent.py
"""
Test suite for the NetworkAgent to ensure it identifies network-level vulnerabilities.
"""

import unittest
import asyncio
import sys
import os

# Add the parent directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.network_agent import NetworkAgent

class TestNetworkAgent(unittest.TestCase):
    """Test cases for the network security agent"""

    def setUp(self):
        """Set up the test environment"""
        self.agent = NetworkAgent()
        # A target with known open ports and services
        self.target_url = "http://testphp.vulnweb.com/"

    def test_scan_target_finds_network_vulnerabilities(self):
        """
        Test if the network agent can find vulnerabilities like open ports and weak SSL/TLS ciphers.
        """
        async def run_scan():
            # Run the scan
            results = await self.agent.scan_target(self.target_url)
            
            # Check for vulnerabilities
            self.assertIn('vulnerabilities', results)
            self.assertGreater(len(results['vulnerabilities']), 0, "Network Agent should find vulnerabilities.")
            
            # Check for specific network findings
            self.assertIn('port_scan_results', results)
            self.assertGreater(len(results['port_scan_results'].get('open_ports', [])), 0, "Should identify open ports.")
            
            # Check for SSL/TLS findings if applicable
            if "443" in results['port_scan_results'].get('open_ports', []):
                self.assertIn('ssl_tls_results', results)
                self.assertGreater(len(results['ssl_tls_results'].get('supported_ciphers', [])), 0, "Should list supported SSL/TLS ciphers.")

        # Run the async test
        asyncio.run(run_scan())

if __name__ == '__main__':
    unittest.main()
