# tests/test_security_validator.py
"""
Test suite for the SecurityValidator to ensure it correctly validates targets and configurations.
"""

import unittest
import sys
import os

# Add the parent directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.security_validator import SecurityValidator

class TestSecurityValidator(unittest.TestCase):
    """Test cases for the security validator"""

    def test_validate_target_with_valid_url(self):
        """
        Test that a valid URL passes validation.
        """
        try:
            SecurityValidator.validate_target("http://example.com")
            # No exception should be raised
            self.assertTrue(True)
        except ValueError:
            self.fail("validate_target() raised ValueError unexpectedly!")

    def test_validate_target_with_invalid_url(self):
        """
        Test that an invalid URL raises a ValueError.
        """
        with self.assertRaises(ValueError):
            SecurityValidator.validate_target("not_a_valid_url")

    def test_validate_target_with_disallowed_ip(self):
        """
        Test that a disallowed IP address raises a ValueError.
        """
        with self.assertRaises(ValueError):
            SecurityValidator.validate_target("http://127.0.0.1")

    def test_get_safe_scan_config(self):
        """
        Test that the safe scan configuration is returned correctly.
        """
        config = SecurityValidator.get_safe_scan_config()
        self.assertIn('timeout', config)
        self.assertIn('max_redirects', config)
        self.assertIn('user_agent', config)
        self.assertLessEqual(config['timeout'], 10)

if __name__ == '__main__':
    unittest.main()
