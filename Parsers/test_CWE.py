"""
This file is part of the VulnerabilityManager project, a tool aimed at managing vulnerabilities
Copyright (C) 2025  Philippe Godbout
"""

import unittest

import CWE

class TestCWE(unittest.TestCase):

    def test_CWE(self):
        """
        Validates that a valid application CPE can be loaded
        """
        c = CWE.CWE()
        self.assertEqual(c.description_for_code(338),
                         'Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)')
        self.assertEqual(c.description_for_code('338'),
                         'Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)')
        self.assertEqual(c.description_for_code('CWE-338'),
                         'Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)')
        self.assertEqual(c.description_for_code('cwe-338'),
                         'Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)')
        self.assertEqual(c.description_for_code('not a cwe'),
                         None)
