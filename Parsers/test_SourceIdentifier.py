"""
This file is part of the VulnerabilityManager project, a tool aimed at managing vulnerabilities
Copyright (C) 2025  Philippe Godbout
"""

import unittest

import SourceIdentifier

class TestSourceIdentifier(unittest.TestCase):

    def test_SourceIdentifier_offline(self):
        """
        Validates The initialisation and the use of a SourceIdentifier
        """
        si = SourceIdentifier.SourceIdentifier(use_api_key=False, networked=False)
        r = si.get_source_identifier('8254265b-2729-46b6-b9e3-3dfca2d5bfca')
        self.assertEqual('MITRE',r['name'])

        r = si.get_source_identifier('RogerRabbit')
        self.assertEqual(None, None)

    def test_SourceIdentifier_online_with_API_Key(self):
        """
        Validates The initialisation and the use of a SourceIdentifier - Going online for update
        """
        si = SourceIdentifier.SourceIdentifier(use_api_key=True, networked=True)
        r = si.get_source_identifier('8254265b-2729-46b6-b9e3-3dfca2d5bfca')
        self.assertEqual('MITRE', r['name'])

        r = si.get_source_identifier('RogerRabbit')
        self.assertEqual(None, None)

    def test_SourceIdentifier_online_without_API_Key(self):
        """
        Validates The initialisation and the use of a SourceIdentifier - Going online for update
        """
        si = SourceIdentifier.SourceIdentifier(use_api_key=False, networked=True)
        r = si.get_source_identifier('8254265b-2729-46b6-b9e3-3dfca2d5bfca')
        self.assertEqual('MITRE', r['name'])

        r = si.get_source_identifier('RogerRabbit')
        self.assertEqual(None, None)
