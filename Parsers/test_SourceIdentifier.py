#  This file is part of the cve_investigator, a tool aimed at exploring CVEs
#  Copyright (c) 2025 Philippe Godbout
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.

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
