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

import json
import unittest

import CVSSMetricV40

class TestCVE(unittest.TestCase):

    def test_valid_CVSS(self):
        single_cvss = CVSSMetricV40.CVSSMetricV40(CVSS_TEST_DATA_VALID_V40_1)
        self.assertEqual(single_cvss.infos.source, "cna@vuldb.com")

        single_cvss = CVSSMetricV40.CVSSMetricV40(CVSS_TEST_DATA_VALID_V40_2)
        self.assertEqual(single_cvss.infos.source, "cna@vuldb.com")

    def test_invalid_CVSS(self):
        self.assertRaises(ValueError, CVSSMetricV40.CVSSMetricV40, CVSS_TEST_DATA_INVALID_V40_1)


CVSS_TEST_DATA_VALID_V40_1 = """{
      "cvssMetricV40": [
        {
          "source": "cna@vuldb.com",
          "type": "Secondary",
          "cvssData": {
            "version": "4.0"
          }
        }
      ]}"""

CVSS_TEST_DATA_VALID_V40_2 = """{
      "cvssMetricV40": [
        {
          "source": "cna@vuldb.com",
          "type": "Primary",
          "cvssData": {
            "version": "4.0"
          }
        }
      ]}"""

CVSS_TEST_DATA_INVALID_V40_1 = """{
      "cvssMetricV40": [
        {
          "soooource": "cna@vuldb.com",
          "type": "Secondary",
          "cvssData": {
            "version": "4.0"
          }
        }
      ]}"""