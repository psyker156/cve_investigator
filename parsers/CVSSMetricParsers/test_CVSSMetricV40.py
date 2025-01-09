"""
This file is part of the VulnerabilityManager project, a tool aimed at managing vulnerabilities
Copyright (C) 2025  Philippe Godbout
"""

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