"""
This file is part of the VulnerabilityManager project, a tool aimed at managing vulnerabilities
Copyright (C) 2025  Philippe Godbout
"""

import unittest

import CPE

class TestCPE(unittest.TestCase):

    def test_CPE_valid_application(self):
        """
        Validates that a valid application CPE can be loaded
        """
        app_cpe = CPE.CPE(VALID_CPE_23_APPLICATION)
        self.assertEqual(app_cpe.identifier, 'cpe')
        self.assertEqual(app_cpe.cpe_version, '2.3')
        self.assertEqual(app_cpe.part, 'a')
        self.assertEqual(app_cpe.vendor, 'dell')
        self.assertEqual(app_cpe.product, 'emc_openmanage_integration_for_microsoft_system_center')
        self.assertEqual(app_cpe.version, '7.2.1')
        self.assertEqual(app_cpe.update, '*')
        self.assertEqual(app_cpe.edition, '*')
        self.assertEqual(app_cpe.language, '*')
        self.assertEqual(app_cpe.sw_edition, '*')
        self.assertEqual(app_cpe.target_sw, 'system_center_virtual_machine_manager')
        self.assertEqual(app_cpe.target_hw, '*')
        self.assertEqual(app_cpe.other, '*')

        self.assertTrue(app_cpe.is_application())
        self.assertFalse(app_cpe.is_os())
        self.assertFalse(app_cpe.is_hardware())

    def test_CPE_valid_os(self):
        """
        Validates that a valid OS CPE can be loaded
        """
        app_cpe = CPE.CPE(VALID_CPE_23_OS)
        self.assertEqual(app_cpe.identifier, 'cpe')
        self.assertEqual(app_cpe.cpe_version, '2.3')
        self.assertEqual(app_cpe.part, 'o')
        self.assertEqual(app_cpe.vendor, 'canonical')
        self.assertEqual(app_cpe.product, 'ubuntu')
        self.assertEqual(app_cpe.version, '20.04')
        self.assertEqual(app_cpe.update, '*')
        self.assertEqual(app_cpe.edition, '*')
        self.assertEqual(app_cpe.language, '*')
        self.assertEqual(app_cpe.sw_edition, '*')
        self.assertEqual(app_cpe.target_sw, '*')
        self.assertEqual(app_cpe.target_hw, 'x86_64')
        self.assertEqual(app_cpe.other, '*')

        self.assertFalse(app_cpe.is_application())
        self.assertTrue(app_cpe.is_os())
        self.assertFalse(app_cpe.is_hardware())

    def test_CPE_valid_hardware(self):
        """
        Validates that a valid hardware CPE can be loaded
        """
        app_cpe = CPE.CPE(VALID_CPE_23_HARDWARE)
        self.assertEqual(app_cpe.identifier, 'cpe')
        self.assertEqual(app_cpe.cpe_version, '2.3')
        self.assertEqual(app_cpe.part, 'h')
        self.assertEqual(app_cpe.vendor, 'hp')
        self.assertEqual(app_cpe.product, 'proliant_dl360_gen10')
        self.assertEqual(app_cpe.version, '-')
        self.assertEqual(app_cpe.update, '*')
        self.assertEqual(app_cpe.edition, '*')
        self.assertEqual(app_cpe.language, '*')
        self.assertEqual(app_cpe.sw_edition, '*')
        self.assertEqual(app_cpe.target_sw, '*')
        self.assertEqual(app_cpe.target_hw, '*')
        self.assertEqual(app_cpe.other, '*')

        self.assertFalse(app_cpe.is_application())
        self.assertFalse(app_cpe.is_os())
        self.assertTrue(app_cpe.is_hardware())

    def test_CPE_unsupported_version(self):
        """
        Validates that an unsupported version CPE will not be loaded
        """
        self.assertRaises(ValueError, CPE.CPE, UNSUPPORTED_CPE_VERSION)

    def test_CPE_invalid_string_random(self):
        """
        Validates that a random string will not be loaded
        """
        self.assertRaises(ValueError, CPE.CPE, INVALID_CPE_STRING_RANDOM)

    def test_CPE_invalid_len(self):
        """
        Validates that an invalid length CPE will not be loaded
        """
        self.assertRaises(ValueError, CPE.CPE, INVALID_CPE_STRING_TOO_SHORT)
        self.assertRaises(ValueError, CPE.CPE, INVALID_CPE_STRING_TOO_LONG)

VALID_CPE_23_APPLICATION = 'cpe:2.3:a:dell:emc_openmanage_integration_for_microsoft_system_center:7.2.1:*:*:*:*:system_center_virtual_machine_manager:*:*'
VALID_CPE_23_OS = 'cpe:2.3:o:canonical:ubuntu:20.04:*:*:*:*:*:x86_64:*'
VALID_CPE_23_HARDWARE = 'cpe:2.3:h:hp:proliant_dl360_gen10:-:*:*:*:*:*:*:*'
UNSUPPORTED_CPE_VERSION = 'cpe:/h:hp:proliant_dl360_gen10:-'
INVALID_CPE_STRING_RANDOM = 'This is a random string'
INVALID_CPE_STRING_TOO_LONG = 'cpe:2.3:a:dell:emc_openmanage_integration_for_microsoft_system_center:7.2.1:*:*:*:*:system_center_virtual_machine_manager:*:*:OneMoreField'
INVALID_CPE_STRING_TOO_SHORT = 'cpe:2.3:a:dell:emc_openmanage_integration_for_microsoft_system_center:7.2.1:*:*:*:*:system_center_virtual_machine_manager:OneLessField'