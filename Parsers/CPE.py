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


OFFSET_CPE_IDENTIFIER = 0
OFFSET_CPE_CPE_VERSION = 1
OFFSET_CPE_PART = 2
OFFSET_CPE_VENDOR = 3
OFFSET_CPE_PRODUCT = 4
OFFSET_CPE_VERSION = 5
OFFSET_CPE_UPDATE = 6
OFFSET_CPE_EDITION = 7
OFFSET_CPE_LANGUAGE = 8
OFFSET_CPE_SW_EDITION = 9
OFFSET_CPE_TARGET_SW = 10
OFFSET_CPE_TARGET_HW = 11
OFFSET_CPE_OTHER = 12

CPE_PART_APPLICATION = 'a'
CPE_PART_OS = 'o'
CPE_PART_HARDWARE = 'h'

SUPPORTED_CVE_VERSION = ['2.3']

INVALID_OR_UNSUPPORTED_VERSION = 'ERROR - Invalid CPE string, or unsupported CPE version.'

class CPE:
    """
    This class represents a CPE as described in: https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf
    """
    raw_cpe_string = None

    identifier = None
    cpe_version = None
    part = None
    vendor = None
    product = None
    version = None
    update = None
    edition = None
    language = None
    sw_edition = None
    target_sw = None
    target_hw = None
    other = None

    def __init__(self, cpe_str):
        """
        The constructor for CPE. Following this being called, the CPE is fully populated and no additional
        information is required.
        :param cpe_str: a valid CPE string
        """
        self.raw_cpe_string = cpe_str

        if not self.valid_cpe_string():
            raise ValueError(INVALID_OR_UNSUPPORTED_VERSION)

        split_cpe = self.raw_cpe_string.split(':')
        self.identifier = split_cpe[OFFSET_CPE_IDENTIFIER]
        self.cpe_version = split_cpe[OFFSET_CPE_CPE_VERSION]
        self.part = split_cpe[OFFSET_CPE_PART]
        self.vendor = split_cpe[OFFSET_CPE_VENDOR]
        self.product = split_cpe[OFFSET_CPE_PRODUCT]
        self.version = split_cpe[OFFSET_CPE_VERSION]
        self.update = split_cpe[OFFSET_CPE_UPDATE]
        self.edition = split_cpe[OFFSET_CPE_EDITION]
        self.language = split_cpe[OFFSET_CPE_LANGUAGE]
        self.sw_edition = split_cpe[OFFSET_CPE_SW_EDITION]
        self.target_sw = split_cpe[OFFSET_CPE_TARGET_SW]
        self.target_hw = split_cpe[OFFSET_CPE_TARGET_HW]
        self.other = split_cpe[OFFSET_CPE_OTHER]

    def valid_cpe_string(self):
        """
        This method makes basic checks about the validity and support of a CPE string. The validation is NAIVE and
        only makes sure that the CPE string contains a valid number of parts.
        :param cpe_str: A valid CPE string
        :return: Boolean, True if valid, False otherwise
        """
        return_value = False
        split_cpe = self.raw_cpe_string.split(':')

        if len(split_cpe) == 13:
            if split_cpe[OFFSET_CPE_CPE_VERSION] in SUPPORTED_CVE_VERSION:
                return_value = True
        return return_value

    def is_application(self):
        """
        This method checks if the CPE string is an application CPE.
        :return: True if application, False otherwise
        """
        return True if self.part == CPE_PART_APPLICATION else False

    def is_os(self):
        """
        This method checks if the CPE string is an OS CPE.
        :return: True if OS, False otherwise
        """
        return True if self.part == CPE_PART_OS else False

    def is_hardware(self):
        """
        This method checks if the CPE string is a hardware CPE.
        :return: True if hardware, False otherwise
        """
        return True if self.part == CPE_PART_HARDWARE else False
