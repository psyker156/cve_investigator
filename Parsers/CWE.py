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

# The following are all constants used to locate data on the local hard drive
CWE_INFO_LOCATION = 'Parsers/cwe.csv'   # The separator is a : colon

# Dict used to hold the CWE information after it is loaded
CWE_INFO = None


def fetch_cwe_info():
    """
    Simply loads the CWE info from the file, one CWE per line, separator is ':'
    """
    global CWE_INFO
    CWE_INFO = {}
    with open(CWE_INFO_LOCATION, 'r', encoding='utf-8') as f:
        data = f.readlines()

    for line in data:
        split_line = line.split(':')
        CWE_INFO[split_line[0]] = split_line[1][:-1]


class CWE(object):
    """
    This class depends on CWE_INFO being populated. When called, if CWE_info is not available, it will
    """
    def __init__(self):
        """
        Creates a CWE object, this object aims at being interrogated
        :param cwe_code: string, will accept either 'CWE-XXX' or just the number 'XXX'
        """
        if CWE_INFO is None:
            fetch_cwe_info()

    def description_for_code(self, cwe_code):
        """
        Will return the description of the CWE or None if it is not available
        :param cwe_code: string, will accept either 'CWE-XXX' or just the number 'XXX' it will also accept an int
        :return: string containing the description of the CWE
        """
        global CWE_INFO
        return_value = None
        if isinstance(cwe_code, int):
            cwe_code = str(cwe_code)
        elif cwe_code[0:4] == 'CWE-' or cwe_code[0:4] == 'cwe-':
            cwe_code = cwe_code[4:]

        if cwe_code in CWE_INFO:
            return_value = CWE_INFO[cwe_code]

        return return_value
