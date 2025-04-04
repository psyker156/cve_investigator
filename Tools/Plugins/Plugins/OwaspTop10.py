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

import pprint
import re

from NetworkServices.NISTAPIServices import call_cve_api
from Parsers.CVE import CVE
from Parsers.CWE import CWE
from Tools.configuration import *

import Tools.Plugins.BasePlugin as BasePlugin

# Data source for correspondence: https://cwe.mitre.org/data/definitions/1344.html
A01 = [22, 23, 35, 59, 200, 201, 219, 264, 275, 276, 284, 285, 352, 359, 377, 402, 425, 441, 497, 538, 540, 548, 552, 566, 601, 639, 651, 668, 706, 862, 863, 913, 922, 1275, 276, 277, 278, 279, 280, 281, 618, 766, 767]
A02 = [261, 296, 310, 311, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 335, 336, 337, 338, 340, 347, 523, 720, 757, 759, 760, 780, 818, 916, 311, 321, 325, 326, 261, 324, 325, 328, 331, 334, 335, 338, 347, 916, 1204, 1240]
A03 = [20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 113, 116, 138, 184, 470, 471, 564, 610, 643, 644, 652, 917]
A04 = [73, 183, 209, 213, 235, 256, 257, 266, 269, 280, 311, 312, 313, 316, 419, 430, 434, 444, 451, 472, 501, 522, 525, 539, 579, 598, 602, 642, 646, 650, 653, 656, 657, 799, 807, 840, 841, 927, 1021, 1173, 283, 639, 640, 708, 770, 826, 837, 841]
A05 = [2, 11, 13, 15, 16, 260, 315, 520, 526, 537, 541, 547, 611, 614, 756, 776, 942, 1004, 1032, 1174, 16, 209, 548]
A06 = [1104]
A07 = [256, 257, 260, 261, 262, 263, 324, 521, 523, 549, 620, 640, 645, 798, 916, 1392, 259, 287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307, 346, 384, 521, 613, 620, 640, 798, 940]
A08 = [345, 353, 426, 494, 502, 565, 784, 829, 830, 915]
A09 = [117, 223, 532, 778]
A10 = [918]

TOP_10_DESC = {1: ("A01:2021 - Broken Access Control", A01),
               2: ("A02:2021 - Cryptographic Failures", A02),
               3: ("A03:2021 - Injection", A03),
               4: ("A04:2021 - Insecure Design", A04),
               5: ("A05:2021 - Security Misconfiguration", A05),
               6: ("A06:2021 - Vulnerable and Outdated Components", A06),
               7: ("A07:2021 - Identification and Authentication Failures", A07),
               8: ("A08:2021 - Software and Data Integrity Failures", A08),
               9: ("A09:2021 - Security Logging and Monitoring Failures", A09),
               10:("A10:2021 - Server-Side Request Forgery (SSRF)", A10)}



class OwaspTop10(BasePlugin.BasePlugin):
    """
    This plugin allows the user to explore CVEs
    """
    ITERATION = 2

    INFO_HELP_STRING = ('owasp has mainly 2 modes of execution:\n'
                        '# owasp CVE-XXXX-XXXX - Prints the OWASP top 10 info for a given CVE if possible\n'
                        '# owasp filtered_cache - Prints general OWASP top 10 stats based on the filtered cache\n'
                        '\n\n The version of the top 10 currently being used is 2021\n'
                        'More info: https://owasp.org/Top10/\n')


    INVALID_ARGUMENT_ERROR = -1
    INVALID_ARGUMENT_MESSAGE = "owasp must be call with at least a CVE number"

    CVE_REGEX = r"(?i)^cve-\d{4}-\d{4,}$"

    COMMAND_TYPE_INVALID = 0
    COMMAND_TYPE_CVE = 1
    COMMAND_TYPE_FILTERED_CACHE = 2



    def __init__(self, cache, filtered_cache):
        """
        Simply sets up the plugin so it can be used.
        """
        super().__init__()
        self.LOCAL_CACHE = cache
        self.LOCAL_CACHE_FILTERED = filtered_cache
        self.set_plugin_type('command')
        self.set_plugin_identity('owasp')
        self.set_plugin_description('Allows OWASP top 10 analysis of CVE')
        self.set_help(self.INFO_HELP_STRING)
        self.register_error_code(self.INVALID_ARGUMENT_ERROR, self.INVALID_ARGUMENT_MESSAGE)

    def validate_command(self, args):
        """
        This is a localized command parser that every plugin must implement.
        :param args: a list of commands including the command name
        :return: return_value, cve_number, sub_command
        """
        return_value = self.INVALID_ARGUMENT_ERROR
        param_len = len(args)

        if param_len == 2 and bool(re.match(self.CVE_REGEX, args[1])):
            return_value = self.COMMAND_TYPE_CVE
        elif param_len == 2 and "filtered_cache" == args[1]:
            return_value = self.COMMAND_TYPE_FILTERED_CACHE

        return return_value


    def run(self, params=None):
        """
        Main entry point for the plugin, calls validate and runs individual functions based on the parameters.
        :param params: list, the parameters passed to the plugin
        :return: 0 if properly called, self.INVALID_ARGUMENT_ERROR if wrongly called
        """
        return_value = self.INVALID_ARGUMENT_ERROR
        valid_command = self.validate_command(params)

        if valid_command == self.COMMAND_TYPE_CVE:
            self._run_cve(params[1])
            return_value = self.RUN_SUCCESS
        elif valid_command == self.COMMAND_TYPE_FILTERED_CACHE:
            self._run_filtered_cache()
            return_value = self.RUN_SUCCESS

        return return_value

    def _cwe_to_top_10(self, cwe):
        """
        This will convert a CWE to a top 10 vulnerability if able to
        :param cwe: string, the CWE code to be converted
        :return: number, int, 0 if not found
        """
        for group in TOP_10_DESC.keys():
            if cwe in TOP_10_DESC[group][1]:
                return group
        return 0

    def _run_cve(self, cve):
        """
        This will attempt at getting a top 10 match for CWEs related to a vulnerability
        :param cve: string, the CVE that we're interested in
        :return:
        """
        return_value = self.RUN_UNKNOWN_ERROR

        cve_data = self._obtain_cve(cve)
        if cve_data is not None:
            #cve_data.cwe will be an array of CWE code CWE-XXX
            for cwe in cve_data.cwe:
                top_10 = self._cwe_to_top_10(int(cwe.split('-')[1]))
                if top_10 != 0:
                    print(f'{cve_data.infos.id} is a top 10 : {TOP_10_DESC[top_10][0]}')
                    return_value = self.RUN_SUCCESS
        if return_value != self.RUN_SUCCESS:
            print(f"No top 10 vulnerability group found for {cve_data.infos.id}")
        return return_value

    def _run_filtered_cache(self):
        """
        This will run general stats on OWASP top 10 based on everything that is located in the filtered cache
        :return: RUN_UNKNOWN_ERROR if error otherwise RUN_SUCCESS
        """
        return_value = self.RUN_UNKNOWN_ERROR
        filtered_cache = self.LOCAL_CACHE_FILTERED
        top_10_cache = {1: 0,
                        2: 0,
                        3: 0,
                        4: 0,
                        5: 0,
                        6: 0,
                        7: 0,
                        8: 0,
                        9: 0,
                        10:0}

        for cve in filtered_cache:
            # cve_data.cwe will be an array of CWE code CWE-XXX
            for cwe in cve.cwe:
                try:
                    top_10 = self._cwe_to_top_10(int(cwe.split('-')[1]))
                except ValueError:
                    continue
                if top_10 != 0:
                    top_10_cache[top_10] += 1

        print(f"OWASP top 10 stats based on content of filtered cache")
        for top_10 in top_10_cache:
            print(f'\t{TOP_10_DESC[top_10][0]}: {top_10_cache[top_10]}')

        return_value = self.RUN_SUCCESS
        return return_value

    def _obtain_cve(self, cve):
        if cve not in self.LOCAL_CACHE:
            print(f'Searching NVD for {cve}...')
            r = call_cve_api(cve=cve)

            if len(r['vulnerabilities']) == 0:
                raise Exception(f'No vulnerabilities found for {cve} in NVD records')
            self.LOCAL_CACHE[cve] = CVE(r['vulnerabilities'][0])
            print(f'{cve} was added to local cache from NVD')
        else:
            print(f'Loading {cve} from local cache')

        return self.LOCAL_CACHE[cve]