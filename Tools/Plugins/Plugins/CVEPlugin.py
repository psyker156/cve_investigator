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


class CVEPlugin(BasePlugin.BasePlugin):
    """
    This plugin allows the user to explore CVEs
    """
    ITERATION = 2

    INFO_HELP_STRING = ('CVE has mainly 3 modes of execution:\n'
                        '# cve CVE-XXXX-XXXX - Prints a summary of a given CVE if available\n'
                        '# cve verbose CVE-XXXX-XXXX - Prints a long version of the CVE information\n'
                        '# cve AnyCVEParameter CVE-XXXX-XXXX - Prints the data for a given CVE part\n'
                        '# cve show CVE-XXX-XXXX - Prints the available parameters for a given CVE\n')


    INVALID_ARGUMENT_ERROR = -1
    INVALID_ARGUMENT_MESSAGE = "cve must be call with at least a CVE number"

    CVE_REGEX = r"(?i)^cve-\d{4}-\d{4,}$"



    COMMAND_TYPE_INVALID = 0
    COMMAND_TYPE_SHORT = 1
    COMMAND_TYPE_VERBOSE = 2
    COMMAND_TYPE_PARAM = 3
    COMMAND_TYPE_SHOW = 4


    def __init__(self, cache, filtered_cache):
        """
        Simply sets up the plugin so it can be used.
        """
        super().__init__()
        self.LOCAL_CACHE = cache
        self.LOCAL_CACHE_FILTERED = filtered_cache
        self.set_plugin_type('command')
        self.set_plugin_identity('cve')
        self.set_plugin_description('Allows CVE inspection based on a CVE number')
        self.set_help(self.INFO_HELP_STRING)
        self.register_error_code(self.INVALID_ARGUMENT_ERROR, self.INVALID_ARGUMENT_MESSAGE)

    def validate_command(self, args):
        """
        This is a localized command parser that every plugin must implement.
        :param args: a list of commands including the command name
        :return: return_value, cve_number, sub_command
        """
        return_value = self.COMMAND_TYPE_INVALID
        cve_number = None
        sub_command = None

        # cve can be called in two fashions: just a CVE number or a CVE preceded by a parameter
        len_args = len(args)

        if len_args == 2:
            cve_number = args[1].upper()
            if bool(re.match(self.CVE_REGEX, cve_number)):
                return_value = self.COMMAND_TYPE_SHORT

        if len_args == 3:
            cve_number = args[2].upper()

            if bool(re.match(self.CVE_REGEX, cve_number)):
                sub_command = args[1]

                if sub_command == "verbose":
                    return_value = self.COMMAND_TYPE_VERBOSE
                elif sub_command == "show":
                    return_value = self.COMMAND_TYPE_SHOW
                else:
                    return_value = self.COMMAND_TYPE_PARAM

        return return_value, cve_number, sub_command


    def run(self, params=None):
        """
        This will simply display general information about cve_investigator. It "kinda" is the
        hello world of the plugins :P
        :param params: list, in this case the list should be empty!!!
        :return: 0 if properly called, self.INVALID_ARGUMENT_ERROR if wrongly called
        """
        return_value = self.INVALID_ARGUMENT_ERROR
        valid_command, cve_number, sub_command = self.validate_command(params)
        usable_cve = None

        if valid_command != self.COMMAND_TYPE_INVALID and cve_number is not None:
            usable_cve = self._obtain_cve(cve_number)

        if valid_command == self.COMMAND_TYPE_SHORT:
            self._execute_single_short(usable_cve)
            return_value = self.RUN_SUCCESS
        elif valid_command == self.COMMAND_TYPE_VERBOSE:
            self._execute_single_verbose(usable_cve)
            return_value = self.RUN_SUCCESS
        elif valid_command == self.COMMAND_TYPE_PARAM:
            self._execute_single_parameter(usable_cve, sub_command)
            return_value = self.RUN_SUCCESS
        elif valid_command == self.COMMAND_TYPE_SHOW:
            self._execute_single_show(usable_cve)
            return_value = self.RUN_SUCCESS

        return return_value


    def _execute_single_short(self, cve):
        """
        This is called by run and should never be called directly!!!!
        """
        cwe = CWE()
        print(f'CVE identifier: {cve.infos.id}')
        print(f'\tPublished on: {cve.infos.published}')

        if len(cve.cvss) > 0:
            print(f'\tCVSS(s):')
            for cvss in cve.cvss:
                print(self._format_text(f'CVSSv{cvss.version}: {cvss.base_score} --- AV:{cvss.attack_vector}', tabulation=2))

        print(f'\tCWE(s):')
        for single_cwe in cve.cwe:
            t = cwe.description_for_code(single_cwe)
            print(self._format_text(f'{single_cwe} - {t if t is not None else "N/A"}', tabulation=2))

        print(f'\tDescription(s):')
        for d in cve.infos.descriptions:
            if d.lang == 'en':
                print(self._format_text(d.value, tabulation=2))
                print()


    def _execute_single_verbose(self, cve):
        print('Single verbose CVE')


    def _execute_single_parameter(self, cve, parameter=None):
        print(f'CVE identifier: {cve.infos.id}')
        if hasattr(cve.infos, parameter):
            pprint.pprint(getattr(cve.infos, parameter))
        else:
            print(self._format_text(f'This CVE does not have {parameter} attribute', tabulation=1))


    def _execute_single_show(self, cve):
        print(f'CVE identifier: {cve.infos.id}')
        print(self._format_text(f'The CVE has the following attributes', tabulation=1))

        attributes = dir(cve.infos)

        for a in attributes:
            if not a.startswith('_'):
                print(self._format_text(a, tabulation=2))



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



