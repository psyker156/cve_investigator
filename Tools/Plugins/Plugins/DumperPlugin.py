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

from contextlib import redirect_stdout

import pprint
import re
import datetime

from NetworkServices.NISTAPIServices import call_cve_api
from Parsers.CVE import CVE
from Parsers.CWE import CWE
from Tools.configuration import *

import Tools.Plugins.BasePlugin as BasePlugin


class DumperPlugin(BasePlugin.BasePlugin):
    """
    This plugin allows the user to explore CVEs
    """
    ITERATION = 2

    INFO_HELP_STRING = ('dumper has 1 command for now which will dump the cache:\n'
                        '# dumper dump\n'
                        'It can however be used with the "filtered" option to dump the filtered cache')


    INVALID_ARGUMENT_ERROR = -1
    INVALID_ARGUMENT_MESSAGE = "dumper must be call with dump"

    COMMAND_TYPE_INVALID = 0
    COMMAND_TYPE_DUMP = 1


    def __init__(self, cache, filtered_cache):
        """
        Simply sets up the plugin so it can be used.
        """
        super().__init__()
        self.LOCAL_CACHE = cache
        self.LOCAL_CACHE_FILTERED = filtered_cache
        self.set_plugin_type('command')
        self.set_plugin_identity('dumper')
        self.set_plugin_description('dump short description of all CVEs to drive')
        self.set_help(self.INFO_HELP_STRING)
        self.register_error_code(self.INVALID_ARGUMENT_ERROR, self.INVALID_ARGUMENT_MESSAGE)

    def validate_command(self, args):
        """
        This is a localized command parser that every plugin must implement.
        :param args: a list of commands including the command name
        :return: return_value, cve_number, sub_command
        """
        return_value_a = self.COMMAND_TYPE_INVALID
        return_value_b = False

        if len(args) == 2:
            if args[1] == 'dump':
                return_value_a = self.COMMAND_TYPE_DUMP
        elif len(args) == 3:
            if args[1] == 'dump' and args[2] == 'filtered':
                return_value_a = self.COMMAND_TYPE_DUMP
                return_value_b = True

        return return_value_a, return_value_b


    def run(self, params=None):
        """
        This will simply display general information about cve_investigator. It "kinda" is the
        hello world of the plugins :P
        :param params: list, in this case the list should be empty!!!
        :return: 0 if properly called, self.INVALID_ARGUMENT_ERROR if wrongly called
        """
        return_value, filtered = self.validate_command(params)
        if return_value == self.COMMAND_TYPE_DUMP:
            self._dump_short_desc(filtered)
            return_value = self.RUN_SUCCESS
        return return_value


    def _dump_short_desc(self, filtered=False):
        """
        This is called by run and should never be called directly!!!!
        """
        path = str(datetime.datetime.now()).replace(':', '-') + '.txt'
        with open(path, 'w', encoding='utf-8') as f:
            with redirect_stdout(f):
                cwe = CWE()
                cve_list = []
                if not filtered:
                    for cve_k in self.LOCAL_CACHE:
                        cve_list.append(self.LOCAL_CACHE[cve_k])
                else:
                    cve_list = self.LOCAL_CACHE_FILTERED

                for cve in cve_list:
                    print(f'CVE identifier: {cve.infos.id}')
                    print(f'\tPublished on: {cve.infos.published}')

                    if len(cve.cvss) > 0:
                        print(f'\tCVSS(s):')
                        for cvss in cve.cvss:
                            print(self._format_text(f'CVSSv{cvss.version}: {cvss.base_score} --- AV:{cvss.attack_vector}',
                                                    tabulation=2))

                    print(f'\tCWE(s):')
                    for single_cwe in cve.cwe:
                        t = cwe.description_for_code(single_cwe)
                        print(self._format_text(f'{single_cwe} - {t if t is not None else "N/A"}', tabulation=2))

                    print(f'\tDescription(s):')
                    for d in cve.infos.descriptions:
                        if d.lang == 'en':
                            print(self._format_text(d.value, tabulation=2))
                            print()
        print('Dumper just took a dump!')