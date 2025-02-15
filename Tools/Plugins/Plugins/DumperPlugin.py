"""
This file is part of the VulnerabilityManager project, a tool aimed at managing vulnerabilities
Copyright (C) 2025  Philippe Godbout
"""
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
    ITERATION = 1

    INFO_HELP_STRING = ('dumper has 1 command for now:\n'
                        '# dumper dump')


    INVALID_ARGUMENT_ERROR = -1
    INVALID_ARGUMENT_MESSAGE = "dumper must be call with dump"

    COMMAND_TYPE_INVALID = 0
    COMMAND_TYPE_DUMP = 1


    def __init__(self, cache):
        """
        Simply sets up the plugin so it can be used.
        """
        super().__init__()
        self.LOCAL_CACHE = cache
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
        return_value = self.COMMAND_TYPE_INVALID

        if len(args) == 2:
            if args[1] == 'dump':
                return_value = self.COMMAND_TYPE_DUMP

        return return_value


    def run(self, params=None):
        """
        This will simply display general information about cve_investigator. It "kinda" is the
        hello world of the plugins :P
        :param params: list, in this case the list should be empty!!!
        :return: 0 if properly called, self.INVALID_ARGUMENT_ERROR if wrongly called
        """
        return_value = self.validate_command(params)
        if return_value == self.COMMAND_TYPE_DUMP:
            self._dump_short_desc()
            return_value = self.RUN_SUCCESS
        return return_value


    def _dump_short_desc(self):
        """
        This is called by run and should never be called directly!!!!
        """
        path = str(datetime.datetime.now()).replace(':', '-') + '.txt'
        with open(path, 'w', encoding='utf-8') as f:
            with redirect_stdout(f):
                cwe = CWE()
                for cve_k in self.LOCAL_CACHE:
                    cve = self.LOCAL_CACHE[cve_k]
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