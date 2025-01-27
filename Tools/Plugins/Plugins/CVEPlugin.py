"""
This file is part of the VulnerabilityManager project, a tool aimed at managing vulnerabilities
Copyright (C) 2025  Philippe Godbout
"""
import re
import textwrap

from NetworkServices.NISTAPIServices import call_cve_api
from Parsers.CVE import CVE
from Tools.configuration import *

import Tools.Plugins.BasePlugin as BasePlugin


class CVEPlugin(BasePlugin.BasePlugin):
    """
    This plugin simply displays general information about cve_investigator
    """
    ITERATION = 1

    INFO_HELP_STRING = ('CVE has mainly 3 modes of execution:\n'
                        '# cve CVE-XXXX-XXXX - Prints a summary of a given CVE if available\n'
                        '# cve CVE-XXXX-XXXX verbose - Prints a long version of the CVE information\n'
                        '# cve CVE-XXXX-XXXX AnyCVEParameter- Prints the data for a given CVE part\n'
                        '\t valid inputs are as documented in the CVE 2.0 API documentation')


    INVALID_ARGUMENT_ERROR = -1
    INVALID_ARGUMENT_MESSAGE = "cve must be call with at least a CVE number"

    CVE_REGEX = r"(?i)^cve-\d{4}-\d{4,}$"

    LOCAL_CACHE = {}


    def __init__(self):
        """
        Simply sets up the plugin so it can be used.
        """
        super().__init__()
        self.set_plugin_type('command')
        self.set_plugin_identity('cve')
        self.set_plugin_description('Allows CVE inspection based on a CVE number')
        self.set_help(self.INFO_HELP_STRING)
        self.register_error_code(self.INVALID_ARGUMENT_ERROR, self.INVALID_ARGUMENT_MESSAGE)


    def validate_command(self, args):
        """
        This is a localized command parser that every plugin must implement.
        :param args: a list of commands including the command name
        :return: boolean, True if the command is valid, False otherwise
        """
        # CVE requires at least two parameters the first one being the name
        if len(args) < 2 or args[0] != self.plugin_identity():
            return False

        # Let's validate the CVE number is valid before we try to use it
        cve_number = args[1]
        return bool(re.match(self.CVE_REGEX, cve_number))


    def run(self, params=None):
        """
        This will simply display general information about cve_investigator. It "kinda" is the
        hello world of the plugins :P
        :param params: list, in this case the list should be empty!!!
        :return: 0 if properly called, self.INVALID_ARGUMENT_ERROR if wrongly called
        """
        return_value = self.INVALID_ARGUMENT_ERROR
        if self.validate_command(params):
            cve = params[1].upper()
            other_params = None

            if len(params) > 2:
                other_params = params[2:]

            self._execute(cve, params)
            return_value = self.RUN_SUCCESS
        return return_value


    def _execute(self, cve, params=None):
        """
        This is called by run and should never be called directly!!!!
        """
        if cve not in self.LOCAL_CACHE:
            print(f'Searching NVD for {cve}...')
            r = call_cve_api(cve=cve)

            if not 'vulnerabilities' in r:
                raise Exception(f'No vulnerabilities found in {cve} NVD records')
            self.LOCAL_CACHE[cve] = r['vulnerabilities'][0]
            print(f'{cve} was added to local cache from NVD')
        else:
            print(f'Loading {cve} from local cache\n')

        usable_cve = CVE(self.LOCAL_CACHE[cve])
        print(f'CVE identifier: {usable_cve.infos.id}')
        print(f'\tPublished on:{usable_cve.infos.published}')
        print(f'\tLast modified on:{usable_cve.infos.lastModified}')

        print(f'\tDescription(s):')
        for d in usable_cve.infos.descriptions:
            print(f'\t{d.lang}')
            print(self._format_text(d.value))

    def _format_text(self, text):
        end_result = ''
        wrapped_text = textwrap.wrap(text, width=70)
        for d in wrapped_text:
            end_result += f'\t{d}\n'
        return end_result


