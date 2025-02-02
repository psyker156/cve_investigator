"""
This file is part of the VulnerabilityManager project, a tool aimed at managing vulnerabilities
Copyright (C) 2025  Philippe Godbout
"""
import pprint
import re
import textwrap

from NetworkServices.NISTAPIServices import call_cve_api
from Parsers.CVE import CVE
from Tools.configuration import *

import Tools.Plugins.BasePlugin as BasePlugin


class CVEPlugin(BasePlugin.BasePlugin):
    """
    This plugin allows the user to explore CVEs
    """
    ITERATION = 1

    INFO_HELP_STRING = ('CVE has mainly 3 modes of execution:\n'
                        '# cve CVE-XXXX-XXXX - Prints a summary of a given CVE if available\n'
                        '# cve verbose CVE-XXXX-XXXX - Prints a long version of the CVE information\n'
                        '# cve AnyCVEParameter CVE-XXXX-XXXX - Prints the data for a given CVE part\n'
                        '# cve show CVE-XXX-XXXX - Prints the available parameters for a given CVE\n')


    INVALID_ARGUMENT_ERROR = -1
    INVALID_ARGUMENT_MESSAGE = "cve must be call with at least a CVE number"

    CVE_REGEX = r"(?i)^cve-\d{4}-\d{4,}$"

    LOCAL_CACHE = {}

    COMMAND_TYPE_INVALID = 0
    COMMAND_TYPE_SHORT = 1
    COMMAND_TYPE_VERBOSE = 2
    COMMAND_TYPE_PARAM = 3
    COMMAND_TYPE_SHOW = 4


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
        print(f'CVE identifier: {cve.infos.id}')
        print(f'\tPublished on:{cve.infos.published}')
        print(f'\tLast modified on:{cve.infos.lastModified}')

        print(f'\tDescription(s):')
        for d in cve.infos.descriptions:
            print(f'\t{d.lang}')
            print(self._format_text(d.value, tabulation=1))


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

            if not 'vulnerabilities' in r:
                raise Exception(f'No vulnerabilities found in {cve} NVD records')
            self.LOCAL_CACHE[cve] = r['vulnerabilities'][0]
            print(f'{cve} was added to local cache from NVD')
        else:
            print(f'Loading {cve} from local cache')

        return CVE(self.LOCAL_CACHE[cve])


    def _format_text(self, text, width=70, tabulation=0):
        end_result = ''
        wrapped_text = textwrap.wrap(text, width=width)
        len_wrapped_text = len(wrapped_text)
        for d in wrapped_text:
            suffix = '' if len_wrapped_text == 1 else '\n'
            end_result += f'{'\t'*tabulation}{d}{suffix}'
        return end_result


