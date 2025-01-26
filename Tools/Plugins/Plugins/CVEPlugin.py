"""
This file is part of the VulnerabilityManager project, a tool aimed at managing vulnerabilities
Copyright (C) 2025  Philippe Godbout
"""
import re

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

    CVE_REGEX = r"^CVE-\d{4}-\d{4,}$"


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
            # self._execute()
            return_value = self.RUN_SUCCESS
        return return_value


    def _execute(self):
        """
        This is called by run and should never be called directly!!!!
        """
        print(f'CVE Investogator version {CVE_INVESTIGATOR_VERSION} Community Edition')
        print(f'Release Date: {CVE_INVESTIGATOR_RELEASE_DATE}')
        print(f'Provided by {CVE_INVESTIGATOR_WEBSITE_URL}')
        print(f'Latest version available at: {CVE_INVESTIGATOR_SOURCE_URL}')
        print(f'{CVE_INVESTIGATOR_COPYRIGHT}')
