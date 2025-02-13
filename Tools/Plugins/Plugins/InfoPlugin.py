"""
This file is part of the VulnerabilityManager project, a tool aimed at managing vulnerabilities
Copyright (C) 2025  Philippe Godbout
"""
from Tools.configuration import *

import Tools.Plugins.BasePlugin as BasePlugin

class InfoPlugin(BasePlugin.BasePlugin):
    """
    This plugin simply displays general information about cve_investigator
    """
    ITERATION = 1

    INFO_HELP_STRING = ('Info does not have any argument and must be called like:\n'
                        '# info\n'
                        'After calling, the current information about cve_investigator will be displayed\n')


    INVALID_ARGUMENT_ERROR = -1
    INVALID_ARGUMENT_MESSAGE = "Info must be called without any arguments"


    def __init__(self, cache):
        """
        Simply sets up the plugin so it can be used.
        """
        super().__init__()
        self.LOCAL_CACHE = cache
        self.set_plugin_type('command')
        self.set_plugin_identity('info')
        self.set_plugin_description('Displays general information about cve_investigator')
        self.set_help(self.INFO_HELP_STRING)
        self.register_error_code(self.INVALID_ARGUMENT_ERROR, self.INVALID_ARGUMENT_MESSAGE)


    def validate_command(self, args):
        """
        This is a localized command parser that every plugin must implement.
        :param args: a list of commands including the command name
        :return: boolean, True if the command is valid, False otherwise
        """
        return_value = True

        # Info requires a single parameter with its own name
        if len(args) != 1 or args[0] != self.plugin_identity():
            print()
            return_value = False

        return return_value

    def run(self, params=None):
        """
        This will simply display general information about cve_investigator. It "kinda" is the
        hello world of the plugins :P
        :param params: list, in this case the list should be empty!!!
        :return: 0 if properly called, self.INVALID_ARGUMENT_ERROR if wrongly called
        """
        return_value = self.INVALID_ARGUMENT_ERROR
        if self.validate_command(params):
            self._execute()
            return_value = self.RUN_SUCCESS
        return return_value


    def _execute(self):
        """
        This is called by run and should never be called directly!!!!
        """
        print(f'CVE Investigator version {CVE_INVESTIGATOR_VERSION}')
        print(f'Release Date: {CVE_INVESTIGATOR_RELEASE_DATE}')
        print(f'Provided by {CVE_INVESTIGATOR_WEBSITE_URL}')
        print(f'Latest version available at: {CVE_INVESTIGATOR_SOURCE_URL}')
        print(f'{CVE_INVESTIGATOR_COPYRIGHT}')
