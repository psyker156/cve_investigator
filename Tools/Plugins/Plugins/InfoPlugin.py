"""
This file is part of the VulnerabilityManager project, a tool aimed at managing vulnerabilities
Copyright (C) 2025  Philippe Godbout
"""
from Tools.configuration import *

import Tools.Plugins.BasePlugin as BasePlugin

class InfoPlugin(BasePlugin):
    """
    This plugin simply displays general information about cve_investigator
    """
    INFO_HELP_STRING = ('Info does not have any argument and must be called like:\n'
                        '# info\n'
                        'After calling, the current information about cve_investigator will be displayed\n')


    INVALID_ARGUMENT_ERROR = -2
    INVALID_ARGUMENT_MESSAGE = "Info must be called without any arguments"

    def __init__(self):
        """
        Simply sets up the plugin so it can be used.
        """
        self.set_plugin_type('command')
        self.set_plugin_identity('info')
        self.set_plugin_description('Displays general information about cve_investigator')
        self.set_help(self.INFO_HELP_STRING)
        self.register_error_code(self.INVALID_ARGUMENT_ERROR, self.INVALID_ARGUMENT_MESSAGE)

    def run(self, params):
        """
        This will simply display general information about cve_investigator. It "kinda" is the
        hello world of the plugins :P
        :param params: list, in this case the list should be empty!!!
        :return: 0 if properly called, self.INVALID_ARGUMENT_ERROR if wrongly called
        """
        return_value = self.INVALID_ARGUMENT_ERROR
        if len(params) == 0:
            return_value = self.RUN_SUCCESS
            self._execute()
        return return_value

    def _execute(self):
        """
        This is called by run and should never be called directly!!!!
        """
        print(f'CVE Investogator version {CVE_INVESTIGATOR_VERSION} Community Edition\n')
        print(f'Release Date: {CVE_INVESTIGATOR_RELEASE_DATE}\n')
        print(f'Provided by {CVE_INVESTIGATOR_WEBSITE_URL}\n')
        print(f'Latest version available at: {CVE_INVESTIGATOR_SOURCE_URL}\n')
        print(f'{CVE_INVESTIGATOR_COPYRIGHT}\n')
