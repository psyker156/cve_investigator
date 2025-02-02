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


class StatsPlugin(BasePlugin.BasePlugin):
    """
    This plugin allows the user to easily obtain statistics about CVEs
    """
    ITERATION = 1

    INFO_HELP_STRING = ('The stats plugin needs to be configured in order to get the stats you are looking for\n'
                        'Here are the various configuration commands\n'
                        '\t# stats set_start XXXX-XX-XX\t The start date for the statistics interval\n'
                        '\t# stats set_end XXXX-XX-XX\t The end date for the statistics interval\n'
                        '\t# stats set_keyword AAAAAAA\t Adds a keyword to be used for CVE search\n'
                        '\t# stats add_cwe CWE-XXX\t Adds a CWE to the list of interesting CWE\n'
                        '\t# stats crunch\t Runs the statistics based on the configuration\n'
                        '\t# stats clear_cache\t Remove all data from the local cache (required to start anew)\n'
                        '\t# stats load_cache\t Loads/update all CVEs from the range to local cache (required')


    INVALID_ARGUMENT_ERROR = -1
    INVALID_ARGUMENT_MESSAGE = "Command is invalid, see help to learn how to use it"

    LOCAL_CACHE = {}

    COMMAND_TYPE_INVALID = 0
    COMMAND_SET_START = 1           # This command sets the start date for the stats range
    COMMAND_SET_END = 2             # This command sets the end date for the stats range
    COMMAND_CRUNCH = 3              # This command will generate the stats according to the configuration
    COMMAND_RESET = 4               # This command will reset all configuration if used alone, specific config otherwise
    COMMAND_SET_KEYWORD = 5         # This command will add a keyword to the search keys
    COMMAND_ADD_CWE = 6             # This command will limit the statistics to a set of CVE based on CWE
    COMMAND_CLEAR_CACHE = 7         # This command will flush the local cache for the plugin
    COMMAND_LOAD_CACHE = 8          # This command will add/update the CVEs from the range to the cache

    VALID_COMMANDS = ['set_start',
                      'set_end',
                      'crunch',
                      'reset',
                      'set_keyword',
                      'add_cwe',
                      'clear_cache',
                      'load_cache']

    DATE_REGEX = re.compile(r'^\d{4}-\d{2}-\d{2}$')     # TODO


    def __init__(self):
        """
        Simply sets up the plugin so it can be used.
        """
        super().__init__()
        self.set_plugin_type('command')
        self.set_plugin_identity('stats')
        self.set_plugin_description('Quickly generates statistics about CVEs')
        self.set_help(self.INFO_HELP_STRING)
        self.register_error_code(self.INVALID_ARGUMENT_ERROR, self.INVALID_ARGUMENT_MESSAGE)

        self.start = None
        self.end = None
        self.keyword = []
        self.cwe = []

    def reset_configuration(self):
        self.start = None
        self.end = None
        self.keyword = []
        self.cwe = []

    def clear_cache(self):
        self.LOCAL_CACHE = {}

    def validate_command(self, args):
        """
        This is a localized command parser that every plugin must implement.
        :param args: a list of commands including the command name
        :return: boolean, True if the command is valid, False otherwise
        """
        return_value = self.COMMAND_TYPE_INVALID

        return return_value


    def run(self, params=None):
        """
        This will simply display general information about cve_investigator. It "kinda" is the
        hello world of the plugins :P
        :param params: list, in this case the list should be empty!!!
        :return: 0 if properly called, self.INVALID_ARGUMENT_ERROR if wrongly called
        """
        return_value = self.INVALID_ARGUMENT_ERROR

        return return_value


    def _execute_single_short(self, cve):
        """
        This is called by run and should never be called directly!!!!
        """
        pass



    def _format_text(self, text, width=70, tabulation=0):
        end_result = ''
        wrapped_text = textwrap.wrap(text, width=width)
        len_wrapped_text = len(wrapped_text)
        for d in wrapped_text:
            suffix = '' if len_wrapped_text == 1 else '\n'
            end_result += f'{'\t'*tabulation}{d}{suffix}'
        return end_result


