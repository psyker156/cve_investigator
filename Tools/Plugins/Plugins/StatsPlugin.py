"""
This file is part of the VulnerabilityManager project, a tool aimed at managing vulnerabilities
Copyright (C) 2025  Philippe Godbout
"""

import datetime
import pprint
import re
import textwrap

from NetworkServices.NISTAPIServices import call_cve_api
from Parsers.CVE import CVE
from Parsers.CWE import CWE
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
    COMMAND_ADD_KEYWORD = 5         # This command will add a keyword to the search keys
    COMMAND_REMOVE_KEYWORD = 6
    COMMAND_ADD_CWE = 7             # This command will limit the statistics to a set of CVE based on CWE
    COMMAND_REMOVE_CWE = 8
    COMMAND_CLEAR_CACHE = 9         # This command will flush the local cache for the plugin
    COMMAND_LOAD_CACHE = 10         # This command will add/update the CVEs from the range to the cache
    COMMAND_SHOW_CONFIG = 11        # This will display the current plugin configuration

    VALID_COMMANDS = ['set_start',
                      'set_end',
                      'crunch',
                      'reset',
                      'add_keyword',
                      'remove_keyword',
                      'add_cwe',
                      'remove_cwe',
                      'clear_cache',
                      'load_cache',
                      'show_config']


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

    def validate_date(self, date_str):
        try:
            datetime.datetime.strptime(date_str, '%Y-%m-%d')
            return True
        except ValueError:
            return False

    def validate_cwe(self, cwe_str):
        return_value = False
        cwe = CWE()
        cwe_desc = cwe.description_for_code(cwe_str)
        if cwe_desc is not None:
            return_value = True
        else:
            print(f'{cwe_str} is not a valid CWE or CWE repository is out of date')
        return return_value

    def validate_command(self, args):
        """
        This is a localized command parser that every plugin must implement.
        VALID_COMMANDS = ['set_start',
                          'set_end',
                          'crunch',
                          'reset',
                          'add_keyword',
                          'remove_keyword',
                          'add_cwe',
                          'remove_cwe',
                          'clear_cache',
                          'load_cache',
                          'show_config']
        :param args: a list of commands including the command name
        :return: commandType, param
        """
        return_value = self.COMMAND_TYPE_INVALID

        command = None
        param = None

        if len(args) >= 2:
            command = args[1]   # Index one is the local command while index 0 is the global command

        if  command in self.VALID_COMMANDS:
            try:
                param = args[2]
            except IndexError:
                pass

        if command == 'set_start' and self.validate_date(param):
            return_value = self.COMMAND_SET_START
        elif command == 'set_end' and self.validate_date(param):
            return_value = self.COMMAND_SET_END
        elif command == 'crunch' and param is None:
            return_value = self.COMMAND_CRUNCH
        elif command == 'reset' and param is None:
            return_value = self.COMMAND_RESET
        elif command == 'add_keyword' and param is not None:
            return_value = self.COMMAND_ADD_KEYWORD
        elif command == 'remove_keyword' and param is not None:
            return_value = self.COMMAND_REMOVE_KEYWORD
        elif command == 'add_cwe' and self.validate_cwe(param):
            return_value = self.COMMAND_ADD_CWE
        elif command == 'remove_cwe' and self.validate_cwe(param):
            return_value = self.COMMAND_REMOVE_CWE
        elif command == 'clear_cache' and param is None:
            return_value = self.COMMAND_CLEAR_CACHE
        elif command == 'load_cache' and param is None:
            return_value = self.COMMAND_LOAD_CACHE
        elif command == 'show_config' and param is None:
            return_value = self.COMMAND_SHOW_CONFIG

        return return_value, param


    def run(self, params=None):
        """
        This will simply display general information about cve_investigator. It "kinda" is the
        hello world of the plugins :P
        :param params: list, in this case the list should be empty!!!
        :return: 0 if properly called, self.INVALID_ARGUMENT_ERROR if wrongly called
        """
        return_value = self.INVALID_ARGUMENT_ERROR
        command_code, param = self.validate_command(params)

        if command_code == self.COMMAND_SET_START:
            return_value = self.set_start(param)
        elif command_code == self.COMMAND_SET_END:
            return_value = self.set_end(param)
        elif command_code == self.COMMAND_CRUNCH:
            return_value = self.crunch()
        elif command_code == self.COMMAND_RESET:
            return_value = self.reset_configuration()
        elif command_code == self.COMMAND_ADD_KEYWORD:
            return_value = self.add_keyword(param)
        elif command_code == self.COMMAND_REMOVE_KEYWORD:
            return_value = self.remove_keyword(param)
        elif command_code == self.COMMAND_ADD_CWE:
            return_value = self.add_cwe(param)
        elif command_code == self.COMMAND_REMOVE_CWE:
            return_value = self.remove_cwe(param)
        elif command_code == self.COMMAND_CLEAR_CACHE:
            return_value = self.clear_cache()
        elif command_code == self.COMMAND_LOAD_CACHE:
            return_value = self.load_cache()
        elif command_code == self.COMMAND_SHOW_CONFIG:
            return_value = self.show_config()

        return return_value

    def set_start(self, param):
        self.start = param
        return self.RUN_SUCCESS

    def set_end(self, param):
        self.end = param
        return self.RUN_SUCCESS

    def crunch(self):
        pass
        return self.RUN_SUCCESS

    def reset_configuration(self):
        self.start = None
        self.end = None
        self.keyword = []
        self.cwe = []
        return self.RUN_SUCCESS

    def add_keyword(self, param):
        return_value = self.INVALID_ARGUMENT_ERROR
        if param not in self.keyword:
            self.keyword.append(param)
            return_value = self.RUN_SUCCESS
        return return_value

    def remove_keyword(self, param):
        return_value = self.INVALID_ARGUMENT_ERROR
        if param in self.keyword:
            self.keyword.remove(param)
            return_value = self.RUN_SUCCESS
        return return_value

    def add_cwe(self, param):
        return_value = self.INVALID_ARGUMENT_ERROR
        if param[0:4].casefold() == 'cwe-'.casefold() and param not in self.cwe:
            self.cwe.append(param)
            return_value = self.RUN_SUCCESS
        return return_value


    def remove_cwe(self, param):
        return_value = self.INVALID_ARGUMENT_ERROR
        if param[0:4].casefold() == 'cwe-'.casefold() and param in self.cwe:
            self.cwe.remove(param)
            return_value = self.RUN_SUCCESS
        return return_value

    def clear_cache(self):
        self.LOCAL_CACHE = {}
        return self.RUN_SUCCESS

    def load_cache(self):
        pass
        return self.RUN_SUCCESS

    def show_config(self):
        print(f'{self._identity} Current configuration:')
        print(self._format_text(f'Start Data: {self.start}', tabulation=1))
        print(self._format_text(f'End Data: {self.end}', tabulation=1))
        print(self._format_text(f'Keywords: {str(self.keyword)}', tabulation=1))
        print(self._format_text(f'CWEs: {str(self.cwe)}', tabulation=1))
        print(self._format_text(f'Local Cache CVE count: {len(self.LOCAL_CACHE)}', tabulation=1))
        return self.RUN_SUCCESS

    def _format_text(self, text, width=70, tabulation=0):
        end_result = ''
        wrapped_text = textwrap.wrap(text, width=width)
        len_wrapped_text = len(wrapped_text)
        for d in wrapped_text:
            suffix = '' if len_wrapped_text == 1 else '\n'
            end_result += f'{'\t'*tabulation}{d}{suffix}'
        return end_result


