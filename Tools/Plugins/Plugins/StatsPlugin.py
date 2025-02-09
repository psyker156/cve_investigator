"""
This file is part of the VulnerabilityManager project, a tool aimed at managing vulnerabilities
Copyright (C) 2025  Philippe Godbout
"""

import datetime
import pprint
import re
import statistics
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
    INVALID_CONFIGURATION_ERROR = -2
    INVALID_CONFIGURATION_MESSAGE = "Minimal configuration requires Start and End Date"

    LOCAL_CACHE = {}

    COMMAND_TYPE_INVALID = 0
    COMMAND_SET_START = 1                       # This command sets the start date for the stats range
    COMMAND_SET_END = 2                         # This command sets the end date for the stats range
    COMMAND_CRUNCH_CVSS_DISTRIBUTION = 3        # This command will generate the stats according to the configuration
    COMMAND_RESET = 4                           # This command will reset all configuration if used alone, specific config otherwise
    COMMAND_ADD_KEYWORD = 5                     # This command will add a keyword to the search keys
    COMMAND_REMOVE_KEYWORD = 6
    COMMAND_ADD_CWE = 7                         # This command will limit the statistics to a set of CVE based on CWE
    COMMAND_REMOVE_CWE = 8
    COMMAND_CLEAR_CACHE = 9                     # This command will flush the local cache for the plugin
    COMMAND_LOAD_CACHE = 10                     # This command will add/update the CVEs from the range to the cache
    COMMAND_SHOW_CONFIG = 11                    # This will display the current plugin configuration
    COMMAND_OMIT_CVE_STATUS = 12                # This will add a CVE status to be omitted from the stats
    COMMAND_INCLUDE_CVE_STATUS = 13             # This will remove an omitted status

    VALID_COMMANDS = ['set_start',
                      'set_end',
                      'crunch_cvss_distribution',
                      'reset',
                      'add_keyword',
                      'remove_keyword',
                      'add_cwe',
                      'remove_cwe',
                      'clear_cache',
                      'load_cache',
                      'show_config',
                      'omit_cve_status',
                      'include_cve_status']


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
        self.register_error_code(self.INVALID_CONFIGURATION_ERROR, self.INVALID_CONFIGURATION_MESSAGE)

        self.start = "2023-01-01"
        self.end = "2023-03-31"
        self.keyword = []
        self.cwe = []
        self.omitted_cve_status = []

        self.load_cache()

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
                          'crunch_cvss_distribution',
                          'reset',
                          'add_keyword',
                          'remove_keyword',
                          'add_cwe',
                          'remove_cwe',
                          'clear_cache',
                          'load_cache',
                          'show_config',
                          'omit_cve_status',
                          'include_cve_status']
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
        elif command == 'crunch_cvss_distribution' and param is None:
            return_value = self.COMMAND_CRUNCH_CVSS_DISTRIBUTION
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
        elif command == 'omit_cve_status' and param in CVE.VALID_CVE_STATUS:
            return_value = self.COMMAND_OMIT_CVE_STATUS
        elif command == 'include_cve_status' and param in CVE.VALID_CVE_STATUS:
            return_value = self.COMMAND_INCLUDE_CVE_STATUS

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
        elif command_code == self.COMMAND_CRUNCH_CVSS_DISTRIBUTION:
            return_value = self.crunch_cvss_distribution()
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
        elif command_code == self.COMMAND_OMIT_CVE_STATUS:
            return_value = self.omit_cve_status(param)
        elif command_code == self.COMMAND_INCLUDE_CVE_STATUS:
            return_value = self.include_cve_status(param)

        return return_value

    def set_start(self, param):
        self.start = param
        return self.RUN_SUCCESS

    def set_end(self, param):
        self.end = param
        return self.RUN_SUCCESS

    def crunch_cvss_distribution(self):
        if self.start is None or self.end is None:
            return self.INVALID_CONFIGURATION_ERROR
        print(self._format_text(f'CVSS Distribution for CVEs published between {self.start} and {self.end}:', width=100))
        print(self._format_text(f'Numbers of CVEs published: {len(self.LOCAL_CACHE)}', tabulation=1))

        cvss_crunched_data = {}
        more_than_one_version = []
        more_than_one_same_version = []
        for cve in self.LOCAL_CACHE:
            usable_cve = self.LOCAL_CACHE[cve]
            if hasattr(usable_cve.infos, 'metrics'):
                t = vars(usable_cve.infos.metrics)
                if len(t) > 0:
                    if len(t) > 1:
                        more_than_one_version.append(t.keys())
                    for version in t.keys():
                        if version not in cvss_crunched_data:
                            cvss_crunched_data[version] = []

                        if len(t[version]) > 1:
                            more_than_one_same_version.append(t[version])
                        for single_metric in t[version]:
                            cvss_crunched_data[version].append(single_metric.cvssData.baseScore)
        print(self._format_text(f'{len(more_than_one_version)} CVEs had CVSS scores using multiple versions', tabulation=1))
        print(self._format_text(f'{len(more_than_one_same_version)} CVEs had multiple CVSS scores using the same version ', tabulation=1))

        for version in cvss_crunched_data.keys():
            usable_data = cvss_crunched_data[version]
            parsed_data = self.organise_cvss_base_score(usable_data)
            print(self._format_text(f'{version} data:', tabulation=1))
            print(self._format_text(f'{len(usable_data)} CVEs with {version} data', tabulation=2))
            print(self._format_text(f'Average base score {statistics.mean(usable_data)}', tabulation=2))
            print(self._format_text(f'Median base score {statistics.median(usable_data)}', tabulation=2))
            print(self._format_text(f'CVSS low: {len(parsed_data['low'])}', tabulation=2))
            print(self._format_text(f'CVSS medium: {len(parsed_data['medium'])}', tabulation=2))
            print(self._format_text(f'CVSS high: {len(parsed_data['high'])}', tabulation=2))
            print(self._format_text(f'CVSS critical: {len(parsed_data['critical'])}', tabulation=2))

        return self.RUN_SUCCESS

    def organise_cvss_base_score(self, base_score_list):
        data = {'low':[], 'medium':[], 'high':[], 'critical':[]}
        for base_score in base_score_list:
            if 0 <= base_score < 4:
                data['low'].append(base_score)
            elif 4 <= base_score < 7:
                data['medium'].append(base_score)
            elif 7 <= base_score < 9:
                data['high'].append(base_score)
            elif 9 <= base_score <= 10:
                data['critical'].append(base_score)
        return data

    def reset_configuration(self):
        self.start = None
        self.end = None
        self.keyword = []
        self.cwe = []
        self.omitted_cve_status = []
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
        return_value = self.INVALID_CONFIGURATION_ERROR
        if self.start is not None and self.end is not None:
            print(f'Loading CVEs from NVD for interval between {self.start} and {self.end}...')
            total_results = 5000
            start_index = 0
            print(f'Progression 0%')
            while start_index < total_results:
                cves = call_cve_api(start=self.start, end=self.end, index=start_index)
                results_per_page = cves['resultsPerPage']
                total_results = cves['totalResults']
                start_index += results_per_page

                vulnerabilities = cves['vulnerabilities']
                for cve in vulnerabilities:
                    self.LOCAL_CACHE[cve['cve']['id']] = CVE(cve)
                print(f'Progression {int((start_index/total_results)*100)}%')
            print(f'Done loading CVEs for interval between {self.start} and {self.end}')
            return_value = self.RUN_SUCCESS
        return return_value

    def show_config(self):
        print(f'{self._identity} Current configuration:')
        print(self._format_text(f'Start Data: {self.start}', tabulation=1))
        print(self._format_text(f'End Data: {self.end}', tabulation=1))
        print(self._format_text(f'Keywords: {str(self.keyword)}', tabulation=1))
        print(self._format_text(f'CWEs: {str(self.cwe)}', tabulation=1))
        print(self._format_text(f'Omitted CVE Statuses: {str(self.omitted_cve_status)}', tabulation=1))
        print(self._format_text(f'Local Cache CVE count: {len(self.LOCAL_CACHE)}', tabulation=1))
        return self.RUN_SUCCESS

    def omit_cve_status(self, param):
        return_value = self.INVALID_ARGUMENT_ERROR
        if param not in self.omitted_cve_status:
            self.omitted_cve_status.append(param)
            return_value = self.RUN_SUCCESS
        return return_value

    def include_cve_status(self, param):
        return_value = self.INVALID_ARGUMENT_ERROR
        if param in self.omitted_cve_status:
            self.omitted_cve_status.remove(param)
            return_value = self.RUN_SUCCESS
        return return_value

    def _format_text(self, text, width=70, tabulation=0):
        end_result = ''
        wrapped_text = textwrap.wrap(text, width=width)
        len_wrapped_text = len(wrapped_text)
        for d in wrapped_text:
            suffix = '' if len_wrapped_text == 1 else '\n'
            end_result += f'{'\t'*tabulation}{d}{suffix}'
        return end_result


