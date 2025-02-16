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

import datetime
import statistics
from collections import defaultdict

from NetworkServices.NISTAPIServices import call_cve_api
from Parsers.CVE import CVE
from Parsers.CVSSMetricParsers import *
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
                        '\t# stats clear_cache\t Remove all data from the local cache (required to start anew)\n'
                        '\t# stats load_cache\t Loads/update all CVEs from the range to local cache (required\n'
                        '\t# stats show_conifg\t Current state of plugin will be displayed including cache\n'
                        '\t# stats omit_cve_status\t CVEs with the provided status will be ignored from stats\n'
                        '\t# stats include_cve_status\t Reverts the effect of omit_cve_status\n'
                        '\t# stats crunch_attack_vector\t Provides stats about the attack vectors\n'
                        '\t# stats crunch_cwe_top_10\t Provides stats about the top 10 CWEs for CVEs in cache\n'
                        '\t# stats crunch_cvss_version_representation\t General CVSS version adoption stats\n'
                        '\t# stats crunch_exploit_status\t Provides CVSS v4.0 exploit status information\n'
                        '\t# stats crunch_cvss_distribution\t Runs CVSS severity stats')


    INVALID_ARGUMENT_ERROR = -1
    INVALID_ARGUMENT_MESSAGE = "Command is invalid, see help to learn how to use it"
    INVALID_CONFIGURATION_ERROR = -2
    INVALID_CONFIGURATION_MESSAGE = "Minimal configuration requires Start and End Date"

    COMMAND_TYPE_INVALID = 0
    COMMAND_SET_START = 1                       # This command sets the start date for the stats range
    COMMAND_SET_END = 2                         # This command sets the end date for the stats range
    COMMAND_CRUNCH_CVSS_DISTRIBUTION = 3        # This command will generate general CVSS base score stats
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
    COMMAND_CRUNCH_ATTACK_VECTOR = 14           # This will generate general statistics relating to Attack Vector
    COMMAND_CRUNCH_CWE_TOP_10 = 15              # This will return CWE top 10 along with number of instance
    COMMAND_CRUNCH_CVSS_VERSION_REPRESENTATION = 16     # Computes information about CVSS versions adoption
    COMMAND_CRUNCH_EXPLOIT_STATUS = 17          # At this moment, this returns stats about CVSS v4.0 exploit status

    VALID_COMMANDS = ['set_start',
                      'set_end',
                      'crunch_cvss_distribution',
                      'crunch_attack_vector',
                      'crunch_cwe_top_10',
                      'crunch_cvss_version_representation',
                      'crunch_exploit_status',
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


    def __init__(self, cache):
        """
        Simply sets up the plugin so it can be used.
        """
        super().__init__()
        self.LOCAL_CACHE = cache
        self.LOCAL_CACHE_FILTERED = []

        self.set_plugin_type('command')
        self.set_plugin_identity('stats')
        self.set_plugin_description('Quickly generates statistics about CVEs')
        self.set_help(self.INFO_HELP_STRING)
        self.register_error_code(self.INVALID_ARGUMENT_ERROR, self.INVALID_ARGUMENT_MESSAGE)
        self.register_error_code(self.INVALID_CONFIGURATION_ERROR, self.INVALID_CONFIGURATION_MESSAGE)

        self.start = None
        self.end = None
        self.keyword = []
        self.cwe = []
        self.omitted_cve_status = ['Rejected']

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

    def filter_cache(self):
        """
        This method will filter the main cache in a way that the filtered cache may only contain CVEs that
        respect the stats plugin configuration criteria.

        Caches are:
            LOCAL_CACHE = {}
            LOCAL_CACHE_FILTERED = []

        Filters criteria are:
            self.start = "XXXX-XX-XX"
            self.end = "XXXX-XX-XX"
            self.keyword = []
            self.cwe = []
            self.omitted_cve_status = []
        """
        self.LOCAL_CACHE_FILTERED = []
        print(f'Filtering cache based on current configuration:')
        self.show_config()
        print(f'Filtering...')
        for cve in self.LOCAL_CACHE:
            usable_cve = self.LOCAL_CACHE[cve]
            if (self.in_date_range(usable_cve)
                    and self.contains_keywords(usable_cve)
                    and self.contains_cwe(usable_cve)
                    and self.is_not_within_status(usable_cve)):
                # All matching criteria have checked positively!
                self.LOCAL_CACHE_FILTERED.append(usable_cve)
        print(f'Done filtering')
        print(self._format_text(f'Pre-Filter CVE count: {len(self.LOCAL_CACHE)}', tabulation=1))
        print(self._format_text(f'Post-Filter CVE count: {len(self.LOCAL_CACHE_FILTERED)}', tabulation=1))

    def in_date_range(self, usable_cve):
        """
        This will validate if a CVE is within the configured date range.
        :param usable_cve: a CVE object
        :return: True if within, else False
        """
        return_value = False

        start = datetime.datetime.fromisoformat(self.start + 'T00:00:00.000')
        end = datetime.datetime.fromisoformat(self.end + 'T23:59:59.999')
        cve_datetime = datetime.datetime.fromisoformat(usable_cve.infos.published)

        if start <= cve_datetime <= end:
            return_value = True

        return return_value

    def contains_keywords(self, usable_cve):
        return_value = True
        if len(self.keyword) == 0:
            return return_value
        descriptions_concatenation = ""

        for description in usable_cve.infos.descriptions:
            descriptions_concatenation += description.value + " "

        for keyword in self.keyword:
            if keyword.casefold() not in descriptions_concatenation.casefold():
                return_value = False
                break

        return return_value

    def contains_cwe(self, usable_cve):
        return_value = False

        if len(self.cwe) == 0:
            return_value = True
            return return_value

        if hasattr(usable_cve.infos, 'weaknesses'):
            for weakness in usable_cve.infos.weaknesses:
                for single_description in weakness.description:
                    if single_description.value.casefold() in [x.casefold() for x in self.cwe]:
                        return_value = True
                        break

        return return_value

    def is_not_within_status(self, usable_cve):
        return_value = True
        if len(self.omitted_cve_status) == 0:
            return return_value

        if usable_cve.status.casefold() in [x.casefold() for x in self.omitted_cve_status]:
            return_value = False

        return return_value

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

    def validate_command(self, args):
        """
        This is a localized command parser that every plugin must implement.
        VALID_COMMANDS = ['set_start',
                          'set_end',
                          'crunch_cvss_distribution',
                          'crunch_attack_vector',
                          'crunch_cwe_top_10',
                          'crunch_cvss_version_representation',
                          'crunch_exploit_status',
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
        elif command == 'crunch_attack_vector' and param is None:
            return_value = self.COMMAND_CRUNCH_ATTACK_VECTOR
        elif command == 'crunch_cwe_top_10' and param is None:
            return_value = self.COMMAND_CRUNCH_CWE_TOP_10
        elif command == 'crunch_cvss_version_representation' and param is None:
            return_value = self.COMMAND_CRUNCH_CVSS_VERSION_REPRESENTATION
        elif command == 'crunch_exploit_status' and param is None:
            return_value = self.COMMAND_CRUNCH_EXPLOIT_STATUS
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
        elif command_code == self.COMMAND_CRUNCH_ATTACK_VECTOR:
            return_value = self.crunch_attack_vector()
        elif command_code == self.COMMAND_CRUNCH_CWE_TOP_10:
            return_value = self.crunch_cwe_top_10()
        elif command_code == self.COMMAND_CRUNCH_CVSS_VERSION_REPRESENTATION:
            return_value = self.crunch_cvss_version_representation()
        elif command_code == self.COMMAND_CRUNCH_EXPLOIT_STATUS:
            return_value = self.crunch_exploit_status()
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

    def pre_crunch_setup(self):
        if self.start is None or self.end is None:
            return False
        self.filter_cache()
        return True

    def crunch_cvss_distribution(self):
        if not self.pre_crunch_setup():
            return self.INVALID_CONFIGURATION_ERROR

        print(self._format_text(f'CVSS distribution for CVEs published between {self.start} and {self.end}:', width=100))
        print(self._format_text(f'Numbers of CVEs: {len(self.LOCAL_CACHE_FILTERED)}', tabulation=1))

        cvss_crunched_data = {}

        for usable_cve in self.LOCAL_CACHE_FILTERED:
            for cvss in usable_cve.cvss:
                if cvss.version not in cvss_crunched_data:
                    cvss_crunched_data[cvss.version] = [cvss.base_score]
                else:
                    cvss_crunched_data[cvss.version].append(cvss.base_score)

        for version in cvss_crunched_data.keys():
            usable_data = cvss_crunched_data[version]
            parsed_data = self.organise_cvss_base_score(usable_data)
            print(self._format_text(f'CVSS v{version} data:', tabulation=1))
            print(self._format_text(f'{len(usable_data)} CVEs with {version} data', tabulation=2))
            print(self._format_text(f'Average base score {statistics.mean(usable_data)}', tabulation=2))
            print(self._format_text(f'Median base score {statistics.median(usable_data)}', tabulation=2))
            print(self._format_text(f'CVSS low: {len(parsed_data['low'])}', tabulation=2))
            print(self._format_text(f'CVSS medium: {len(parsed_data['medium'])}', tabulation=2))
            print(self._format_text(f'CVSS high: {len(parsed_data['high'])}', tabulation=2))
            print(self._format_text(f'CVSS critical: {len(parsed_data['critical'])}', tabulation=2))

        return self.RUN_SUCCESS

    def crunch_attack_vector(self):
        if not self.pre_crunch_setup():
            return self.INVALID_CONFIGURATION_ERROR

        vectors_crunched_data = {'2.0':{}, '3.0':{}, '3.1':{}, '4.0':{}}
        cves_without_cvss = []

        print(self._format_text(f'Attack Vector distribution for CVEs published between {self.start} and {self.end}:', width=100))
        print(self._format_text(f'Numbers of CVEs: {len(self.LOCAL_CACHE_FILTERED)}', tabulation=1))

        for usable_cve in self.LOCAL_CACHE_FILTERED:
            if len(usable_cve.cvss) == 0:
                cves_without_cvss.append(usable_cve.infos.id)
                continue
            for cvss in usable_cve.cvss:
                if cvss.attack_vector not in vectors_crunched_data[cvss.version].keys():
                    vectors_crunched_data[cvss.version][cvss.attack_vector] = 1
                    break
                else:
                    vectors_crunched_data[cvss.version][cvss.attack_vector] += 1
                    break

        print(self._format_text(f'The following CVE {len(cves_without_cvss)} do not have Attack Vector information:', tabulation=1, width=100))
        print(self._format_text(f'{cves_without_cvss}', tabulation=2, width=100))
        print()
        print(self._format_text(f'Attack Vector distribution', tabulation=1))
        for version in vectors_crunched_data.keys():
            print(self._format_text(f'CVSS version: {version}', tabulation=2))
            for vector in vectors_crunched_data[version]:
                print(self._format_text(f'AV: {vector}: {vectors_crunched_data[version][vector]}', tabulation=3))

        return self.RUN_SUCCESS

    def crunch_cwe_top_10(self):
        if not self.pre_crunch_setup():
            return self.INVALID_CONFIGURATION_ERROR

        cwe_basic_infos = defaultdict(int)
        unknown_cwe_cves = []

        print(self._format_text(f'Top 10 CWE for CVEs published between {self.start} and {self.end}:', width=100))

        for usable_cve in self.LOCAL_CACHE_FILTERED:
            if len(usable_cve.cwe) == 0:
                unknown_cwe_cves.append(usable_cve.infos.id)
                continue
            cwe_list = []
            for cwe in usable_cve.cwe:
                cwe_list.append(cwe)

            cwe_list = list(set(cwe_list))

            for cwe in cwe_list:
                cwe_basic_infos[cwe] += 1

        print(self._format_text(f'The following CVE ({len(unknown_cwe_cves)}) do not have CWE information:', tabulation=1, width=100))
        print(self._format_text(f'{unknown_cwe_cves}', tabulation=2, width=100))
        print()
        sorted_keys = sorted(cwe_basic_infos, key=lambda k: cwe_basic_infos[k], reverse=True)
        cwe_parser = CWE()
        for key in sorted_keys if len(sorted_keys) <= 10 else sorted_keys[:10]:
            print(self._format_text(f'{key}: {cwe_basic_infos[key]}', tabulation=1))
            print(self._format_text(f'{cwe_parser.description_for_code(key)}', tabulation=2, width=100))

        return self.RUN_SUCCESS

    def crunch_cvss_version_representation(self):
        if not self.pre_crunch_setup():
            return self.INVALID_CONFIGURATION_ERROR

        v2_qty = 0
        v30_qty = 0
        v31_qty = 0
        v40_qty = 0
        no_data_qty = 0

        for cve in self.LOCAL_CACHE_FILTERED:
            v2 = False
            v30 = False
            v31 = False
            v40 = False

            if len(cve.cvss) == 0:
                no_data_qty += 1
                continue

            for cvss in cve.cvss:
                if cvss.version == '2.0':
                    v2 = True
                elif cvss.version == '3.0':
                    v30 = True
                elif cvss.version == '3.1':
                    v31 = True
                elif cvss.version == '4.0':
                    v40 = True

            if v2:
                v2_qty += 1
            if v30:
                v30_qty += 1
            if v31:
                v31_qty += 1
            if v40:
                v40_qty += 1

        print(self._format_text(f'CVSS adoption data for CVEs published between {self.start} and {self.end}:', width=100))
        print(self._format_text(f'CVEs missing CVSS information: {no_data_qty}', tabulation=1))
        print(self._format_text(f'CVEs with CVSS v2.0 information: {v2_qty}', tabulation=1))
        print(self._format_text(f'CVEs with CVSS v3.0 information: {v30_qty}', tabulation=1))
        print(self._format_text(f'CVEs with CVSS v3.1 information: {v31_qty}', tabulation=1))
        print(self._format_text(f'CVEs with CVSS v4.0 information: {v40_qty}', tabulation=1))

        return self.RUN_SUCCESS

    def crunch_exploit_status(self):
        if not self.pre_crunch_setup():
            return self.INVALID_CONFIGURATION_ERROR

        exploit_status = defaultdict(int)

        for cve in self.LOCAL_CACHE_FILTERED:
            for cvss in cve.cvss:
                if cvss.version == '4.0':
                    if cvss.exploit_maturity is not None:
                        exploit_status[cvss.exploit_maturity] += 1

        print(self._format_text(f'Exploit status for CVEs published between {self.start} and {self.end}:', width=100))
        for k in exploit_status.keys():
            print(self._format_text(f'{k}: {exploit_status[k]}', tabulation=1))
        return self.RUN_SUCCESS

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
            self.cwe.append(param.upper())
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




