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

import pprint
import re
import datetime

from NetworkServices.NISTAPIServices import call_cve_api
from NetworkServices.CISAApiCall import call_cisa_kev
from Parsers.CVE import CVE
from Parsers.CWE import CWE
from Parsers.KEV import KEV
from Tools.configuration import *

import Tools.Plugins.BasePlugin as BasePlugin


class CisaKev(BasePlugin.BasePlugin):
    """
    This plugin allows the user to explore CVEs
    """
    ITERATION = 2

    INFO_HELP_STRING = ('cisakev Blah\n'
                        '# cisakev CVE-XXXX-XXXX - Checks if a given CVE is part of KEV\n'
                        '# cisakev time_to_exploitation - Computes time to exploitation stats for every CVE in the kev\n'
                        '# cisakev time_to_exploitation_from YYYY-MM-DD - Computes time to exploitation stats from a given date\n'
                        '# cisakev time_to_exploitation_cache - Computes time to exploitation stats CVEs present in cache\n'
                        '# cisakev refresh_kev_cache - Gets the latest KEV file and keep in local plugin cache')


    INVALID_ARGUMENT_ERROR = -1
    INVALID_ARGUMENT_MESSAGE = "Error while calling cisa kev"

    CVE_REGEX = r"(?i)^cve-\d{4}-\d{4,}$"



    COMMAND_TYPE_INVALID = 0
    COMMAND_TYPE_CVE = 1
    COMMAND_TYPE_TIME_TO_EXPLOITATION = 2
    COMMAND_TYPE_TIME_TO_EXPLOITATION_FROM = 3
    COMMAND_TYPE_TIME_TO_EXPLOITATION_CACHE = 4
    COMMAND_TYPE_REFRESH_KEV_CACHE = 5


    def __init__(self, cache, filtered_cache):
        """
        Simply sets up the plugin so it can be used.
        """
        super().__init__()
        self.LOCAL_CACHE = cache
        self.LOCAL_CACHE_FILTERED = filtered_cache
        self.LOCAL_KEV_CACHE = {'date_released': None, 'kev': {}}
        self.set_plugin_type('command')
        self.set_plugin_identity('cisakev')
        self.set_plugin_description('Enables KEV based processing of CVEs')
        self.set_help(self.INFO_HELP_STRING)
        self.register_error_code(self.INVALID_ARGUMENT_ERROR, self.INVALID_ARGUMENT_MESSAGE)

    def validate_date(self, date_str):
        try:
            datetime.datetime.strptime(date_str, '%Y-%m-%d')
            return True
        except ValueError:
            return False

    def validate_command(self, args):
        """
        This is a localized command parser that every plugin must implement.
        :param args: a list of commands including the command name
        :return: return_value, cve_number, sub_command
        """
        return_value = self.COMMAND_TYPE_INVALID
        cve_number = None
        date = None
        len_args = len(args)

        if len_args == 2 and bool(re.match(self.CVE_REGEX, args[1])):
            return_value = self.COMMAND_TYPE_CVE
            cve_number = args[1]
        elif len_args == 2 and args[1] == "time_to_exploitation":
            return_value = self.COMMAND_TYPE_TIME_TO_EXPLOITATION
        elif len_args == 3 and args[1] == "time_to_exploitation_from" and self.validate_date(args[2]):
            return_value = self.COMMAND_TYPE_TIME_TO_EXPLOITATION_FROM
            date = args[2]
        elif len_args == 2 and args[1] == "time_to_exploitation_cache":
            return_value = self.COMMAND_TYPE_TIME_TO_EXPLOITATION_CACHE
        elif len_args == 2 and args[1] == "refresh_kev_cache":
            return_value = self.COMMAND_TYPE_REFRESH_KEV_CACHE

        return return_value, cve_number, date


    def run(self, params=None):
        """
        This will simply display general information about cve_investigator. It "kinda" is the
        hello world of the plugins :P
        :param params: list, in this case the list should be empty!!!
        :return: 0 if properly called, self.INVALID_ARGUMENT_ERROR if wrongly called
        """
        return_value = self.INVALID_ARGUMENT_ERROR
        valid_command, cve_number, date = self.validate_command(params)

        if valid_command == self.COMMAND_TYPE_CVE:
            return_value = self._cve(cve_number)
        elif valid_command == self.COMMAND_TYPE_TIME_TO_EXPLOITATION:
            return_value = self._time_to_exploitation()
        elif valid_command == self.COMMAND_TYPE_TIME_TO_EXPLOITATION_FROM:
            return_value = self._time_to_exploitation(date)
        elif valid_command == self.COMMAND_TYPE_TIME_TO_EXPLOITATION_CACHE:
            return_value = self._time_to_exploitation_cache()
        elif valid_command == self.COMMAND_TYPE_REFRESH_KEV_CACHE:
            self._refresh_kev_cache()
            return_value = self.RUN_SUCCESS

        return return_value

    def _get_cve_published_and_kev_dates(self, cve_number):
        return_value = self.INVALID_ARGUMENT_ERROR
        result = self.INVALID_ARGUMENT_ERROR
        cve = None
        cve_date = None
        kev_date = None
        if len(self.LOCAL_KEV_CACHE['kev']) == 0:
            result = self._refresh_kev_cache()

        cve = self._obtain_cve(cve_number)

        if cve is not None:
            cve_date = cve.published_date.split('T')[0]
            if cve.cve_number in self.LOCAL_KEV_CACHE['kev']:
                kev_date = self.LOCAL_KEV_CACHE['kev'][cve.cve_number].date_added

        return return_value, cve_date, kev_date

    def _date_comparator(self, cve_date, kev_date):
        if type(cve_date) != datetime.datetime:
            if self.validate_date(cve_date):
                cve_date = datetime.datetime.strptime(cve_date, '%Y-%m-%d')
            else:
                raise ValueError('Error while comparing dates')

        if type(kev_date) != datetime.datetime:
            if self.validate_date(kev_date):
                kev_date = datetime.datetime.strptime(kev_date, '%Y-%m-%d')
            else:
                raise ValueError('Error while comparing dates')


        return (kev_date - cve_date).days

    def _time_to_exploitation(self, date_from='1900-01-01'):
        return_value = self.INVALID_ARGUMENT_ERROR
        self._refresh_kev_cache()
        output = []

        for cve_number in self.LOCAL_KEV_CACHE['kev'].keys():
            _, cve_date, kev_date = self._get_cve_published_and_kev_dates(cve_number)
            if cve_date is not None and kev_date is not None and self._date_comparator(date_from, cve_date) >= 0:
                delta = self._date_comparator(cve_date, kev_date)
                output.append(f'{cve_number};{cve_date};{kev_date};{delta}')
                print(f'{cve_number} added to output')

        for line in output:
            print(line)

        return_value = self.RUN_SUCCESS
        return return_value

    def _time_to_exploitation_cache(self):
        return_value = self.INVALID_ARGUMENT_ERROR
        self._refresh_kev_cache()
        output = []

        for cve_number in self.LOCAL_KEV_CACHE['kev'].keys():
            if cve_number in self.LOCAL_CACHE:
                cve = self.LOCAL_CACHE[cve_number]
                cve_date = cve.published_date.split('T')[0]
                kev_date = self.LOCAL_KEV_CACHE['kev'][cve.cve_number].date_added
                delta = self._date_comparator(cve_date, kev_date)
                output.append(f'{cve_number}\t{cve_date}\t{kev_date}\t{delta}')

        for line in output:
            print(line)

        return_value = self.RUN_SUCCESS
        return return_value

    def _cve(self, cve_number):
        return_value = self.INVALID_ARGUMENT_ERROR
        result, cve_date, kev_date = self._get_cve_published_and_kev_dates(cve_number)
        delta = self._date_comparator(cve_date, kev_date)
        if cve_date is not None and kev_date is not None:
            print(f'{cve_number} published on: {cve_date} '
                  f'and has been added to CISA KEV on: {kev_date}, '
                  f'{delta} day(s) after being originally published.')
            return_value = self.RUN_SUCCESS
        elif cve_date is not None:
            print(f'{cve_number} published on: {cve_date} but has not been located in CISA KEV data')
            return_value = self.RUN_SUCCESS
        else:
            print(f'{cve_number} appears to be invalid')
        return return_value

    def _refresh_kev_cache(self):
        return_value = self.INVALID_ARGUMENT_ERROR
        print('Checking CISA KEV for update')
        json_kev = call_cisa_kev()
        if json_kev['dateReleased'] != self.LOCAL_KEV_CACHE['date_released']:
            print('CISA Kev file has an available update... Loading updates...')

            if len(self.LOCAL_KEV_CACHE['kev']) != 0:
                self.LOCAL_KEV_CACHE['kev'] = {}

            for v in json_kev['vulnerabilities']:
                valid_kev = KEV(v)
                self.LOCAL_KEV_CACHE['kev'][valid_kev.cve_number] = valid_kev
            return_value = self.RUN_SUCCESS
            print('CISA local KEV cache has been updated')
        else:
            print('CISA Kev file has does not have an available update...')
            return_value = self.RUN_SUCCESS

        return return_value

    def _obtain_cve(self, cve):
        if cve not in self.LOCAL_CACHE:
            print(f'Searching NVD for {cve}...')
            r = call_cve_api(cve=cve)

            if len(r['vulnerabilities']) == 0:
                raise Exception(f'No vulnerabilities found for {cve} in NVD records')
            self.LOCAL_CACHE[cve] = CVE(r['vulnerabilities'][0])
            print(f'{cve} was added to local cache from NVD')
        else:
            print(f'Loading {cve} from local cache')

        return self.LOCAL_CACHE[cve]





