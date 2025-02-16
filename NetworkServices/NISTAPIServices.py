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

from NetworkServices.NISTApiCall import call_nist_api

# All the NIST api documentation can be found https://nvd.nist.gov/general

CVE_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
CVE_CHANGE_HISTORY_URL = 'https://services.nvd.nist.gov/rest/json/cvehistory/2.0'
DATA_SOURCES_API_URL = 'https://services.nvd.nist.gov/rest/json/source/2.0'
CPE_API_URL = 'https://services.nvd.nist.gov/rest/json/cpes/2.0'
CPE_MATCH_API_URL = 'https://services.nvd.nist.gov/rest/json/cpematch/2.0'


def call_cve_api(cve=None,
                 keyword=None,
                 lastx=None,
                 yesterday=False,
                 start=None,
                 end=None,
                 index=0,
                 nistapikey=True,
                 safe=False):
    request_string = CVE_API_URL + '?' + 'startIndex=' + str(index) + '&'
    if start is not None and not yesterday:
        request_string += 'pubStartDate=' + start + 'T00:00:00.000' + '&'
    if end is not None and not yesterday:
        request_string += 'pubEndDate=' + end + 'T23:59:59.999' + '&'
    if yesterday:
        today = datetime.datetime.now(datetime.UTC).date()
        yesterday = (today - datetime.timedelta(days=1)).isoformat()
        request_string += 'pubStartDate=' + yesterday + 'T00:00:00.000' + '&'
        request_string += 'pubEndDate=' + yesterday + 'T23:59:59.999' + '&'
    if lastx is not None:
        x = lastx
        right_now = datetime.datetime.now(datetime.UTC)
        x_hours_ago = right_now - datetime.timedelta(hours=x)
        request_string += 'pubStartDate=' + x_hours_ago.isoformat(timespec='seconds').split('+')[0] + '&'
        request_string += 'pubEndDate=' + right_now.isoformat(timespec='seconds').split('+')[0] + '&'
    request_string += '' if keyword is None else 'keywordSearch=' + keyword + '&'
    request_string += '' if cve is None else 'cveId=' + cve + '&'

    return call_nist_api(nistapikey, request_string, safe=safe)

def call_cve_history_api(cve, use_api_key=False, index=0):
    request_string = CVE_API_URL + '?' + 'cveId=' + cve
    return call_nist_api(use_api_key, request_string)

def call_source_api(use_api_key=False):
    data = call_nist_api(use_api_key, DATA_SOURCES_API_URL)
