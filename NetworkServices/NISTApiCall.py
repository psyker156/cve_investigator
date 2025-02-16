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

import json
import requests
import time

from NetworkServices.CallUrlBasedRestAPI import call_url_based_rest_api

# The following are all constants used to locate data on the local hard drive
API_KEY_LOCATION = 'NetworkServices/key.txt'

def fetch_api_key():
        with open(API_KEY_LOCATION, 'r', encoding='utf-8') as f:
            return f.readline().strip()

def call_nist_api(use_api_key, url, safe=False):
    api_key = None
    try:
        if use_api_key:
            api_key = fetch_api_key()
    except FileNotFoundError:
        print('ERROR - API key file not found, continuing without an API key.')
        api_key = None

    if api_key is not None:
        response = call_url_based_rest_api(url, headers={'apiKey': api_key}, safe=safe)
    else:
        response = call_url_based_rest_api(url, safe=safe)

    time.sleep(6)   # This is based on NIST recommendation: https://nvd.nist.gov/general/news/API-Key-Announcement

    return json.loads(response)
