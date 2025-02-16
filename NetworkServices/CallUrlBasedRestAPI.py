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

import requests
import time

def call_url_based_rest_api(url, headers=None, safe=False):
    # Just an effort to not blast out the APIs
    if safe:
        time.sleep(1)

    print(f'Calling url: {url}')
    response = None
    if headers is not None:
        response = requests.get(url, headers=headers)
    else:
        response = requests.get(url)

    if response.status_code != 200:
        raise ConnectionError(f'ERROR - http error code {response.status_code} while calling { url }')
    return response.text