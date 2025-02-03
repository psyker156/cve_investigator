"""
This file is part of the VulnerabilityManager project, a tool aimed at managing vulnerabilities
Copyright (C) 2025  Philippe Godbout
"""

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