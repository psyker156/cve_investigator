"""
This file is part of the VulnerabilityManager project, a tool aimed at managing vulnerabilities
Copyright (C) 2025  Philippe Godbout
"""

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
