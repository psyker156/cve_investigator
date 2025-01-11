"""
This file is part of the VulnerabilityManager project, a tool aimed at managing vulnerabilities
Copyright (C) 2025  Philippe Godbout
"""

import json

from NetworkServices.CallUrlBasedRestAPI import call_url_based_rest_api

# All the CISA api documentation can be found https://www.cisa.gov/known-exploited-vulnerabilities-catalog

KEV_JSON_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

def call_cisa_kev():
    response = call_url_based_rest_api(KEV_JSON_URL)
    return json.loads(response)
