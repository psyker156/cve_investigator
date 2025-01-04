"""
This file is part of the VulnerabilityManager project, a tool aimed at managing vulnerabilities
Copyright (C) 2025  Philippe Godbout
"""

import json
from types import SimpleNamespace

class CVE:
    """
    This class represents a single Vulnerability presented as a python object.
    The reason for this class to exist is to avoid users having to deal directly with raw CVE data.
    This class conforms to the CVE API Schema: https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema
    """

    infos = None

    def __init__(self, individual_cve):
        """
        The constructor for CVE. Following this being called, the CVE is fully populated and no additional
        information is required.
        :param individual_cve: The complete information directly from the JSON response for a single CVE.
                               The parameter can either be a string or a json object.
                               https://docs.python.org/3/library/json.html
        """
        # We want to be able to call the same constructor with either a string or json
        # The code bellow is what allows for this.
        cve_json = individual_cve
        if isinstance(individual_cve, str):
            cve_json = json.loads(individual_cve)
        cve_data = individual_cve


        # The data structure from NVD has "two" levels with an outer envelope containing just a 'cve' key.
        # The actual data is in the inside envelope. By doing the operation bellow, we can support both
        # data structures and make life easier, and prettier, for the calling code.
        if 'cve' in cve_json.keys():
            cve_json = cve_json['cve']
        cve_string = json.dumps(cve_json)
        self.infos = json.loads(cve_string, object_hook=lambda d: SimpleNamespace(**d))
