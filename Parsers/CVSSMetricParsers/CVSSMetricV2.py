"""
This file is part of the VulnerabilityManager project, a tool aimed at managing vulnerabilities
Copyright (C) 2025  Philippe Godbout
"""

import json
from types import SimpleNamespace

MANDATORY_CVSS_FIELDS = ["source",
                         "type",
                         "cvssData"]

class CVSSMetricV2:
    """
    This class represents a single CVSS score presented as a python object.
    The reason for this class to exist is to avoid users having to deal directly with raw CVE data.
    This class conforms to the CVE API Schema: https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema
    """

    def __init__(self, individual_cvss):
        """
        The constructor for CVSS. Following this being called, the CVSS is fully populated and no additional
        information is required.
        :param individual_cvss: The complete information directly from the JSON response for a single CVSS.
                               The parameter can either be a string or a json object.
                               https://docs.python.org/3/library/json.html
        """

        self.infos = None
        self.source = None
        self.type = None
        self.version = None
        self.base_score = None
        self.attack_vector = None

        # We want to be able to call the same constructor with either a string or json
        # The code bellow is what allows for this.
        cvss_json = individual_cvss
        if isinstance(individual_cvss, str):
            cvss_json = json.loads(individual_cvss)

        if 'cvssMetricV2' in cvss_json.keys():
            cvss_json = cvss_json['cvssMetricV2'][0]



        if not self.is_cvss_valid(cvss_json):
            raise ValueError('ERROR - CVSS missing required field')

        cvss_string = json.dumps(cvss_json)
        self.infos = json.loads(cvss_string, object_hook=lambda d: SimpleNamespace(**d))
        self.type = cvss_json['type']
        self.source = cvss_json['source']
        self.parse_inner_cvss(cvss_json['cvssData'])

    def is_cvss_valid(self, cvss):
        """
        This simply validates that the cvss contains all the required fields
        :param cvss: A single CVSS in json format
        :return: Boolean True if valid false otherwise.
        """
        return_value = True
        keys = cvss.keys()

        for mandatory_field in MANDATORY_CVSS_FIELDS:
            if mandatory_field not in keys:
                return_value = False
                break

        return return_value

    def parse_inner_cvss(self, cvss):
        """
        This simply parses the inner fields that we want to keep
        :param cvss: json object of the CVSS
        """
        if 'version' in cvss.keys():
            self.version = cvss['version']
        if 'baseScore' in cvss.keys():
            self.base_score = cvss['baseScore']
        if 'accessVector' in cvss.keys():
            self.attack_vector = cvss['accessVector']