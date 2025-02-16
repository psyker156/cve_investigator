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
from types import SimpleNamespace

MANDATORY_CVSS_FIELDS = ["source",
                         "type",
                         "cvssData"]

class CVSSMetricV31:
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

        if 'cvssMetricV31' in cvss_json.keys():
            cvss_json = cvss_json['cvssMetricV31'][0]

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
        if 'attackVector' in cvss.keys():
            self.attack_vector = cvss['attackVector']
