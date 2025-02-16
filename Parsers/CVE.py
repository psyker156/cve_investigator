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


from Parsers.CVSSMetricParsers.helper import version_agnostic_cvss_parser

MANDATORY_CVE_FIELDS = ["id",
                        "published",
                        "lastModified",
                        "references",
                        "descriptions"]

class CVE:
    """
    This class represents a single Vulnerability presented as a python object.
    The reason for this class to exist is to avoid users having to deal directly with raw CVE data.
    This class conforms to the CVE API Schema: https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema
    """

    # Status details are available here: https://nvd.nist.gov/vuln/vulnerability-status
    VALID_CVE_STATUS = ['Received',
                        'Awaiting Analysis',
                        'Undergoing Analysis',
                        'Analyzed',
                        'Modified',
                        'Deferred',
                        'Rejected']

    def __init__(self, individual_cve):
        """
        The constructor for CVE. Following this being called, the CVE is fully populated and no additional
        information is required.
        :param individual_cve: The complete information directly from the JSON response for a single CVE.
                               The parameter can either be a string or a json object.
                               https://docs.python.org/3/library/json.html
        """
        self.infos = None
        self.cvss = []
        self.cwe = []
        self.status = 'Unknown'

        # We want to be able to call the same constructor with either a string or json
        # The code bellow is what allows for this.
        cve_json = individual_cve
        if isinstance(individual_cve, str):
            cve_json = json.loads(individual_cve)

        # The data structure from NVD has "tree" levels with an outer, a middle envelope containing just a 'cve' key.
        # The actual data is inside the middle envelope. By doing the operation bellow, we can support both
        # middle and inner data structures and make life easier, and prettier, for the calling code.
        if 'cve' in cve_json.keys():
            cve_json = cve_json['cve']

        if not self.is_cve_valid(cve_json):
            raise ValueError('ERROR - CVE missing required field')

        cve_string = json.dumps(cve_json)
        self.infos = json.loads(cve_string, object_hook=lambda d: SimpleNamespace(**d))

        # Now populate the specialized cvss information
        if 'metrics' in cve_json.keys():
            for version in cve_json['metrics'].keys():
                for cvss in cve_json['metrics'][version]:
                    self.cvss.append(version_agnostic_cvss_parser(version, cvss))
                    pass

        if 'vulnStatus' in cve_json.keys():
            self.status = cve_json['vulnStatus']

        if 'weaknesses' in cve_json.keys():
            for weakness in cve_json['weaknesses']:
                for description in weakness['description']:
                    self.cwe.append(description['value'])

    def is_cve_valid(self, cve):
        """
        This simply validates that the cve contains all the required fields
        :param cve: A JSON parsed API response.
        :return: Boolean True if valid false otherwise.
        """
        return_value = True
        keys = cve.keys()

        for mandatory_field in MANDATORY_CVE_FIELDS:
            if mandatory_field not in keys:
                return_value = False
                break
        return return_value