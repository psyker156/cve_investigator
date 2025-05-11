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


class KEV:
    """
    This class represents a single KEV object as described in the CISA kev json file format
    """

    def __init__(self, json_raw_kev):
        """
        The constructor for a kev.
        """
        self.info = json_raw_kev
        self.cve_number = json_raw_kev['cveID']
        self.date_added = json_raw_kev['dateAdded']
        self.due_date = json_raw_kev['dueDate']
        self.known_ransomware_campaign_use = json_raw_kev['knownRansomwareCampaignUse']
        self.notes = json_raw_kev['notes']
        self.vendor_project = json_raw_kev['vendorProject']
        self.vulnerability_name = json_raw_kev['vulnerabilityName']
        self.product = json_raw_kev['product']
        self.required_action = json_raw_kev['requiredAction']
        self.short_description = json_raw_kev['shortDescription']

