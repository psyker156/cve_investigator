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

from Parsers.CVSSMetricParsers.CVSSMetricV2 import CVSSMetricV2
from Parsers.CVSSMetricParsers.CVSSMetricV30 import CVSSMetricV30
from Parsers.CVSSMetricParsers.CVSSMetricV31 import CVSSMetricV31
from Parsers.CVSSMetricParsers.CVSSMetricV40 import CVSSMetricV40


def version_agnostic_cvss_parser(version, cvss_data):
    if version == 'cvssMetricV2':
        return CVSSMetricV2(cvss_data)
    elif version == 'cvssMetricV30':
        return CVSSMetricV30(cvss_data)
    elif version == 'cvssMetricV31':
        return CVSSMetricV31(cvss_data)
    elif version == 'cvssMetricV40':
        return CVSSMetricV40(cvss_data)
    else:
        raise ValueError(f'Invalid CVSS Version {version}')