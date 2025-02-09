"""
This file is part of the VulnerabilityManager project, a tool aimed at managing vulnerabilities
Copyright (C) 2025  Philippe Godbout
"""

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