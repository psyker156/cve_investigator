"""
This file is part of the VulnerabilityManager project, a tool aimed at managing vulnerabilities
Copyright (C) 2025  Philippe Godbout
"""

from Tools.configuration import *

class Console:
    def __init__(self):
        self.print_welcome()

    def print_welcome(self):
        """
        This is simply meant to display a welcome message to the console and provide data
        about the release and general status of the framework.
        """
        print(f'CVE Investogator version {CVE_INVESTIGATOR_VERSION} Community Edition\n')
        print(f'Release Date: {CVE_INVESTIGATOR_RELEASE_DATE}\n')

    def load_plugins(self):
        """
        cve_investigator is a plugin based tool aimed at helping vulnerability management teams.
        As such, security teams can add plugins to extend the capabilities of this tool.
        """



if __name__ == '__main__':
    pass