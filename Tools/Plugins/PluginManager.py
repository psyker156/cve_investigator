"""
This file is part of the VulnerabilityManager project, a tool aimed at managing vulnerabilities
Copyright (C) 2025  Philippe Godbout
"""

import importlib
import os

PLUGINS_DIRECTORY = os.path.dirname(__file__) + 'Plugins'

class PluginManager(object):
    """
    All plugins are loaded, unloaded and accessed through the plugin manager. In many
    ways, this should be seen as the cve_investigator's core.
    """

    plugins = []

    def __init__(self):
        pass

    def load_all_plugins(self):
        pass

    def load_plugin(self, plugin_name):
        pass

    def unload_plugin(self, plugin_name):
        pass

    def validate_plugin(self, plugin_name):
        pass
