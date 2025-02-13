"""
This file is part of the VulnerabilityManager project, a tool aimed at managing vulnerabilities
Copyright (C) 2025  Philippe Godbout
"""

from Tools.Plugins.BasePlugin import *

import importlib
import os
import sys

PLUGINS_DIRECTORY = os.path.dirname(__file__) + os.path.sep + 'Plugins'


class PluginManager(object):
    """
    All plugins are loaded, unloaded and accessed through the plugin manager. In many
    ways, this should be seen as the cve_investigator's core.
    """

    ITERATION = 1   # This number is to be incremented each time base plugin mandatory
                    # implementation changes.

    plugins = {}    # A dict of plugin such as {'pluginA_Identity': pluginObject, ...}


    def __init__(self):
        self.LOCAL_CACHE = {}
        self.load_all_plugins()

        # After loading the plugins, they need to be validated to prevent runtime malfunction!
        for plugin in self.plugins.keys():
            self.validate_plugin(plugin)


    def validate_base_plugin_iteration_match(self):
        """
        This is a helper method aimed at making sure that the plugin manager implementation matches
        the version of the base plugin.
        Although this really is just a "dummy check" the hope is that it will help limit
        problems with synchronisation (programmer forgetting something in the mandatory implementation)
        """
        if BasePlugin.ITERATION != self.ITERATION:
            raise EnvironmentError('Base plugin iteration does not match plugin manager iteration\n')


    def load_all_plugins(self):
        """
        This will go through all the plugins found in PLUGINS_DIRECTORY and load them so they are ready to be used
        """
        sys.path.insert(0, PLUGINS_DIRECTORY)        # This allows the interpreter to find our plugins dir

        dir_listing = os.listdir(PLUGINS_DIRECTORY)

        if '__pycache__' in dir_listing:
            dir_listing.remove('__pycache__')

        print(f'Loading {len(dir_listing)} plugins from {PLUGINS_DIRECTORY}')

        for filename in dir_listing:
            if filename.endswith('.py'):
                self.load_plugin(filename[:-3])             # This has to be a module name, not a file name!

        sys.path.remove(PLUGINS_DIRECTORY)                  # Once no longer required we remove it!


    def load_plugin(self, plugin_name):
        """
        This will load a plugin file. After being loaded, the plugin will be available from the plugins dictionary
        :param plugin_name: string, the name of the plugin file needing to be loaded
        """
        module = importlib.import_module(plugin_name)

        # A module main class need to bear the same name as the module name
        if not hasattr(module, module.__name__):
            raise EnvironmentError(f'Plugin {module.__name__} can\'t be loaded missing plugin implementation\n')

        # We only need an object for the module nothing more, these should all be self-contained
        single_plugin_main_class = getattr(module, module.__name__)
        single_plugin = single_plugin_main_class(self.LOCAL_CACHE)      # create an instance of the plugin

        # From here the plugin is available to the plugin manager
        self.plugins[single_plugin.plugin_identity()] = single_plugin


    def unload_plugin(self, plugin_name):
        """
        This will remove a loaded plugin, following the plugin removal, it will not be available to be called
        :param plugin_name: string, the plugin identity
        """
        del self.plugins[plugin_name]


    def validate_plugin(self, plugin_name):
        """
        This method will go through a plugin and validate that the plugin is ready to be used and fully implemented.
        See BasePlugin for the details as to what is required.
        :param plugin_name:
        :return:
        """
        plugin = self.plugins[plugin_name]
        plugin.self_validate()


if __name__ == '__main__':
    manager = PluginManager()