"""
This file is part of the VulnerabilityManager project, a tool aimed at managing vulnerabilities
Copyright (C) 2025  Philippe Godbout
"""

class BasePlugin(object):
    """
    This class is the parent class for all plugins. A valid plugin MUST inherit from BasePlugin.
    """
    type = 'Base'   # The plugin type is used to group plugins by type, the base plugin is just an example.
    identity = 'DisplayNameOfThePlugin'
    description = 'A string giving a simple description of the plugin'


    #This part contains general configuration
    valid_plugin_types = ['command',
                          'writer']
    plugin_error_messages = {-1: "Run is not implemented"}
    identity_max_len = 15
    description_max_len = 60

    def __init__(self):
        pass

    def plugin_type(self):
        return self.type

    def set_plugin_type(self, plugin_type):
        """
        Call this to set the plugin type. Currently, the valid types are:
            -command    This is a type of plugin that provides a command line command to be executed
            -writer     This is a type of plugin that aims at writing some information somewhere
        :param plugin_type: string, the plugin type to be used
        :return:
        """
        if plugin_type not in self.valid_plugin_types:
            raise Exception(f'Invalid plugin type {plugin_type}\n')
        self.type = plugin_type

    def plugin_identity(self):
        return self.identity

    def set_plugin_identity(self, plugin_identity):
        """
        This will set the plugin identity. In order to keep things clean, only 15 chars are allowed
        :param plugin_identity: string, the plugin display name
        """
        if len(plugin_identity) > self.identity_max_len:
            raise Exception(f'Invalid plugin identity length {len(plugin_identity)} for plugin {plugin_identity}\n')
        self.identity = plugin_identity

    def plugin_description(self):
        return self.description

    def set_plugin_description(self, plugin_description):
        """
        This will provide a short description to the plugin. The description is aimed at being used on a
        command line to get general information about the plugin. The current max length is 60 chars.
        :param plugin_description:
        """
        if len(plugin_description) > self.description_max_len:
            raise Exception(f'Invalid plugin description length {len(plugin_description)} for plugin {plugin_description}\n')
        self.description = plugin_description

    def register_error_code(self, code, message):
        """
        This is to be called in order to add a new error code and message to the plugin.
        :param code: integer, the error code must be unique within a plugin
        :param message: string, the error message, cannot exceed 60 chars
        """
        if code in self.plugin_error_messages.keys():
            raise Exception(f'Can\'t register error code {code}, already registered\n')
        if len(message) > self.description_max_len:
            raise Exception(f'Error message length is too long {len(message)}\n')
        self.plugin_error_messages[code] = message

    def error_message(self, code):
        """
        This is to be called following run if run did not return 0, it will return the error message for the code.
        :param code: integer, the error code to lookup
        :return: string, the error message for the given error code
        """
        if code not in self.plugin_error_messages.keys():
            raise Exception(f'Can\'t find error code {code} in plugin {self.plugin_identity()}\n')
        return self.plugin_error_messages[code]

    def run(self, params):
        """
        This method will be called when the plugin is executed. All plugins MUST return 0 in case of success.
        Any other value need to be mapped to the plugin_error_messages dictionary so that the calling code
        can access a description of the error
        :param params: An array of strings containing the plugin parameters
        :return: All plugins MUST return 0 in case of success.
        """
        print(params)
        return -1
