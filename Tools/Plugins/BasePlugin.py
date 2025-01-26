"""
This file is part of the VulnerabilityManager project, a tool aimed at managing vulnerabilities
Copyright (C) 2025  Philippe Godbout
"""



class BasePlugin(object):
    """
    This class is the parent class for all plugins. A valid plugin MUST inherit from BasePlugin.
    """

    ITERATION = 1   # This number is to be incremented each time base plugin mandatory
                    # implementation changes.

    # This first part is the plugin help menu, this must be set
    _help_string = ''

    # This is general plugin bookkeeping
    _type = 'Base'   # The plugin type is used to group plugins by type, the base plugin is just an example.
    _identity = 'DisplayNameOfThePlugin'
    _description = 'A string giving a simple description of the plugin'


    # This part contains general configuration
    _valid_plugin_types = ['command',
                           'writer']
    RUN_SUCCESS = 0
    RUN_NOT_IMPLEMENTED = -1000

    _identity_max_len = 15
    _description_max_len = 60


    def __init__(self):
        self._plugin_error_messages = {BasePlugin.RUN_NOT_IMPLEMENTED: "Run is not implemented"}


    def plugin_type(self):
        return self._type


    def set_plugin_type(self, plugin_type):
        """
        Call this to set the plugin type. Currently, the valid types are:
            -command    This is a type of plugin that provides a command line command to be executed
            -writer     This is a type of plugin that aims at writing some information somewhere
        :param plugin_type: string, the plugin type to be used
        :return:
        """
        if plugin_type not in self._valid_plugin_types:
            raise Exception(f'Invalid plugin type {plugin_type}\n')
        self._type = plugin_type


    def plugin_identity(self):
        return self._identity


    def set_plugin_identity(self, plugin_identity):
        """
        This will set the plugin identity. In order to keep things clean, only 15 chars are allowed
        :param plugin_identity: string, the plugin display name
        """
        if len(plugin_identity) > self._identity_max_len:
            raise Exception(f'Invalid plugin identity length {len(plugin_identity)} for plugin {plugin_identity}\n')
        self._identity = plugin_identity


    def plugin_description(self):
        return self._description


    def set_plugin_description(self, plugin_description):
        """
        This will provide a short description to the plugin. The description is aimed at being used on a
        command line to get general information about the plugin. The current max length is 60 chars.
        :param plugin_description:
        """
        if len(plugin_description) > self._description_max_len:
            raise Exception(f'Invalid plugin description length {len(plugin_description)} for plugin {plugin_description}\n')
        self._description = plugin_description


    def register_error_code(self, code, message):
        """
        This is to be called in order to add a new error code and message to the plugin.
        :param code: integer, the error code must be unique within a plugin
        :param message: string, the error message, cannot exceed 60 chars
        """
        if code in self._plugin_error_messages.keys():
            raise Exception(f'Can\'t register error code {code}, already registered\n')
        if len(message) > self._description_max_len:
            raise Exception(f'Error message length is too long {len(message)}\n')
        self._plugin_error_messages[code] = message


    def error_message(self, code):
        """
        This is to be called following run if run did not return 0, it will return the error message for the code.
        :param code: integer, the error code to lookup
        :return: string, the error message for the given error code
        """
        if code not in self._plugin_error_messages.keys():
            raise Exception(f'Can\'t find error code {code} in plugin {self.plugin_identity()}\n')
        return self._plugin_error_messages[code]


    def help(self):
        """
        This is called to access the help for a given plugin. All the user facing documentation is returned.
        :return: string, a formated string of help text
        """
        return self._help_string


    def set_help(self, new_help_string):
        """
        This is used to set the help string. Properly formating the help string is the plugin responsibility.
        :param new_help_string: string, a formated string of help text
        """
        if type(new_help_string) != str:
            raise Exception(f'Invalid help string {type(new_help_string)}, must be string\n')
        self._help_string = new_help_string


    def self_validate(self):
        """
        This method makes sure that the kid plugin matches the base plugin!
        """
        if BasePlugin.ITERATION != self.ITERATION:
            raise EnvironmentError('Plugin iteration does not match base plugin iteration\n')

        if BasePlugin.run == self.run:
            raise EnvironmentError('Plugin run is not implemented\n')

        if BasePlugin.validate_command == self.validate_command:
            raise EnvironmentError('Plugin validate_command() is not implemented\n')

        if BasePlugin._identity == self._identity:
            raise EnvironmentError('Plugin identity is not set\n')

        if BasePlugin._description == self._description:
            raise EnvironmentError('Plugin identity is not set\n')

        if BasePlugin._type == self._type:
            raise EnvironmentError('Plugin type is not set\n')

        if BasePlugin._help_string == self._help_string:
            raise EnvironmentError('Plugin help is not set\n')

        print(f'Plugin \'{self.plugin_identity()}\' is valid and ready to be used.\n')


    def validate_command(self, args):
        """
        This is a localized command parser that every plugin must implement.
        :param args: a list of commands including the command name
        :return: boolean, True if the command is valid, False otherwise
        """
        pass
        return True


    def run(self, params=None):
        """
        This method will be called when the plugin is executed. All plugins MUST return 0 in case of success.
        Any other value need to be mapped to the plugin_error_messages dictionary so that the calling code
        can access a description of the error
        :param params: An array of strings containing the plugin parameters
        :return: All plugins MUST return 0 in case of success.
        """
        print(params)
        return self.RUN_NOT_IMPLEMENTED
