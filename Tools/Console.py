"""
This file is part of the VulnerabilityManager project, a tool aimed at managing vulnerabilities
Copyright (C) 2025  Philippe Godbout
"""

from Tools.Plugins.PluginManager import PluginManager

class Console:

    builtins_command = {'exit': 'Running this will terminate cve_investigator',
                        'help': 'Running this will display all available commands'}

    pm = None
    context = ''

    def __init__(self, plugin_manager: PluginManager):
        self.pm = plugin_manager


    def run_console(self):
        print('Console is running...')

        while True:
            # Get the command
            command = self.acquire_command()
            parsed_command = self.parse_command(command)
            command_name = parsed_command[0]

            if self.run_built_in_commands(parsed_command):
                continue    # The command was an internal command, we need a new one!

            # Validate the command
            if command_name not in self.pm.plugins:
                self.invalid_command(command_name)
                continue

            if not self.pm.plugins[command_name].validate_command(parsed_command):
                self.invalid_command(command_name)
                continue

            self.pm.plugins[command_name].run(parsed_command)

        print('')
        print('Closing Console...')


    def acquire_command(self):
        return input(f'{self.context}# ')

    def parse_command(self, command):
        return command.split()

    def invalid_command(self, command_name):
        print(f'Command not found: {command_name}')

    def run_built_in_commands(self, params):
        """
        The console requires a set of "basic commands". This method checks if a command
        is a built_in command. If it is, the command will be executed. Otherwise, This will
        return False indicating that the command is not internal and needs to be managed through
        the PluginManager.
        :return: boolean, True if the command is an internal command and ran successfully
        """
        built_in = False
        if params[0] in self.builtins_command:
            built_in = True     # This is a builtin command!
            if hasattr(self, params[0]):
                getattr(self, params[0])(params)
            else:
                print(f'Built-in command: {params[0]} not implemented.')
        return built_in

    #
    # EVERYTHING THAT FOLLOWS IS FOR BUILT-IN COMMANDS IMPLEMENTATION
    #
    def help(self, params):
        print('Available commands:')
        print('\tBuilt-in commands:')
        for command in self.builtins_command.keys():
            print(f'\t\t{command} : {self.builtins_command[command]}')
        print()
        print('\tPlugins commands:')
        for command in self.pm.plugins.keys():
            print(f'\t\t{command} : {self.pm.plugins[command].plugin_description()}')
        print()


    def exit(self, params):
        quit()


if __name__ == '__main__':
    pass