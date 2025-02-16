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

from Tools.Plugins.PluginManager import PluginManager
from Tools.Plugins.BasePlugin import BasePlugin

class Console:

    builtins_command = {'exit': 'Running this will terminate cve_investigator',
                        'help': 'Running this will display all available commands',
                        'set_context': 'Run #context prefix suffix to add these to your commands',
                        'unset_context': 'Removes a previously set context'}

    def __init__(self, plugin_manager: PluginManager):
        self.pm = plugin_manager
        self.context_prefix = ''
        self.context_suffix = ''
        self.context = self.context_prefix + ' ' + self.context_suffix


    def run_console(self):
        print('Console is running...')
        while True:
            # Get the command
            command = self.acquire_command()
            if len(command) == 0:
                continue
            parsed_command = [command]
            if command != 'unset_context':      # unset_context needs a special treatment... TODO review this
                parsed_command = self.parse_command(command)
            command_name = parsed_command[0]

            if self.run_built_in_commands(parsed_command):
                continue    # The command was an internal command, we need a new one!

            # Validate the command
            if command_name not in self.pm.plugins:
                self.invalid_command(command_name)
                continue
            try:
                result = self.pm.plugins[command_name].run(parsed_command)
                if result != BasePlugin.RUN_SUCCESS:
                    print(self.pm.plugins[command_name].error_message(result))
            except BaseException as e:
                print(e)

        print('')
        print('Closing Console...')


    def acquire_command(self):
        try:
            return input(f'{self.context}# ')
        except:
            quit()

    def parse_command(self, command):
        parsed = command.split()
        if len(self.context_prefix) > 0:
            parsed = [self.context_prefix] + parsed + [self.context_suffix]
        return parsed

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
        if len(params) == 1:
            print('Available commands:')
            print('\tBuilt-in commands:')
            for command in self.builtins_command.keys():
                print(f'\t\t{command} : {self.builtins_command[command]}')
            print()
            print('\tPlugins commands:')
            for command in self.pm.plugins.keys():
                print(f'\t\t{command} : {self.pm.plugins[command].plugin_description()}')
            print()
        elif len(params) == 2:
            help_for = params[1]
            if help_for in self.pm.plugins.keys():
                print(self.pm.plugins[help_for].INFO_HELP_STRING)
            else:
                print(f'Command not found: {help_for}')


    def exit(self, params):
        quit()


    def set_context(self, params):
        self.context_prefix = params[1]
        if len(params) > 2:
            self.context_suffix = params[2]
        self.context = self.context_prefix + ' ' + self.context_suffix


    def unset_context(self, params):
        self.context_prefix = ''
        self.context_suffix = ''
        self.context = self.context_prefix + ' ' + self.context_suffix


if __name__ == '__main__':
    pass