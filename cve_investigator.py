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

import Tools.Console
import Tools.Plugins.PluginManager

if __name__ == "__main__":
    print('Initializing cve_investigator')
    print('Loading plugins...')
    pm = Tools.Plugins.PluginManager.PluginManager()
    print('All plugins loaded.')
    print('Initializing cve_investigator console...')
    print('\n')
    cs = Tools.Console.Console(plugin_manager=pm)
    pm.plugins['info'].run(['info'])    # We need to fake a command line here
    print('\n')
    print('Console initialized.')
    print('\n')
    cs.run_console()        # From here, Console controls the execution of cve_investigator
    print('cve_investigator has terminated.')

