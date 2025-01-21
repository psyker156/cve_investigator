"""
This file is part of the VulnerabilityManager project, a tool aimed at managing vulnerabilities
Copyright (C) 2025  Philippe Godbout
"""

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

