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

def write_to_file(filename, data, append_nl=False):
    """
    Wrapper function for a "buffer writer" based around a list where each element is a line to be written to the file
    If the passed in data is a string, the function will assume the text to be pre-formated
    :param filename: The full path of the file to write
    :param data: list, or string of lines to write
    :param append_nl: if True, each line gets a '\n' appended before being written to the file
    """
    if isinstance(data, str):
        data = [data]

    with open(filename, 'w', encoding='utf-8') as f:
        for line in data:
            if append_nl:
                line += '\n'
            f.write(line)
