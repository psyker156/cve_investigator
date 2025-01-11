"""
This file is part of the VulnerabilityManager project, a tool aimed at managing vulnerabilities
Copyright (C) 2025  Philippe Godbout
"""

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
