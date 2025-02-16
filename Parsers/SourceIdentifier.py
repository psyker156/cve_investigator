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

from NetworkServices.NISTAPIServices import call_source_api
from Writers.FileWriter import write_to_file

# NISTDataSource makes use of the NIST APIs, the full documentation to these can be found at the address bellow
# https://nvd.nist.gov/developers/data-sources
NIST_DATA_SOURCE_API_URL = 'https://services.nvd.nist.gov/rest/json/source/2.0?'

# The following are all constants used to locate data on the local hard drive
DATA_SOURCE_LOCAL_CACHE_LOCATION = 'data_source.csv'
SEPARATOR = ';'


class SourceIdentifier:
    """
    This class represents a single data-source presented as a python object.
    The reason for this class to exist is to avoid users having to deal directly with raw data.
    This class conforms to the Source API Schema: https://nvd.nist.gov/developers/data-sources
    """

    infos = None
    data_source = None

    def __init__(self, use_api_key=False, networked=False):
        """
        The constructor for SourceIdentifier.
        """
        if networked:
            self.update_datasource_local_cache(use_api_key)
        self.fetch_data_source_data()

    def get_source_identifier(self, data_source_string):
        """
        This is the method that the end user needs to call to get the data source identifier informations
        :param data_source_string: string, a UUID style identifier for a specific data source.
        :return: dict, {'name': name, 'date_first_submission': date_first_submission, 'contact_mail': contact_mail}
                 None if information is not available
        """
        return_value = None
        if data_source_string in self.data_source.keys():
            return_value = self.data_source[data_source_string]
        return return_value

    def parse_single_source(self, single_source):
        name = single_source['name'].replace(';', '')
        created = single_source['created'].replace(';', '')
        id = ''
        emails = ''

        for identifier in single_source['sourceIdentifiers']:
            if '@' in identifier:
                emails += f'{identifier}, '.replace(';', '')
            else:
                id += identifier.replace(';', '')

        return {'id': id, 'name': name, 'created': created, 'emails': emails}

    def update_datasource_local_cache(self, use_api_key=False):
        data = call_source_api(use_api_key)

        sources = data['sources']
        parsed_sources = []

        for single_source in sources:
            parsed_source = self.parse_single_source(single_source)
            data_line = (f'{parsed_source['id']};'
                         f'{parsed_source['name']};'
                         f'{parsed_source['created']};'
                         f'{parsed_source['emails']}')
            parsed_sources.append(data_line)

        write_to_file(DATA_SOURCE_LOCAL_CACHE_LOCATION, parsed_sources, append_nl=True)

    def fetch_data_source_data(self):
        with open(DATA_SOURCE_LOCAL_CACHE_LOCATION, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        self.data_source = {}

        for line in lines:
            split_line = line.strip().split(sep=SEPARATOR)
            s_id = split_line[0]
            name = split_line[1]
            date_first_submission = split_line[2]
            contact_mail = split_line[3]
            self.data_source[s_id] = {'name': name,
                                      'date_first_submission': date_first_submission,
                                      'contact_mail': contact_mail}
