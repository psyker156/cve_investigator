import json
import requests

import NISTApiCall


# NISTDataSource makes use of the NIST APIs, the full documentation to these cane be found at the address bellow
# https://nvd.nist.gov/developers/data-sources
NIST_DATA_SOURCE_API_URL = 'https://services.nvd.nist.gov/rest/json/source/2.0?'

# The following are all constants used to locate data on the local hard drive
DATA_SOURCE_LOCAL_CACHE_LOCATION = 'data_source.csv'    # The separator is a ; semi-colon
SEPARATOR = ';'

def fetch_data_source():
    with open(DATA_SOURCE_LOCAL_CACHE_LOCATION, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    result_dict = {}

    for line in lines:
        split_line = line.strip().split(sep=SEPARATOR)
        id = split_line[0]
        name = split_line[1]
        date_first_submission = split_line[2]
        contact_mail = split_line[3]
        result_dict[id] = {'name': name,
                           'date_first_submission': date_first_submission,
                           'contact_mail': contact_mail}
    return result_dict


def update_datasource_local_cache(use_api_key):
    request_string = ''
    request_string += NIST_DATA_SOURCE_API_URL
    data = NISTApiCall.call_nist_api(use_api_key, request_string)

    print(f'Data source contains {data['totalResults']} sources')

    sources = data['sources']
    parsed_sources = []

    for single_source in sources:
        name = single_source['name'].replace(';', '')
        created = single_source['created'].replace(';', '')
        id = ''
        emails = ''

        for identifier in single_source['sourceIdentifiers']:
            if '@' in identifier:
                emails += f'{identifier}, '.replace(';', '')
            else:
                id += identifier.replace(';', '')
        data_line = f'{id};{name};{created};{emails}'
        parsed_sources.append(data_line)

    with open(DATA_SOURCE_LOCAL_CACHE_LOCATION, 'w', encoding='utf-8') as f:
        for source in parsed_sources:
            f.write(source + '\n')

    print('Data source local cache has been updated')

def call_datasource_api(datasource, use_api_key=False):
    request_string = ''
    request_string += NIST_DATA_SOURCE_API_URL
    request_string += 'sourceIdentifier=' + str(datasource) + '&'
    NISTApiCall.call_nist_api(use_api_key, request_string)

if __name__ == '__main__':
    update_datasource_local_cache()

