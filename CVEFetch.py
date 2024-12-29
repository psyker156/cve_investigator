import argparse
import datetime
import json

import CWEDataSource
import NISTApiCall
import NISTDataSource


# CVEFetch makes use of the NIST APIs, the full documentation to these cane be found at the address bellow
# https://nvd.nist.gov/developers/vulnerabilities
# https://nvd.nist.gov/vuln/vulnerability-status#divNvdStatus
# https://nvd.nist.gov/developers/data-sources
CVE_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0?'
CVE_CHANGE_API_URL = 'https://services.nvd.nist.gov/rest/json/cvehistory/2.0?'

# The following are all constants used to locate data on the local hard drive
DEBUG_DATA_LOCATION = 'data.json'
CWE_INFO_LOCATION = 'cwe.csv'                           # The separator is a : colon

# Dict used to hold the CWE information after it is loaded
CWE_INFO = {}
DATA_SOURCE_INFO = None

def fetch_cwe_info():
    with open(CWE_INFO_LOCATION, 'r', encoding='utf-8') as f:
        data = f.readlines()

    for line in data:
        split_line = line.split(':')
        CWE_INFO[split_line[0]] = split_line[1]

def call_cve_change_api(params, index=0):
    pass

def call_cve_api(params, index=0):
    request_string = ''
    request_string += CVE_API_URL
    request_string += 'startIndex=' + str(index) + '&'
    request_string += 'pubStartDate=' + params.start + 'T00:00:00.000' + '&'
    request_string += 'pubEndDate=' + params.end + 'T23:59:59.999' + '&'
    request_string += '' + '&' if params.keyword is None else params.keyword + '&'
    request_string += '' + '&' if params.cve is None else params.cve + '&'

    return NISTApiCall.call_nist_api(params.nistapikey, request_string)

def call_cve_api_debug(params, index=0):
    with open(DEBUG_DATA_LOCATION, 'r') as f:
        data = f.read()
    return json.loads(data)

def fetch_command_line_arguments():
    parser = argparse.ArgumentParser(description='CVEFetch')
    parser.add_argument('-m', '--mode',
                        help='What mode to use? CVE|HISTORY, default CVE',
                        default='CVE')
    parser.add_argument('-s', '--start',
                        help='From date, default yesterday',
                        default=(datetime.date.today() - datetime.timedelta(days=1)).isoformat())
    parser.add_argument('-e', '--end',
                        help='To date, default today',
                        default=datetime.date.today().isoformat())
    parser.add_argument('-k', '--keyword',
                        help='Search keywords, default None',
                        default=None)
    parser.add_argument('-i', '--info',
                        help='Only return high level information (used for statistics)',
                        type=bool,
                        default=False)
    parser.add_argument('-c', '--cve',
                        help='Return information for a specific CVE',
                        default=None)
    parser.add_argument('-n', '--nistapikey',
                        help='Specifies to use a NIST API key, the key must be in key.txt under the same folder',
                        type=bool,
                        default=False)
    parser.add_argument('-d', '--debug',
                        help='Debug mode, requires a file named data.json under the same folder',
                        type=bool,
                        default=True)
    parser.parse_args(namespace=argparse.Namespace())

    args = parser.parse_args()
    return args

def parse_individual_cve(individual_cve):
    spacer = '\n'
    indent = '\t'
    return_lines = []
    id_line = f'{individual_cve['id']}{spacer}'
    return_lines.append(id_line)

    # TODO Source_identifier will need improvement, this is just to get everything working
    source_identifier = individual_cve['sourceIdentifier']
    if source_identifier in DATA_SOURCE_INFO:
        # We already have the info!!
        source_data = DATA_SOURCE_INFO[source_identifier]
        data_source_name_line = f'{indent}Submitter: {source_data['name']}{spacer}'
        return_lines.append(data_source_name_line)
        data_source_first_date_line = f'{indent}Submitter active since: {source_data["date_first_submission"]}{spacer}'
        return_lines.append(data_source_first_date_line)
        data_source_contact_info = f'{indent}Submitter contact info: {source_data["contact_mail"]}{spacer}'
    else:
        # Local source identifiers are out of date
        print('WARNING - Local source identifiers are out of date, please update!')
        print(f'INFO - Trying to fetch source identifier from NVD for: {source_identifier}')
        NISTDataSource.call_datasource_api(source_identifier)

    return_lines.append(spacer)





    return return_lines

def parse_cve_results(cve_results, info_only):
    section_change = '\n\n\n'
    return_lines = []

    # Parse general metadata
    total_results = cve_results['totalResults']
    time_stamp = cve_results['timestamp']

    return_lines.append(f'This report was generated at {time_stamp}\n')
    return_lines.append(f'This report contains {total_results} CVEs\n')
    return_lines.append(section_change)

    if info_only:
        return return_lines

    vulnerabilities = cve_results['vulnerabilities']

    for cve in vulnerabilities:
        return_lines.extend(parse_individual_cve(cve['cve']))
        return_lines.append(section_change)

    return return_lines


def parse_history_results(history_results):
    pass

if __name__ == '__main__':
    # Load local data
    CWE_INFO = CWEDataSource.fetch_cwe_info()
    DATA_SOURCE_INFO = NISTDataSource.fetch_data_source()

    # Fetch command line arguments
    params = fetch_command_line_arguments()

    # Get the data from the right source based on debug execution mode
    if params.debug:
        cves = call_cve_api_debug(params)
    else:
        cves = call_cve_api(params=params)

    parsed_cves = parse_cve_results(cves, info_only=params.info)
    print(parsed_cves)
    quit()



