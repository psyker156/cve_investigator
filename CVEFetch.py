import argparse
import datetime
import json
import requests

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

    return NISTApiCall.call_nist_api(params.nistapikey, request_string, index)

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
    return_lines = []
    id = individual_cve['id']




    return return_lines

def parse_cve_results(cve_results, info_only):
    return_lines = []

    # Parse general metadata
    total_results = cve_results['totalResults']
    time_stamp = cve_results['timestamp']

    return_lines.append(f'This report was generated at {time_stamp}\n')
    return_lines.append(f'This report contains {total_results} CVEs\n\n\n')

    if info_only:
        return return_lines

    vulnerabilities = cve_results['vulnerabilities']

    for cve in vulnerabilities:
        return_lines.extend(parse_individual_cve(cve['cve']))




def parse_history_results(history_results):
    pass

if __name__ == '__main__':
    # Load local data
    fetch_cwe_info()

    # Fetch command line arguments
    params = fetch_command_line_arguments()

    # Get the data from the right source based on debug execution mode
    if params.debug:
        result = call_cve_api_debug(params)
    else:
        result = call_cve_api(params=params)

    # Parse the result
    if params.mode == 'CVE':
        parse_cve_results(result, params.info)
    else:
        parse_history_results(result)

    # Output the results
    print(result)

