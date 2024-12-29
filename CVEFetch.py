import argparse
import datetime
import json
import requests


# CVEFetch makes use of the NIST APIs, the full documentation to these cane be found at the address bellow
# https://nvd.nist.gov/developers/vulnerabilities
CVE_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0?'
CVE_CHANGE_API_URL = 'https://services.nvd.nist.gov/rest/json/cvehistory/2.0?'

API_KEY_LOCATION = 'key.txt'
DEBUG_DATA_LOCATION = 'data.json'

def fetch_api_key():
    with open(API_KEY_LOCATION, 'r') as f:
        data = f.readline()
    return data


def call_api(params, index=0):
    api_key = ''
    if params.nistapikey:
        api_key += fetch_api_key()

    request_string = ''
    if params.mode == 'CVE':
        request_string += CVE_API_URL
        request_string += 'startIndex=' + str(index) + '&'
        request_string += 'pubStartDate=' + params.start + 'T00:00:00.000' + '&'
        request_string += 'pubEndDate=' + params.end + 'T23:59:59.999' + '&'
        request_string += '' if params.keyword is None else params.keyword
    else:
        request_string += CVE_CHANGE_API_URL

    request_string += '' if params.cve is None else params.cve

    response = requests.get(request_string)
    return json.loads(response.text)

def call_api_debug(params, index=0):
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
        return_lines.extend(parse_individual_cve(cve))




def parse_history_results(history_results):
    pass

if __name__ == '__main__':
    # Fetch command line arguments
    params = fetch_command_line_arguments()

    # Get the data from the right source based on debug execution mode
    if params.debug:
        result = call_api_debug(params)
    else:
        result = call_api(params=params)

    # Parse the result
    if params.mode == 'CVE':
        parse_cve_results(result, params.info)
    else:
        parse_history_results(result)

    # Output the results
    print(result)

