import argparse
import datetime
import requests
import urllib


# CVEFetch makes use of the NIST APIs, the full documentation to these cane be found at the address bellow
# https://nvd.nist.gov/developers/vulnerabilities
CVE_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0?'
CVE_CHANGE_API_URL = 'https://services.nvd.nist.gov/rest/json/cvehistory/2.0?'

API_KEY_LOCATION = 'key.txt'

def fetch_api_key():
    with open(API_KEY_LOCATION, 'r') as f:
        data = f.readlines()
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
    return response.json()

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
    parser.add_argument('-h', '--high',
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
    parser.parse_args(namespace=argparse.Namespace())

    args = parser.parse_args()
    return args

if __name__ == '__main__':
    # Fetch command line arguments
    params = fetch_command_line_arguments()
    # Call proper API based on the arguments
    result = call_api(params=params)
    # Output result to txt file
    print(result)

