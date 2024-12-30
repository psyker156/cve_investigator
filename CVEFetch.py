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

# Data output configuration
SPACER = '\n'
INDENT = '\t'

def add_indent(string_list):
    new_list = []
    for item in string_list:
        new_item = INDENT + item
        new_list.append(new_item)
    return new_list

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

def parse_source_identifier(source_identifier, cve='N/A'):
    # TODO this needs improvement for edge cases and local cache management

    return_lines = []

    source_data = {}
    if source_identifier in DATA_SOURCE_INFO:
        # We already have the info!!
        source_data = DATA_SOURCE_INFO[source_identifier]
    elif '@' in source_identifier:
        # This specific source is based on an email and not a uuid
        print(f'WARNING - email as source identifier detected for {cve} info will be incomplete')
        source_data['name'] = "N/A"
        source_data['date_first_submission'] = "N/A"
        source_data['contact_mail'] = source_identifier
    else:
        # Local source identifiers are out of date
        print('WARNING - Local source identifiers may be out of date, please update!')
        print(f'INFO - Trying to fetch source identifier from NVD for: {source_identifier}')
        source_data = NISTDataSource.call_datasource_api(source_identifier)

    data_source_name_line = f'Submitter: {source_data['name']}{SPACER}'
    return_lines.append(data_source_name_line)
    data_source_first_date_line = f'Submitter active since: {source_data["date_first_submission"]}{SPACER}'
    return_lines.append(data_source_first_date_line)
    data_source_contact_info = f'Submitter contact info: {source_data["contact_mail"]}{SPACER}'
    return_lines.append(data_source_contact_info)

    return return_lines

def parse_individual_weakness(weakness, cve='N/A'):
    return_lines = [f'Weakness info provider type: {weakness['type']}{SPACER}']
    source = weakness['source']
    return_lines.extend(parse_source_identifier(source, cve))

    descriptions = weakness['description']
    for cwe in descriptions:
        value = cwe['value']
        if 'CWE-' in value:
            cwe_number = value.split('-')[1]
            if cwe_number in CWE_INFO.keys():
                return_lines.append(f'CWE: {value} - {CWE_INFO[cwe_number]}')
            else:
                return_lines.append(f'CWE: {value}')
                print(f'WARNING - {value} not found in CWE info, local cache might be out of date')
        else:
            return_lines.append(f'CWE: Missing CWE info (parsing error or absent data)')
    return return_lines

def parse_weaknesses(weaknesses, cve='N/A'):
    return_lines = [f'Weakness informations:{SPACER}']
    for weakness in weaknesses:
        return_lines.extend(add_indent(parse_individual_weakness(weakness, cve)))
    return return_lines

def parse_source_info_for_CVSS(metric):
    return_lines = [f'CVSS info provider type: {metric['type']}{SPACER}']
    source = metric['source']
    return_lines.extend(parse_source_identifier(source))
    return return_lines

def parse_cvssMetricV40(metric):
    return_lines = [f'{SPACER}{INDENT}CVSS Metrics ({metric['cvssData']['version']}):']
    return_lines.extend(add_indent(parse_source_info_for_CVSS(metric)))
    return_lines.append(f'{INDENT}Base score: {metric["cvssData"]["baseScore"]}{SPACER}')
    return_lines.append(f'{INDENT}Attack vector: {metric["cvssData"]["attackVector"]}{SPACER}')
    return_lines.append(f'{INDENT}Exploit maturity: {metric["cvssData"]["exploitMaturity"]}{SPACER}')
    return_lines.append(f'{INDENT}Response effort: {metric["cvssData"]["vulnerabilityResponseEffort"]}{SPACER}')
    return_lines.append(f'{INDENT}Provider emergency: {metric["cvssData"]["providerUrgency"]}{SPACER}')

    return return_lines


def parse_cvssMetricV31(metric):
    return_lines = [f'{SPACER}{INDENT}CVSS Metrics ({metric['cvssData']['version']}):']
    return_lines.extend(add_indent(parse_source_info_for_CVSS(metric)))
    return_lines.append(f'{INDENT}Base score: {metric["cvssData"]["baseScore"]}{SPACER}')
    return_lines.append(f'{INDENT}Attack vector: {metric["cvssData"]["attackVector"]}{SPACER}')

    return return_lines

def parse_cvssMetricV2(metric):
    return_lines = [f'{SPACER}{INDENT}CVSS Metrics ({metric['cvssData']['version']}):']
    return_lines.extend(add_indent(parse_source_info_for_CVSS(metric)))
    return_lines.append(f'{INDENT}Base score: {metric["cvssData"]["baseScore"]}{SPACER}')
    return_lines.append(f'{INDENT}Access vector: {metric["cvssData"]["accessVector"]}{SPACER}')

    return return_lines

def parse_metrics(metrics, cve='N/A'):
    return_lines = []

    metric_parser = None
    metric_type = ''
    if 'cvssMetricV40' in metrics.keys():
        metric_parser = parse_cvssMetricV40
        metric_type = metrics['cvssMetricV40']
    elif 'cvssMetricV31' in metrics.keys():
        metric_parser = parse_cvssMetricV31
        metric_type = metrics['cvssMetricV31']
    elif 'cvssMetricV2' in metrics.keys():
        metric_parser = parse_cvssMetricV2
        metric_type = metrics['cvssMetricV2']
    elif len(metrics.keys()) != 0:
        return_lines.append(f'{SPACER}{INDENT}CVSS Metrics:Error, no parser available for {metrics.keys()}')
    else:
        return_lines.append(f'{SPACER}{INDENT}CVSS Metrics:Error, no data available?')

    if metric_parser is not None:
        for metric in metric_type:
            return_lines.extend(metric_parser(metric))

    return return_lines

def parse_description(individual_cve):
    return_lines = []

    for description in individual_cve['descriptions']:
        if 'en' in description['lang']:
            return_lines.append(f'Vulnerability description:{SPACER}')
            max_line_len = 100  # Max 100 chars
            new_line = ''
            for word in description['value'].split():
                if len(new_line) + len(word) + 1 < max_line_len:
                    new_line += word + ' '
                else:
                    return_lines.append(f'{INDENT}{new_line}{SPACER}')
                    new_line = ''
            if len(new_line) > 0:
                return_lines.append(f'{INDENT}{new_line}{SPACER}')

    return return_lines

def parse_individual_cve(individual_cve):
    return_lines = []
    cve = individual_cve['id']
    id_line = f'{cve}{SPACER}'
    return_lines.append(id_line)

    return_lines.append(f'{INDENT}CVE Submitter information:{SPACER}')
    source_identifier = individual_cve['sourceIdentifier']
    return_lines.extend(add_indent(parse_source_identifier(source_identifier, cve)))

    status_line = f'{SPACER}{INDENT}Vulnerability status: {individual_cve["vulnStatus"]}{SPACER}'
    return_lines.append(status_line)

    # TODO Impacted product information

    # CVE Description
    return_lines.append(f'{SPACER}')
    return_lines.extend(add_indent(parse_description(individual_cve)))

    # CWE using local cache in conjunction with the API data
    return_lines.append(f'{SPACER}')
    if 'weaknesses' in individual_cve.keys():
        return_lines.extend(add_indent(parse_weaknesses(individual_cve['weaknesses'], cve)))
    else:
        return_lines.append(f'{SPACER}{INDENT}Weakness information: No weakness infos for this CVE{SPACER}')

    # Getting CVSS information
    if 'metrics' in individual_cve.keys():
        return_lines.extend(add_indent(parse_metrics(individual_cve['metrics'], cve)))
    else:
        return_lines.append(f'{SPACER}{INDENT}CVSS Metrics: No metrics infos for this CVE{SPACER}')

    return_lines.append(SPACER)
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
    for line in parsed_cves:
        print(line[0:-1])
    quit()



