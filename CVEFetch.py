import argparse
import datetime
import json
from datetime import tzinfo

import CWEDataSource
import NISTApiCall
import NISTDataSource

from CPEDecoder import *


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
SECTION_CHANGE = '\n\n'

def fetch_command_line_arguments():
    parser = argparse.ArgumentParser(description='CVEFetch')
    parser.add_argument('-m', '--mode',
                        help='What mode to use? CVE|HISTORY, default CVE',
                        default='CVE')
    parser.add_argument('-y', '--yesterday',
                        help='Get yesterday\'s cves',
                        default=True)
    parser.add_argument('-l', '--lastx',
                        help='Get cves for the last X hours',
                        type=int,
                        default=None)
    parser.add_argument('-s', '--start',
                        help='From date',
                        default=None)
    parser.add_argument('-e', '--end',
                        help='To date',
                        default=None)
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
                        default=True)
    parser.add_argument('-d', '--debug',
                        help='Debug mode, requires a file named under the same folder',
                        type=bool,
                        default=False)
    parser.add_argument('-f', '--file',
                        help='Specify a file name to be used for debug mode',
                        default=DEBUG_DATA_LOCATION)
    parser.parse_args(namespace=argparse.Namespace())

    args = parser.parse_args()
    return args

def add_indent(string_list, quantity=1):
    new_list = []
    for item in string_list:
        new_item = (INDENT * quantity) + item
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
    if params.start is not None and not params.yesterday:
        request_string += 'pubStartDate=' + params.start + 'T00:00:00.000' + '&'
    if params.end is not None and not params.yesterday:
        request_string += 'pubEndDate=' + params.end + 'T23:59:59.999' + '&'
    if params.yesterday:
        today = datetime.datetime.now(datetime.UTC).date()
        yesterday = (today - datetime.timedelta(days=1)).isoformat()
        request_string += 'pubStartDate=' + yesterday + 'T00:00:00.000' + '&'
        request_string += 'pubEndDate=' + yesterday + 'T23:59:59.999' + '&'
    if params.lastx:
        x = params.lastx
        right_now = datetime.datetime.now(datetime.UTC)
        x_hours_ago = right_now - datetime.timedelta(hours=x)
        request_string += 'pubStartDate=' + x_hours_ago.isoformat(timespec='seconds').split('+')[0] + '&'
        request_string += 'pubEndDate=' + right_now.isoformat(timespec='seconds').split('+')[0] + '&'
    request_string += '' if params.keyword is None else 'keywordSearch=' + params.keyword + '&'
    request_string += '' if params.cve is None else 'cveId=' + params.cve + '&'

    return NISTApiCall.call_nist_api(params.nistapikey, request_string)

def call_cve_api_debug(params, index=0):
    with open(DEBUG_DATA_LOCATION, 'r') as f:
        data = f.read()
    return json.loads(data)

def parse_source_identifier(source_identifier, cve='N/A'):
    # TODO this needs improvement for edge cases and local cache management

    return_lines = []

    source_data = {}
    if source_identifier in DATA_SOURCE_INFO:
        # We already have the info!!
        source_data = DATA_SOURCE_INFO[source_identifier]
    elif '@' in source_identifier:
        # This specific source is based on an email and not a uuid
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
                # Some CVE reports contain the following instead of nothing...
                if value != 'NVD-CWE-Other' and value != 'NVD-CWE-noinfo':
                    print(f'WARNING - \'{value}\' not found in CWE info, local cache might be out of date')
                return_lines.append(f'CWE: {value}')

        else:
            return_lines.append(f'CWE: Missing CWE info (parsing error or absent data)')
    return return_lines

def parse_weaknesses(weaknesses, cve='N/A'):
    return_lines = [f'Weakness infos:{SPACER}']
    for weakness in weaknesses:
        return_lines.extend(add_indent(parse_individual_weakness(weakness, cve)))
    return return_lines

def parse_source_info_for_CVSS(metric):
    return_lines = [f'CVSS info provider type: {metric['type']}{SPACER}']
    source = metric['source']
    return_lines.extend(parse_source_identifier(source))
    return return_lines

def parse_cvssMetricV40(metric):
    return_lines = [f'{SPACER}{INDENT}CVSS Metrics ({metric['cvssData']['version']}):{SPACER}']
    return_lines.extend(add_indent(parse_source_info_for_CVSS(metric)))
    return_lines.append(f'{INDENT}Base score: {metric["cvssData"]["baseScore"]}{SPACER}')
    return_lines.append(f'{INDENT}Attack vector: {metric["cvssData"]["attackVector"]}{SPACER}')
    return_lines.append(f'{INDENT}Exploit maturity: {metric["cvssData"]["exploitMaturity"]}{SPACER}')
    return_lines.append(f'{INDENT}Response effort: {metric["cvssData"]["vulnerabilityResponseEffort"]}{SPACER}')
    return_lines.append(f'{INDENT}Provider emergency: {metric["cvssData"]["providerUrgency"]}{SPACER}')

    return return_lines

def parse_cvssMetricV31(metric):
    return_lines = [f'{SPACER}{INDENT}CVSS Metrics ({metric['cvssData']['version']}):{SPACER}']
    return_lines.extend(add_indent(parse_source_info_for_CVSS(metric)))
    return_lines.append(f'{INDENT}Base score: {metric["cvssData"]["baseScore"]}{SPACER}')
    return_lines.append(f'{INDENT}Attack vector: {metric["cvssData"]["attackVector"]}{SPACER}')

    return return_lines

def parse_cvssMetricV30(metric):
    return_lines = [f'{SPACER}{INDENT}CVSS Metrics ({metric['cvssData']['version']}):{SPACER}']
    return_lines.extend(add_indent(parse_source_info_for_CVSS(metric)))
    return_lines.append(f'{INDENT}Base score: {metric["cvssData"]["baseScore"]}{SPACER}')
    return_lines.append(f'{INDENT}Attack vector: {metric["cvssData"]["attackVector"]}{SPACER}')

    return return_lines

def parse_cvssMetricV2(metric):
    return_lines = [f'{SPACER}{INDENT}CVSS Metrics ({metric['cvssData']['version']}):{SPACER}']
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
    elif 'cvssMetricV30' in metrics.keys():
        metric_parser = parse_cvssMetricV30
        metric_type = metrics['cvssMetricV30']
    elif 'cvssMetricV2' in metrics.keys():
        metric_parser = parse_cvssMetricV2
        metric_type = metrics['cvssMetricV2']
    elif len(metrics.keys()) != 0:
        return_lines.append(f'{SPACER}{INDENT}CVSS Metrics:Error, no parser available for {metrics.keys()}{SPACER}')
    else:
        return_lines.append(f'{SPACER}{INDENT}CVSS Metrics: Metric present but no data for it{SPACER}')

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
                if len(new_line) + len(word) < max_line_len:
                    new_line += word + ' '
                else:
                    return_lines.append(f'{INDENT}{new_line}{SPACER}')
                    new_line = word + ' '
            if len(new_line) > 0:
                return_lines.append(f'{INDENT}{new_line}{SPACER}')

    return return_lines

def parse_tags(individual_cve):
    return_lines = []
    tags = individual_cve['cveTags']
    for tag_details in tags:
        for tag in tag_details['tags']:
            return_lines.append(f'Tags:{tag} {INDENT} Source: {tag_details["sourceIdentifier"]}{SPACER}')
    return return_lines

def parse_configurations(individual_cve):
    return_lines = []
    app_lines = []
    os_lines = []
    hw_lines = []
    configurations = individual_cve['configurations']
    for items in configurations:
        for nodes in items['nodes']:
            for cpe_match in nodes['cpeMatch']:
                parsed_cpe = parse_cpe(cpe_match['criteria'])
                part = ''
                part = 'APPLICATION' if parsed_cpe['part'] == CPE_PART_APPLICATION else part
                part = 'OPERATING SYSTEM' if parsed_cpe['part'] == CPE_PART_OS else part
                part = 'HARDWARE' if parsed_cpe['part'] == CPE_PART_HARDWARE else part

                lines = None
                if part == 'APPLICATION':
                    lines = app_lines
                elif part == 'OPERATING SYSTEM':
                    lines = os_lines
                elif part == 'HARDWARE':
                    lines = hw_lines

                lines.append(f'{part} - '
                             f'Provider : {parsed_cpe['vendor']} - '
                             f'System : {parsed_cpe['version']} - {SPACER}')

    # We want to print in the following order: Application - Operating Systems - Hardware
    return_lines.extend(app_lines)
    return_lines.extend(os_lines)
    return_lines.extend(hw_lines)

    return return_lines

def parse_individual_cve(individual_cve):
    return_lines = []
    cve = individual_cve['id']
    return_lines.append(f'{cve}{SPACER}')

    published_date = individual_cve['published']
    return_lines.append(f'{INDENT}Published date : {published_date}{SPACER}')

    modified_date = individual_cve['lastModified']
    return_lines.append(f'{INDENT}Last modified date : {modified_date}{SPACER}')

    return_lines.append(SPACER)

    return_lines.append(f'{INDENT}CVE Submitter information:{SPACER}')
    source_identifier = individual_cve['sourceIdentifier']
    return_lines.extend(add_indent(parse_source_identifier(source_identifier, cve), quantity=2))

    return_lines.append(f'{SPACER}')
    status_line = f'{INDENT}Vulnerability status: {individual_cve["vulnStatus"]}{SPACER}'
    return_lines.append(status_line)

    if 'cveTags' in individual_cve.keys() and len(individual_cve['cveTags']) > 0:
        return_lines.append(f'{SPACER}')
        return_lines.append(f'{INDENT}Vulnerability tags:{SPACER}')
        return_lines.extend(add_indent(parse_tags(individual_cve), quantity=2))
    else:
        return_lines.append(f'{SPACER}{INDENT}Vulnerability tags: No tags infos for this CVE{SPACER}')

    if 'configurations' in individual_cve.keys() and len(individual_cve['configurations']) > 0:
        return_lines.append(f'{SPACER}')
        return_lines.append(f'{INDENT}Vulnerable configuration:{SPACER}')
        return_lines.extend(add_indent(parse_configurations(individual_cve), quantity=2))
    else:
        return_lines.append(f'{SPACER}{INDENT}Vulnerability configuration: No configuration infos for this CVE{SPACER}')

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
    return_lines = []

    # Parse general metadata
    total_results = cve_results['totalResults']
    time_stamp = cve_results['timestamp']

    return_lines.append(f'This report was generated at {time_stamp}\n')
    return_lines.append(f'This report contains {total_results} CVEs\n')
    return_lines.append(SECTION_CHANGE)

    if info_only:
        return return_lines

    vulnerabilities = cve_results['vulnerabilities']

    for cve in vulnerabilities:
        return_lines.extend(parse_individual_cve(cve['cve']))
        return_lines.append(SECTION_CHANGE)

    return return_lines


def parse_history_results(history_results):
    pass

def write_to_file(data):
    with open(f'{datetime.date.today().isoformat()}.txt', 'w', encoding='utf-8') as file:
        for line in data:
            file.write(line)

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
    write_to_file(parsed_cves)



