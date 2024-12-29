# The following are all constants used to locate data on the local hard drive
CWE_INFO_LOCATION = 'cwe.csv'                           # The separator is a : colon

# Dict used to hold the CWE information after it is loaded
CWE_INFO = {}

def fetch_cwe_info():
    cwe_info = {}
    with open(CWE_INFO_LOCATION, 'r', encoding='utf-8') as f:
        data = f.readlines()

    for line in data:
        split_line = line.split(':')
        cwe_info[split_line[0]] = split_line[1]

    return cwe_info




if __name__ == '__main__':
    pass

