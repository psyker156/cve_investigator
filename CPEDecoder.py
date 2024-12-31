# CPEs are described in: https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf
# example of a CPE name: cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:x64:*

OFFSET_CPE_IDENTIFIER = 0
OFFSET_CPE_CPE_VERSION = 1
OFFSET_CPE_PART = 2
OFFSET_CPE_VENDOR = 3
OFFSET_CPE_VERSION = 4
OFFSET_CPE_UPDATE = 5
OFFSET_CPE_EDITION = 6
OFFSET_CPE_LANGUAGE = 7
OFFSET_CPE_SW_EDITION = 8
OFFSET_CPE_TARGET_SW = 9
OFFSET_CPE_TARGET_HW = 10
OFFSET_CPE_OTHER = 11

CPE_PART_APPLICATION = 'a'
CPE_PART_OS = 'o'
CPE_PART_HARDWARE = 'h'

SUPPORTED_CVE_VERSION = ['2.3']


def parse_cpe(cpe_string):
    cpe = None
    split_cpe = cpe_string.split(':')

    if split_cpe[OFFSET_CPE_CPE_VERSION] in SUPPORTED_CVE_VERSION:
        cpe = {}
        cpe['part'] = split_cpe[OFFSET_CPE_PART]
        cpe['vendor'] = split_cpe[OFFSET_CPE_VENDOR]
        cpe['version'] = split_cpe[OFFSET_CPE_VERSION]
        cpe['update'] = split_cpe[OFFSET_CPE_UPDATE]
        cpe['edition'] = split_cpe[OFFSET_CPE_EDITION]
        cpe['language'] = split_cpe[OFFSET_CPE_LANGUAGE]
        cpe['sw_edition'] = split_cpe[OFFSET_CPE_SW_EDITION]
        cpe['target_sw'] = split_cpe[OFFSET_CPE_TARGET_SW]
        cpe['target_hw'] = split_cpe[OFFSET_CPE_TARGET_HW]
        cpe['other'] = split_cpe[OFFSET_CPE_OTHER]

    return cpe


if __name__ == '__main__':
    print("test")