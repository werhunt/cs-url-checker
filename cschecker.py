#!/usr/bin/env python3

import re
import csv
import sys

URL_RE = re.compile(r'https?://[^/]+/(.{4})[^\w{0-9A-Za-z\-\_}]')


def Checksum8(data):
    return sum(map(ord, data))


def Checksum8LSB(data):
    dMetasploitConstants = {
        92: 'Possible Windows/Native Client', #URI_CHECKSUM_INITW / CS x86',
        93: 'Possible CS x64',
        80: 'Possible Python Client', #URI_CHECKSUM_INITP',
        88: 'Possible Java Client', #URI_CHECKSUM_INITJ',
        98: 'Possible Exisiting Session', #URI_CHECKSUM_CONN',
        95: 'Possible New Stageless Session', #URI_CHECKSUM_INIT_CONN',
    }
    value = Checksum8(data) % 0x100
    return (value, dMetasploitConstants.get(value, ''))


def metatool():
    if len(sys.argv) != 2:
        print("Usage pythin metatool.py [uri]")
        sys.exit(1)
    infile = sys.stdin
    outfile = sys.stdout
    r = csv.DictReader(infile)
    w = csv.DictWriter(outfile, fieldnames=r.fieldnames)
    w.writeheader()
    for result in r:
        oSearch = URL_RE.search(result['combined_uri'])
        if oSearch != None:
            path = oSearch.groups()[0]
            checksumValue, checksumConstant = Checksum8LSB(path)
            if checksumConstant != '':
                result['parsedcheck'] = f'{checksumConstant}'
            else:
                result['parsedcheck'] = 'checksum not found'
        else:
            result['parsedcheck'] = 'not evaluated'
        w.writerow(result)


if __name__ == '__main__':
    metatool()
