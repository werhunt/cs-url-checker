#!/usr/bin/env python3

import re
import argparse

URL_RE = re.compile(r'https?://[^/]+/(.{4})\b')


def build_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-p',
        '--print',
        default=False,
        action='store_true',
        help='Print output to stdout'
    )
    parser.add_argument(
        'url',
        help='URL to check if its a CS beacon'
    )
    global args
    args = parser.parse_args()


def Checksum8(data):
    return sum(map(ord, data))


def cs_return(string):
    '''

    add dictionary stuff here
    replace print and return string with dic

    '''
    if args.print:
        print(string)
    else:
        return string


def Checksum8LSB(data):
    dMetasploitConstants = {
        92: 'URI_CHECKSUM_INITW / CS x86',
        93: 'CS x64',
        80: 'URI_CHECKSUM_INITP',
        88: 'URI_CHECKSUM_INITJ',
        98: 'URI_CHECKSUM_CONN',
        95: 'URI_CHECKSUM_INIT_CONN',
    }
    value = Checksum8(data) % 0x100
    return (value, dMetasploitConstants.get(value, ''))


def metatool(url):
    oSearch = URL_RE.search(url)
    if oSearch != None:
        path = oSearch.groups()[0]
        checksumValue, checksumConstant = Checksum8LSB(path)
        if checksumConstant != '':
            return '%s (0x%02x)' % (checksumConstant, checksumValue)
        else:
            return 'checksum not found'
    else:
        return 'not evaluated'


if __name__ == '__main__':
    build_args()
    url = args.url
    t = metatool(url)
    cs_return(t)