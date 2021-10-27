#!/usr/bin/env python3

import base64
import csv
import re
import sys
import time


URL_RE = re.compile('(?:https?://[^/]+)?/([^/]+)/?')

dArchitectures = {
     0: 'nil',
     1: 'ARCH_X86',
     2: 'ARCH_X64',
     3: 'ARCH_X64',
     4: 'ARCH_MIPS',
     5: 'ARCH_MIPSLE',
     6: 'ARCH_MIPSBE',
     7: 'ARCH_PPC',
     8: 'ARCH_PPC64',
     9: 'ARCH_CBEA',
    10: 'ARCH_CBEA64',
    11: 'ARCH_SPARC',
    12: 'ARCH_ARMLE',
    13: 'ARCH_ARMBE',
    14: 'ARCH_CMD',
    15: 'ARCH_PHP',
    16: 'ARCH_TTY',
    17: 'ARCH_JAVA',
    18: 'ARCH_RUBY',
    19: 'ARCH_DALVIK',
    20: 'ARCH_PYTHON',
    21: 'ARCH_NODEJS',
    22: 'ARCH_FIREFOX',
    23: 'ARCH_ZARCH',
    24: 'ARCH_AARCH64',
    25: 'ARCH_MIPS64',
    26: 'ARCH_PPC64LE',
    27: 'ARCH_R',
    28: 'ARCH_PPCE500V2'
}

dPlatforms = {
     0: 'nil',
     1: 'windows',
     2: 'netware',
     3: 'android',
     4: 'java',
     5: 'ruby',
     6: 'linux',
     7: 'cisco',
     8: 'solaris',
     9: 'osx',
    10: 'bsd',
    11: 'openbsd',
    12: 'bsdi',
    13: 'netbsd',
    14: 'freebsd',
    15: 'aix',
    16: 'hpux',
    17: 'irix',
    18: 'unix',
    19: 'php',
    20: 'js',
    21: 'python',
    22: 'nodejs',
    23: 'firefox',
    24: 'r',
    25: 'apple_ios',
    26: 'juniper',
    27: 'unifi',
    28: 'brocade',
    29: 'mikrotik',
    30: 'arista'
  }

def oREurluuid():
        if len(sys.argv) != 2:
        print("Usage python metatool.py [uri]")
        sys.exit(1)
    infile = sys.stdin
    outfile = sys.stdout
    r = csv.DictReader(infile)
    w = csv.DictWriter(outfile, fieldnames=r.fieldnames)
    w.writeheader()
    for result in r:
    oSearch = oREurluuid.search(result['combined_uri'])
        if oSearch != None:
            if len(oSearch.groups()[0]) >= 22:
                try:
                    decoded = base64.urlsafe_b64decode(oSearch.groups()[0][0:22] + '==')
                except:
                    continue

                if len(decoded) < struct.calcsize(format):
                    continue
                puid, xor1, xor2, platform_xored, architecture_xored, ts1_xored, ts2_xored, ts3_xored, ts4_xored = struct.unpack(format, decoded)
                platform = platform_xored ^ xor1
                platformName = dPlatforms.get(platform, UNDEFINED)
                if platformName == UNDEFINED and not options.force:
                    continue
                architecture = architecture_xored ^ xor2
                architectureName = dArchitectures.get(architecture, UNDEFINED)
                if architectureName == UNDEFINED and not options.force:
                    continue
                timestamp = struct.unpack('>I', bytes([ts1_xored ^ xor1, ts2_xored ^ xor2, ts3_xored ^ xor1, ts4_xored ^ xor2]))[0]
                result['puid'] = ('%s (%s)' % (binascii.b2a_hex(puid), repr(puid)))
                result['platform'] = ('%d (%s)' % (platform, platformName))
                result['architecture'] = ('%d (%s)' % (architecture, architectureName))
                result['timestamp' ] = ('%s' % (FormatTime(timestamp)))
            else:
                result['puid'] = 'bad puid'
                result['platform'] = 'bad platform'
                result['architecture'] = 'bad architecture'
                result['timestamp'] = 'bad timestamp'
            w.writerow(result)

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
    oREurluuid()