# coding=utf-8
# Copyright 2018 Sascha Schirra
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" A ND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
from .coloredstring import *
import ropper
import re
import sys

def getFileNameFromPath(path):
    if '/' in path:
        name = path.split('/')[-1]
    elif '\\' in path:
        name = path.split('\\')[-1]
    else:
        name = path

    return name

def isHex(num):
    return re.match('^0x[0-9A-Fa-f]+$', num) != None


def toHex(number, length=4):

    t = 0xff
    for i in range(length-1):
        t <<= 8
        t |= 0xff
    number = int(number) & t
    return ('0x%.' + str(length * 2) + 'x') % number

def printTableHeader( string):
    print('\n')
    print(string)
    print('=' * len(string))
    print('')

def createFmtString(rows, cnames, space):
    scount = []

    for cname in cnames:
        scount.append(len(cname)+space)

    for row in rows:
        for idx in range(len(scount)):
            new = len(cstr(row[idx])) + space

            scount[idx] = max(scount[idx], new)

    return str('%-{}s' * len(scount)).format(*scount)

def printTable(header, cnames, data, space=2, fmt=None):
    ccount = len(cnames)

    if not fmt:
        fmt = createFmtString(data, cnames,  space)

    printTableHeader(header)

    cnamelines = []
    for cname in cnames:
        if isinstance(cname, cstr):
            cnamelines.append(cstr('-' * cname.rawlength(), cname.color))
        else:
            cnamelines.append('-' * len(cname))

    print(fmt % cnames)
    print(fmt % tuple(cnamelines))


    for row in data:
        line = fmt % row


        print(line.strip())

    print('')

def printHexFormat(data, addr, nocolor=False):
    for i in range((int(len(data)/16))+1):
        part = data[i*16:i*16+16]
        bytes = cstr('')
        c = 0
        for j in range(0,len(part),2):
            if j == len(part)-1:
                bytes += cstr(('%.2x ' % tuple(part[j:j+1])), Color.WHITE if c % 2 else Color.LIGHT_GRAY)
            else:
                bytes += cstr(('%.2x%.2x ' % tuple(part[j:j+2])), Color.WHITE if c % 2 else Color.LIGHT_GRAY)
            c += 1
        string = ''
        if nocolor:
            if len(bytes) < 40:
                bytes += ' ' * (40 - len(bytes))
        else:
            if len(bytes) < 227:

                bytes += ' ' * ((8-int(len(bytes)/29)) *5)
        for b in part:
            if b < 32 or b > 126:
                string += '.'
            else:
                string += chr(b)

        bytes +=  ' ' + cstr(string, Color.BLUE)
        print(cstr(toHex(addr + i*16), Color.RED) +': ' + bytes)


def isWindows():
    return sys.platform.lower().startswith('win')
