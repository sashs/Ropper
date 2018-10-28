# coding=utf-8
#
# Copyright 2014 Sascha Schirra
#
# This file is part of Ropper.
#
# Ropper is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ropper is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

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
