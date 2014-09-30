#!/usr/bin/env python2
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
import re



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
