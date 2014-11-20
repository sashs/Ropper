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

from ropperapp.common.abstract import *
from sys import stdout
from ropperapp.loaders.loader import Type
from ropperapp.common.utils import *
from ropperapp.common.enum import Enum
from ropperapp.common.error import PrinterError
from ropperapp.common.coloredstring import *
import ropperapp


class Printer(object):

    def __init__(self, colored=False, out=stdout):
        self._out = out

    def printLine(self, line):
        self._printString(line + '\n')

    def printString(self, string):
        return self._out.write(string)

class PrinterMeta(type):

    def __new__(self, name, bases, dct):
        self.__availableInfos = {}
        for key, value in dct.items():
            if key.startswith('print'):
                info = self.__createInfoString(key[5:])
                self.__availableInfos[info] = value
        dct['availableInformations'] = sorted(self.__availableInfos.keys())

        return super(PrinterMeta, self).__new__(self, name, bases, dct)

    @staticmethod
    def __createInfoString(string):
        toReturn = ''

        for c in string:
            if c >= 'A' and c <= 'Z':
                c = c.lower()
                if len(toReturn) != 0:
                    toReturn += '_'
            toReturn += c

        return toReturn





DataPrinter = PrinterMeta('DataPrinter', (), {})


class FileDataPrinter(DataPrinter):

    def __init__(self, out=stdout):
        super(FileDataPrinter, self).__init__()

        self._out = out

    @classmethod
    def validType(cls):
        return Type.NONE

    def printTableHeader(self, string):
        self._printLine('\n\n')
        self._printLine(string)
        self._printLine('=' * len(string))
        self._printLine('\n')

    def __createFmtString(self, rows, cnames, space):
        scount = []

        for cname in cnames:
            scount.append(len(cname)+space)

        for row in rows:
            for idx in range(len(scount)):
                new = len(cstr(row[idx])) + space

                scount[idx] = max(scount[idx], new)

        return str('%-{}s' * len(scount)).format(*scount)

    def _printTable(self, header, cnames, data, space=2, fmt=None):
        ccount = len(cnames)

        if not fmt:
            fmt = self.__createFmtString(data, cnames,  space)

        self.printTableHeader(header)

        cnamelines = []
        for cname in cnames:
            if isinstance(cname, cstr):
                cnamelines.append(cstr('-' * cname.rawlength(), cname.color))
            else:
                cnamelines.append('-' * len(cname))

        self._printLine(fmt % cnames)
        self._printLine(fmt % tuple(cnamelines))


        for row in data:
            line = fmt % row


            self._printLine(line.strip())

        self._printLine('')

    def _toHex(self, number, length=4):
        return toHex(number, length)

    def _printLine(self, line):
        self._printString(line + '\n')

    def _printString(self, string):
        return self._out.write(string)

    def __createCamelCaseString(self, string):
        parts = string.split('_')
        toReturn = ''
        for part in parts:
            toReturn += part.capitalize()

        return toReturn

    def printData(self, file, info):
        if info not in self.availableInformations:
            raise PrinterError(
                'Cannot print \'{}\' for {} files'.format(info, self.validType()))
        self.__getattribute__('print' + self.__createCamelCaseString(info))(file)

    def printEntryPoint(self, binary):
        self._printLine(self._toHex(binary.entryPoint, binary.arch.addressLength))

    def printImageBase(self, binary):
        self._printLine(
            self._toHex(binary.imageBase))

    @classmethod
    def create(cls, bintype):
        subclasses = FileDataPrinter.__subclasses__()

        for subclass in subclasses:
            if subclass.validType() == bintype:
                dir(subclass)
                return subclass()
