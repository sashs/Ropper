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

from ropper.common.abstract import *
from sys import stdout
from ropper.loaders.loader import Type
from ropper.common.utils import *
from ropper.common.enum import Enum
from ropper.common.error import PrinterError
from ropper.common.coloredstring import *
import ropper


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
