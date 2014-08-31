from ropperapp.common.abstract import *
from sys import stdout
from ropperapp.loaders.loader import Type
from ropperapp.common.utils import *


class PrinterError(BaseException):
    pass


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
        return None

    def printTableHeader(self, string):
        self._printLine('\n\n')
        self._printLine(string)
        self._printLine('=' * len(string))
        self._printLine('\n')

    def __createFmtString(self, rows, ccount, space):
        scount = [0] * ccount

        for row in rows:
            for idx in range(ccount):
                scount[idx] = max(scount[idx], len(str(row[idx])) + space)

        return str('%-{}s' * ccount).format(*scount)

    def _printTable(self, header, cnames, data, space=2, fmt=None):
        ccount = len(cnames)

        if not fmt:
            fmt = self.__createFmtString(data, ccount, space)

        self.printTableHeader(header)

        cnamelines = []
        for cname in cnames:
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
