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
from ctypes import *
from ropper.common.enum import Enum
from struct import pack_into
from ropper.common.error import *
from ropper.arch import *
from hashlib import sha256
import re

class Type(Enum):
    _enum_ = 'ELF PE MACH_O RAW NONE'


class DataContainer(object):

    def __init__(self, **args):
        setattr = super(DataContainer, self).__setattr__
        for key, value in args.items():
            setattr(key, value)


class Section(object):

    def __init__(self, name, sectionbytes, virtualAddress, offset, struct=None):
        if type(name) == bytes:
            name = name.decode('ascii')
        self.name = name
        self.bytes = sectionbytes
        self.virtualAddress = virtualAddress
        self.offset = offset
        self.struct = struct

    @property
    def size(self):
        return len(self.bytes)


class Loader(Abstract):

    def __init__(self, filename, bytes=None, arch=None):
        super(Loader, self).__init__()

        self._fileName = filename
        self._bytes = None
        self._bytes_p = None
        self._arch = arch

        self._gadgets = {}
        self._checksum = 0x0

        self._printer = None
        self._manualImageBase = None
        self.loaded = False

        self.__binary = self._loadFile(filename, bytes)
        self.__calculateChecksum()
        if arch is None:
            self._arch = self._loadDefaultArch()

    @property
    def checksum(self):
        return self._checksum

    @property
    def _binary(self):
        return self.__binary


    @abstractproperty
    def entryPoint(self):
        return None

    @property
    def arch(self):
        return self._arch

    @arch.setter
    def arch(self, arch):
        self._arch = arch

    @abstractproperty
    def type(self):
        return None

    @abstractproperty
    def executableSections(self):
        return None

    @abstractproperty
    def dataSections(self):
        return None

    @abstractmethod
    def _getImageBase():
        pass

    @abstractmethod
    def getSection(self, name):
        pass

    @abstractmethod
    def _loadDefaultArch(self):
        pass

    @abstractmethod
    def setNX(self, enable):
        pass

    @abstractmethod
    def setASLR(self, enable):
        pass

    @abstractmethod
    def checksec(self):
        pass

    @property
    def imageBase(self):
        if self._manualImageBase == None:
            return self._getImageBase()

        return self._manualImageBase

    @imageBase.setter
    def imageBase(self, imageBase):
        self._manualImageBase = imageBase

    @property
    def fileName(self):
        return self._fileName

    def __calculateChecksum(self):
        m = sha256()
        m.update(self._binary._bytes)
        self._checksum = m.hexdigest()

    @classmethod
    def isSupportedFile(cls, fileName, bytes=None):
        return False

    @classmethod
    def open(cls, fileName, bytes=None, raw=False, arch=None):
        sc = Loader.__subclasses__()
        Raw = None
        for subclass in sc:
            if subclass.__name__ != 'Raw':
                if not raw and subclass.isSupportedFile(fileName, bytes):
                    if arch:
                        return subclass(fileName, bytes, arch=arch)
                    else:
                        return subclass(fileName, bytes)
            else:
                Raw = subclass

        if Raw:
            if not arch:
                raise ArgumentError('Architecture has to be set, if raw file should be loaded')
            return Raw(fileName, bytes=bytes, arch=arch)
        else:
            raise LoaderError('Not supported file type')

    @property
    def loaded(self):
        return self._loaded

    @loaded.setter
    def loaded(self, isloaded):
        self._loaded = isloaded

    @property
    def printer(self):
        return self._printer

    @printer.setter
    def printer(self, new_printer):
        self._printer = new_printer

    @property
    def gadgets(self):
        return self._gadgets

    @gadgets.setter
    def gadgets(self, new_gadgets):
        self._gadgets = new_gadgets

    def _loadFile(self, fileName, bytes=None):
        pass

    def assertFileRange(self, value):
        assert value >= self._bytes_p.value and value <= (
            self._bytes_p.value + len(self._bytes)), 'Pointer not in file range'

    def _searchString(self, sections, string=None, length=0):
        toReturn = []
        if not string or string == '[ -~]{2}[ -~]*':
            string = '[ -~]{2}[ -~]*'
        else:
            string = self.arch.searcher.prepareFilter(string)

        string = string.encode('ascii') # python 3 compatibility
        for section in sections:

            b = bytes(bytearray(section.bytes))
            for match in re.finditer(string, b):
                if length > 0:
                    if len(match.group()) >= length:
                        toReturn.append((self.imageBase + section.offset + match.start(), match.group()))
                else:
                    toReturn.append((self.imageBase + section.offset + match.start(), match.group()))

        return toReturn

    def searchDataString(self, string=None, length=0):
        return self._searchString(list(self.dataSections), string, length)

    def searchString(self, string=None, length=0, sectionName=None):
        sections = list(self.dataSections)
        sections.extend(self.executableSections)
        if sectionName != None:
            for section in sections:
                if section.name == sectionName:
                    return self._searchString([section], string, length)
        else:
            return self._searchString(sections, string, length)

    def save(self, fileName=None):

        if not fileName:
            fileName = self.fileName
        try:
            with open(fileName, 'wb') as f:
                f.write(self._binary._bytes)
        except BaseException as e:
            raise LoaderError(e)

    # def calculateImageBase(self, section):
    #     ib = self.imageBase

    #     if self.manualImagebase == None:
    #         return ib

    #     return self.manualImagebase
