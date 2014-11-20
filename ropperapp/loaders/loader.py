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
from ctypes import *
from ropperapp.common.enum import Enum
from struct import pack_into
from ropperapp.common.error import *


class Type(Enum):
    _enum_ = 'ELF PE MACH_O RAW NONE'


class DataContainer(object):

    def __init__(self, **args):
        setattr = super(DataContainer, self).__setattr__
        for key, value in args.items():
            setattr(key, value)


class Section(object):

    def __init__(self, name, sectionbytes, virtualAddress, offset):
        self.name = name
        self.bytes = sectionbytes
        self.virtualAddress = virtualAddress
        self.offset = offset


class Loader(Abstract):

    def __init__(self, filename):
        super(Loader, self).__init__()

        self._fileName = filename
        self._bytes = None
        self._bytes_p = None
        self._arch = None

        self._loadFile()
        self._parseFile()
        self._arch = self._loadDefaultArch()

    @abstractproperty
    def entryPoint(self):
        return None

    @abstractproperty
    def imageBase(self):
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

    @abstractmethod
    def _parseFile(self):
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
    def fileName(self):
        return self._fileName

    @classmethod
    def isSupportedFile(cls, fileName):
        return False

    @classmethod
    def open(cls, fileName):
        sc = Loader.__subclasses__()
        Raw = None
        for subclass in sc:
            if subclass.__name__ != 'Raw':
                if subclass.isSupportedFile(fileName):
                    return subclass(fileName)
            else:
                Raw = subclass

        if Raw:
            return Raw(fileName)
        else:
            raise LoaderError('Not supported file type')


    def _loadFile(self):
        with open(self.fileName, 'rb') as binFile:
            b = binFile.read()
            self._bytes = (c_ubyte * len(b))()
            pack_into('%ds' % len(b), self._bytes, 0, b)

        self._bytes_p = cast(pointer(self._bytes), c_void_p)

    def assertFileRange(self, value):
        assert value >= self._bytes_p.value and value <= (
            self._bytes_p.value + len(self._bytes)), 'Pointer no in file range'

    def save(self, fileName=None):

        if not fileName:
            fileName = self.fileName
        try:
            with open(fileName, 'wb') as f:
                f.write(self._bytes)
        except BaseException as e:
            raise LoaderError(e)
