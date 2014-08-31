#!/usr/bin/env python
# coding=utf-8
from ropperapp.common.abstract import *
from ctypes import *
from ropperapp.common.enum import Enum
from struct import pack_into
from ropperapp.common.error import *


class Type(Enum):
    _enum_ = 'ELF PE'


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

        self._loadFile()
        self._parseFile()

    @abstractproperty
    def entryPoint(self):
        return None

    @abstractproperty
    def imageBase(self):
        return None

    @abstractproperty
    def arch(self):
        return None

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
    def setNX(self, enable):
        pass

    @abstractmethod
    def setASLR(self, enable):
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
        for subclass in sc:
            if subclass.isSupportedFile(fileName):
                return subclass(fileName)

        raise LoaderError('Filetype not supported')

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
