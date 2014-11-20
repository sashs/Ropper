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
from ropperapp.loaders.loader import *
from ropperapp.loaders.mach_intern.mach_gen import *
from struct import pack as p
import importlib

class SegmentData(DataContainer):
    """
    struct = SegmentCommand
    name = string (section name)
    bytes = c_byte_array (section bytes)
    """

class LoaderData(DataContainer):
    """
    struct = LoaderCommand

    """

class SectionData(DataContainer):
    """
    struct = Section

    """

class MachO(Loader):

    def __init__(self, filename):

        self.loaderCommands = []
        self.header = None
        self.segments = []
        self.__module = None
        self.__imageBase = None

        super(MachO, self).__init__(filename)

    @property
    def entryPoint(self):
        return 0x0

    @property
    def imageBase(self):
        if self.__imageBase == None:
            es = self.executableSections[0]
            if es != None:

                self.__imageBase = es.virtualAddress - es.offset
            else:
                self.__imageBase = 0x0
        return self.__imageBase

    
    def _loadDefaultArch(self):
        try:
            return ARCH[self.header.cputype]
        except:
            return None
    @property
    def type(self):
        return Type.MACH_O

    @property
    def executableSections(self):
        toReturn = []
        for loaderCommand in self.loaderCommands:
            if loaderCommand.struct.cmd == LC.SEGMENT or loaderCommand.struct.cmd == LC.SEGMENT_64:
                for section in loaderCommand.sections:
                    section = section.struct
                    if section.flags & S_ATTR.SOME_INSTRUCTIONS > 0 or section.flags & S_ATTR.PURE_INSTRUCTIONS:
                        sectbytes_p = c_void_p(self._bytes_p.value + section.offset)
                        sectbytes = cast(sectbytes_p, POINTER(c_ubyte * section.size)).contents
                        toReturn.append(Section(section.sectname, sectbytes, section.addr, section.offset))
        return toReturn


    def __loadModule(self):
        modName = None
        if self._bytes[7] == 0:
            modName = 'ropperapp.loaders.mach_intern.mach32'
        elif self._bytes[7] == 1:
            modName = 'ropperapp.loaders.mach_intern.mach64'
        else:
            raise LoaderError('Bad architecture')
        self.__module = importlib.import_module(modName)

    def __parseSections(self, segment, segment_p):
        p_tmp = c_void_p(segment_p.value + sizeof(self.__module.SegmentCommand))
        sections = []
        for i in range(segment.nsects):
            sec = cast(p_tmp, POINTER(self.__module.Section)).contents


            p_tmp.value += sizeof(self.__module.Section)
            sections.append(SectionData(struct=sec))

        return sections

    def __parseSegmentCommand(self, segment_p):
        sc = cast(segment_p, POINTER(self.__module.SegmentCommand)).contents
        sections = self.__parseSections(sc, segment_p)
        return SegmentData(struct=sc, name=sc.segname, sections=sections)

    def __parseCommands(self):
        p_tmp = c_void_p(self._bytes_p.value + sizeof(self.__module.MachHeader))
        for i in range(self.header.ncmds):
            command = cast(p_tmp, POINTER(LoadCommand)).contents
            if command.cmd == LC.SEGMENT or command.cmd == LC.SEGMENT_64:
                self.loaderCommands.append(self.__parseSegmentCommand(p_tmp))
            else:
                self.loaderCommands.append(LoaderData(struct=command))
            p_tmp.value += command.cmdsize

    def __parseHeader(self):
        self.header = cast(self._bytes_p, POINTER(self.__module.MachHeader)).contents

    def _parseFile(self):
        self.__loadModule()
        self.__parseHeader()
        self.__parseCommands()

    def setNX(self, enable):
        raise LoaderError('Not available for mach-o files')

    def setASLR(self, enable):
        raise LoaderError('Not available for mach-o files')


    def checksec(self):
        return {}

    @classmethod
    def isSupportedFile(cls, fileName):
        try:
            with open(fileName, 'rb') as f:
                magic = f.read(4)
                return magic == p('>I', 0xfeedface) or magic == p('>I', 0xfeedfacf) or magic == p('<I', 0xfeedface) or magic == p('<I', 0xfeedfacf)
        except BaseException as e:
            raise LoaderError(e)
