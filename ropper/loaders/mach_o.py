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
from ropper.loaders.loader import *
from struct import pack as p
import filebytes.mach_o as macho

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
        return self._binary.entryPoint

    
    def _getImageBase(self):
        return self._binary.imageBase

    
    def _loadDefaultArch(self):
        try:
            return ARCH[self._binary.machHeader.header.cputype]
        except:
            return None
    @property
    def type(self):
        return Type.MACH_O

    @property
    def executableSections(self):
        toReturn = []
        for loadCommand in self._binary.loadCommands:
            if loadCommand.header.cmd == macho.LC.SEGMENT or loadCommand.header.cmd == macho.LC.SEGMENT_64:
                for section in loadCommand.sections:
                    if section.header.flags & macho.S_ATTR.SOME_INSTRUCTIONS  or section.header.flags & macho.S_ATTR.PURE_INSTRUCTIONS:
                        toReturn.append(Section(section.header.sectname, section.raw, section.header.addr, section.header.offset))
        return toReturn

    @property
    def dataSections(self):
        toReturn = []
        for loadCommand in self._binary.loadCommands:
            if loadCommand.header.cmd == macho.LC.SEGMENT or loadCommand.header.cmd == macho.LC.SEGMENT_64:
                for section in loadCommand.sections:
                    if not section.header.flags & macho.S_ATTR.SOME_INSTRUCTIONS  or  not section.header.flags & macho.S_ATTR.PURE_INSTRUCTIONS:
                        toReturn.append(Section(section.header.sectname, section.raw, section.header.addr, section.header.offset))
        return toReturn

    def getSection(self, name):
        for loadCommand in self.loaderCommands:
            if loadCommand.header.cmd == LC.SEGMENT or loadCommand.header.cmd == LC.SEGMENT_64:
                for section in loadCommand.sections:
                    if section.header.sectname.decode('ASCII') == name:
                        toReturn.append(Section(section.header.sectname, section.raw, section.header.addr, section.header.offset))
        raise RopperError('No such secion: %s' % name)        
        
    def setNX(self, enable):
        raise LoaderError('Not available for mach-o files')

    def setASLR(self, enable):
        raise LoaderError('Not available for mach-o files')


    def checksec(self):
        return {}

    def _loadFile(self, fileName):
        return macho.MachO(fileName)

    @classmethod
    def isSupportedFile(cls, fileName):
        return macho.MachO.isSupportedFile(fileName)

ARCH = {int(macho.CpuType.I386): x86,
        int(macho.CpuType.X86_64): x86_64,
        int(macho.CpuType.POWERPC) : PPC,
        int(macho.CpuType.POWERPC64) : PPC64,
        int(macho.CpuType.ARM) : ARM,
        int(macho.CpuType.ARM64) : ARM64}
