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
from ropper.loaders.loader import *
from struct import pack as p
import filebytes.mach_o as macho

class MachO(Loader):

    def __init__(self, filename, bytes=None, arch=None):

        self.loaderCommands = []
        self.header = None
        self.segments = []
        self.__module = None
        self.__imageBase = None

        super(MachO, self).__init__(filename, bytes, arch)

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

    def _loadFile(self, fileName, bytes=None):
        return macho.MachO(fileName, bytes)

    @classmethod
    def isSupportedFile(cls, fileName, bytes=None):
        if bytes:
            return macho.MachO.isSupportedContent(bytes)
        return macho.MachO.isSupportedFile(fileName)

ARCH = {int(macho.CpuType.I386): x86,
        int(macho.CpuType.X86_64): x86_64,
        int(macho.CpuType.POWERPC) : PPC,
        int(macho.CpuType.POWERPC64) : PPC64,
        int(macho.CpuType.ARM) : ARM,
        int(macho.CpuType.ARM64) : ARM64}
