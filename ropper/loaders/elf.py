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

from ctypes import *
from ropper.loaders.loader import *
from ropper.common.error import LoaderError
from ropper.common.error import RopperError
from ropper.arch import Endianess
import filebytes.elf as elf
import os


class ELF(Loader):

    def __init__(self, filename, bytes=None, arch=None):

        self.__execSections = None
        self.__dataSections = None

        super(ELF, self).__init__(filename, bytes, arch)

    @property
    def entryPoint(self):
        return self._binary.entryPoint

    
    def _getImageBase(self):
        return self._binary.imageBase


    def _loadDefaultArch(self):
        try:
            machine = elf.EM[self._binary.elfHeader.header.e_machine]
            cls = elf.ELFCLASS[self._binary.elfHeader.header.e_ident[elf.EI.CLASS]]
            end = self._binary._bytes[elf.EI.DATA]

            return getArch( (machine,cls, end ),self._binary.elfHeader.header.e_entry)
        except BaseException as e:
            raise RopperError(e)




    @property
    def executableSections(self):
        if not self.__execSections:
            self.__execSections = []
            for phdr in self._binary.segments:
                if phdr.header.p_flags & elf.PF.EXEC > 0:
                    self.__execSections.append(Section(name=str(elf.PT[phdr.header.p_type]), sectionbytes=phdr.raw, virtualAddress=phdr.header.p_vaddr, offset=phdr.header.p_offset))

        return self.__execSections

    @property
    def dataSections(self):
        if not self.__dataSections:
            self.__dataSections = []
            for shdr in self._binary.sections:
                if shdr.header.sh_flags & elf.SHF.ALLOC and not (shdr.header.sh_flags & elf.SHF.EXECINSTR) and not(shdr.header.sh_type & elf.SHT.NOBITS):
                    self.__dataSections.append(Section(shdr.name, shdr.raw, shdr.header.sh_addr, shdr.header.sh_offset, shdr.header))
        return self.__dataSections

    @property
    def codeVA(self):

        for phdr in self.phdrs:
            if phdr.header.p_type == PT.INTERP:
                return phdr.header.p_vaddr
        return 0

    @property
    def type(self):
        return Type.ELF

    def setASLR(self, enable):
        raise LoaderError('Not available for elf files')

    def setNX(self, enable):
        perm = elf.PF.READ | elf.PF.WRITE  if enable else elf.PF.READ | elf.PF.WRITE | elf.PF.EXEC
        phdrs = self._binary.segments

        for phdr in phdrs:
            if phdr.header.p_type == elf.PT.GNU_STACK:
                phdr.header.p_flags = perm

        self.save()

    def getSection(self, name):
        for shdr in self._binary.sections:
            if shdr.name == name:
                
                return Section(shdr.name, shdr.raw, shdr.header.sh_addr, shdr.header.sh_addr - self._binary.imageBase)
        raise RopperError('No such section: %s' % name)

    def checksec(self):
        return {}

    def _loadFile(self, fileName, bytes=None):
        return elf.ELF(fileName, bytes)

    @classmethod
    def isSupportedFile(cls, fileName, bytes=None):
        if bytes:
            return elf.ELF.isSupportedContent(bytes)
        return elf.ELF.isSupportedFile(fileName)

def getArch(*params):
    arch = ARCH[params[0]]
    if arch==ARM and (params[1] & 1) == 1:
        return ARMTHUMB
    return arch


ARCH = {(elf.EM.INTEL_386 , elf.ELFCLASS.BITS_32, elf.ELFDATA.LSB): x86,
        (elf.EM.INTEL_80860, elf.ELFCLASS.BITS_32, elf.ELFDATA.LSB): x86,
        (elf.EM.IA_64, elf.ELFCLASS.BITS_64, elf.ELFDATA.LSB): x86_64,
        (elf.EM.X86_64, elf.ELFCLASS.BITS_64, elf.ELFDATA.LSB): x86_64,
        (elf.EM.MIPS, elf.ELFCLASS.BITS_32, elf.ELFDATA.MSB): MIPSBE,
        (elf.EM.MIPS, elf.ELFCLASS.BITS_32, elf.ELFDATA.LSB): MIPS,
        (elf.EM.MIPS, elf.ELFCLASS.BITS_64, elf.ELFDATA.MSB): MIPS64BE,
        (elf.EM.MIPS, elf.ELFCLASS.BITS_64, elf.ELFDATA.LSB): MIPS64,
        (elf.EM.ARM, elf.ELFCLASS.BITS_32, elf.ELFDATA.MSB) : ARMBE,
        (elf.EM.ARM, elf.ELFCLASS.BITS_32, elf.ELFDATA.LSB) : ARM,
        (elf.EM.ARM64, elf.ELFCLASS.BITS_64, elf.ELFDATA.LSB) : ARM64,
        (elf.EM.PPC, elf.ELFCLASS.BITS_32, elf.ELFDATA.MSB) : PPC,
        (elf.EM.PPC, elf.ELFCLASS.BITS_64, elf.ELFDATA.MSB) : PPC64}
