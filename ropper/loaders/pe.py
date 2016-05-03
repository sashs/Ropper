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
from filebytes import pe
import os
import struct


class ImageImportDescriptorData(DataContainer):

    """
    struct = IMAGE_IMPORT_DESCRIPTOR
    dll = string (dll name)
    functions = list (imported function names)
    """


class PE(Loader):

    def __init__(self, filename):

        super(PE, self).__init__(filename)

    @property
    def entryPoint(self):
        return self._binary.entryPoint
        
    def _loadDefaultArch(self):
        return getArch(self._binary.imageNtHeaders.header.FileHeader.Machine)

    @property
    def type(self):
        return Type.PE

    @property
    def executableSections(self):
    #    toReturn = [self.sections['.text']]
        toReturn = []
        for section in self._binary.sections:
            if section.header.Characteristics & pe.IMAGE_SCN.CNT_CODE > 0:
                s = Section(section.name, section.raw, section.header.VirtualAddress + self.imageBase, section.header.VirtualAddress)
                toReturn.append(s)
        return toReturn

    @property
    def dataSections(self):
        toReturn = []
        for section in self._binary.sections:
            if section.header.Characteristics & pe.IMAGE_SCN.CNT_INITIALIZED_DATA or section.header.Characteristics & pe.IMAGE_SCN.CNT_UNINITIALIZED_DATA:
                s = Section(section.name, section.raw, section.header.VirtualAddress + self.imageBase, section.header.VirtualAddress)

                toReturn.append(s)
        return toReturn


    def getWriteableSection(self):
        for section in self._binary.sections:
            if section.header.Characteristics & pe.IMAGE_SCN.MEM_WRITE:
                s = Section(section.name, section.raw, section.header.VirtualAddress + self.imageBase, section.header.VirtualAddress)

                return s

    def getSection(self, name):
        
        for section in self.sections:
            if str(section.name) == name:
                s = Section(section.name, section.raw, section.header.VirtualAddress + self.imageBase, section.header.VirtualAddress)

                return s
        raise RopperError('No such secion: %s' % name)        

    def setNX(self, enable):
        if enable:
            self._binary.imageNtHeaders.header.OptionalHeader.DllCharacteristics |= pe.ImageDllCharacteristics.NX_COMPAT
        else:
            self._binary.imageNtHeaders.header.OptionalHeader.DllCharacteristics &= ~pe.ImageDllCharacteristics.NX_COMPAT
        self.save()

    def setASLR(self, enable):
        if enable:
            self._binary.imageNtHeaders.header.OptionalHeader.DllCharacteristics |= pe.ImageDllCharacteristics.DYNAMIC_BASE
        else:
            self._binary.imageNtHeaders.header.OptionalHeader.DllCharacteristics &= ~pe.ImageDllCharacteristics.DYNAMIC_BASE
        self.save()

    def _getImageBase(self):
        return self._binary.imageBase

    def checksec(self):

        return {'SafeSEH' : self.imageNtHeaders.OptionalHeader.DataDirectory[ImageDirectoryEntry.LOAD_CONFIG].Size != 0,
                'ASLR' : self.imageNtHeaders.OptionalHeader.DllCharacteristics & ImageDllCharacteristics.DYNAMIC_BASE != 0,
                'DEP' : self.imageNtHeaders.OptionalHeader.DllCharacteristics & ImageDllCharacteristics.NX_COMPAT != 0}

    def _loadFile(self, fileName):
        return pe.PE(fileName)

    @classmethod
    def isSupportedFile(cls, fileName):
        return pe.PE.isSupportedFile(fileName)

def getArch(*params):
    return ARCH[params[0]] 

ARCH = {int(pe.IMAGE_FILE_MACHINE.AMD64):
        x86_64, int(pe.IMAGE_FILE_MACHINE.I386): x86,
        int(pe.IMAGE_FILE_MACHINE.ARM) : ARM,
        int(pe.IMAGE_FILE_MACHINE.ARMV) : ARMTHUMB}
