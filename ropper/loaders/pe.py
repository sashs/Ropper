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

    def __init__(self, filename, bytes=None, arch=None):

        super(PE, self).__init__(filename, bytes, arch)

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

    def _loadFile(self, fileName, bytes=None):
        return pe.PE(fileName, bytes)

    @classmethod
    def isSupportedFile(cls, fileName, bytes=None):
        if bytes:
            return pe.PE.isSupportedContent(bytes)
        return pe.PE.isSupportedFile(fileName)

def getArch(*params):
    return ARCH[params[0]]

ARCH = {int(pe.IMAGE_FILE_MACHINE.AMD64):
        x86_64, int(pe.IMAGE_FILE_MACHINE.I386): x86,
        int(pe.IMAGE_FILE_MACHINE.ARM) : ARM,
        int(pe.IMAGE_FILE_MACHINE.ARMV) : ARMTHUMB}
