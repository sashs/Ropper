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

from ctypes import *
from ropperapp.loaders.loader import *
from ropperapp.common.enum import Enum
from ropperapp.loaders.pe_intern.pe_gen import *
import importlib
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



        self.__pe_module = None

        self.sectionHeader = None
        self.sections = {}
        self.imageDosHeader = None
        self.imageNtHeaders = None
        super(PE, self).__init__(filename)

    @property
    def entryPoint(self):
        return self.imageNtHeaders.OptionalHeader.ImageBase + self.imageNtHeaders.OptionalHeader.AddressOfEntryPoint

    def _loadDefaultArch(self):
        try:
            return self.__pe_module.getArch(self.imageNtHeaders.FileHeader.Machine)
        except:
            return None

    @property
    def type(self):
        return Type.PE

    @property
    def executableSections(self):
        toReturn = [self.sections['.text']]
        #for value in self.sectionHeader:
         #   if value.Characteristics & IMAGE_SCN.CNT_CODE > 0:
          #      toReturn.append(self.sections[value.Name])
        return toReturn


    def setNX(self, enable):
        if enable:
            self.imageNtHeaders.OptionalHeader.DllCharacteristics |= ImageDllCharacteristics.NX_COMPAT
        else:
            self.imageNtHeaders.OptionalHeader.DllCharacteristics &= ~ImageDllCharacteristics.NX_COMPAT
        self.save()

    def setASLR(self, enable):
        if enable:
            self.imageNtHeaders.OptionalHeader.DllCharacteristics |= ImageDllCharacteristics.DYNAMIC_BASE
        else:
            self.imageNtHeaders.OptionalHeader.DllCharacteristics &= ~ImageDllCharacteristics.DYNAMIC_BASE
        self.save()

    @property
    def imageBase(self):
        return self.imageNtHeaders.OptionalHeader.ImageBase

    def __parseSections(self, p_bytes):
        self.sectionHeader = (
            IMAGE_SECTION_HEADER * self.imageNtHeaders.FileHeader.NumberOfSections)()

        for i in range(self.imageNtHeaders.FileHeader.NumberOfSections):
            self.assertFileRange(p_bytes.value)
            self.sectionHeader[i] = cast(
                p_bytes, POINTER(self.__pe_module.IMAGE_SECTION_HEADER)).contents
            p_bytes.value += sizeof(self.__pe_module.IMAGE_SECTION_HEADER)

    def __loadThunks(self, addr):
        p_thunk = c_void_p(addr)
        thunks = []
        while True:
            self.assertFileRange(p_thunk.value)
            thunk = cast(
                p_thunk, POINTER(self.__pe_module.IMAGE_THUNK_DATA)).contents
            p_thunk.value += sizeof(self.__pe_module.IMAGE_THUNK_DATA)
            if thunk.Ordinal == 0:
                break
            thunks.append(thunk)

        return thunks

    def __parseThunkContent(self, thunks, diff, thunkRVA):
        contents = []
        tmpRVA = thunkRVA
        for thunk in thunks:
            if 0xf0000000 & thunk.AddressOfData == 0x80000000:
                contents.append((thunk.AddressOfData & 0x0fffffff,'', tmpRVA))
                tmpRVA += sizeof(self.__pe_module.IMAGE_THUNK_DATA)
                continue
            p_thunk_address_of_data = c_void_p(thunk.AddressOfData - diff)

            ibn = cast(
                p_thunk_address_of_data, POINTER(self.__pe_module.IMAGE_IMPORT_BY_NAME)).contents
            p_thunk_address_of_data.value += 2
            self.assertFileRange(p_thunk_address_of_data.value)
            name = cast(p_thunk_address_of_data, c_char_p)
            contents.append((ibn.Hint, name.value, tmpRVA))
            tmpRVA += sizeof(self.__pe_module.IMAGE_THUNK_DATA)
        return contents

    def __parseCode(self, section, p_bytes, size):
        ibytes = cast(p_bytes, POINTER(c_ubyte * size)).contents
        s = Section('.text', ibytes, section.VirtualAddress + self.imageBase, section.VirtualAddress)
        self.sections[s.name] = s

    def __parseImports(self, section, p_bytes, size):
        ibytes = cast(p_bytes, POINTER(c_ubyte * size)).contents
        s = Section('.idata', ibytes, section.VirtualAddress + self.imageBase, section.VirtualAddress)
        self.sections[s.name] = s
        s.importDescriptorTable = []
        s.importNameTable = []
        s.importAddressTable = []
        s.importHintsAndNames = []
        s.contents = {}
        idataRVA = section.VirtualAddress
        idataFAddr = section.PointerToRawData + self._bytes_p.value
        s.header = section

        while True:

            self.assertFileRange(p_bytes.value)
            importDescriptor = cast(
                p_bytes, POINTER(self.__pe_module.IMAGE_IMPORT_DESCRIPTOR)).contents
            p_bytes.value += sizeof(self.__pe_module.IMAGE_IMPORT_DESCRIPTOR)
            if importDescriptor.OriginalFirstThunk == 0:
                break

            else:
                dllNameAddr = c_void_p(
                    importDescriptor.Name - idataRVA + idataFAddr)
                dllName = cast(dllNameAddr, c_char_p)
                importNameTable = self.__loadThunks(
                    importDescriptor.OriginalFirstThunk - idataRVA + idataFAddr)
                importAddressTable = self.__loadThunks(
                    importDescriptor.FirstThunk - idataRVA + idataFAddr)
                functions = self.__parseThunkContent(
                    importNameTable, idataRVA - idataFAddr, importDescriptor.FirstThunk)
                s.importDescriptorTable.append(ImageImportDescriptorData(
                    struct=importDescriptor, dll=dllName.value, functions=functions, importNameTable=importNameTable, importAddressTable=importAddressTable))

    def __parse(self, p_bytes):
        p_tmp = c_void_p(p_bytes.value)
        self.assertFileRange(p_tmp.value)
        self.imageDosHeader = cast(
            p_tmp, POINTER(self.__pe_module.IMAGE_DOS_HEADER)).contents

        p_tmp.value += self.imageDosHeader.e_lfanew
        self.assertFileRange(p_tmp.value)
        self.imageNtHeaders = cast(
            p_tmp, POINTER(self.__pe_module.IMAGE_NT_HEADERS)).contents

        if self.imageNtHeaders.FileHeader.Machine == IMAGE_FILE_MACHINE.AMD64:
            self.__pe_module = importlib.import_module(
                'ropperapp.loaders.pe_intern.pe64')
            self.imageNtHeaders = cast(
                p_tmp, POINTER(self.__pe_module.IMAGE_NT_HEADERS)).contents
        p_tmp.value += sizeof(self.__pe_module.IMAGE_NT_HEADERS)
        self.__parseSections(p_tmp)
        importVaddr = self.imageNtHeaders.OptionalHeader.DataDirectory[ImageDirectoryEntry.IMPORT].VirtualAddress
        for section in self.sectionHeader:
            if importVaddr > section.VirtualAddress and importVaddr < (section.VirtualAddress + section.SizeOfRawData) :
                p_tmp.value = p_bytes.value + (importVaddr - section.VirtualAddress + section.PointerToRawData)
                size = self.imageNtHeaders.OptionalHeader.DataDirectory[
                    ImageDirectoryEntry.IMPORT].Size
                self.__parseImports(section, p_tmp, size)
                idata = True
            if section.Name == b'.text':
                p_tmp.value = p_bytes.value + section.PointerToRawData
                size = section.PhysicalAddress_or_VirtualSize
                self.__parseCode(section, p_tmp, size)
                textsection = section


    def _parseFile(self):
        self.__pe_module = importlib.import_module('ropperapp.loaders.pe_intern.pe32')
        self.__parse(self._bytes_p)

    def checksec(self):

        return {'SafeSEH' : self.imageNtHeaders.OptionalHeader.DataDirectory[ImageDirectoryEntry.LOAD_CONFIG].Size != 0,
                'ASLR' : self.imageNtHeaders.OptionalHeader.DllCharacteristics & ImageDllCharacteristics.DYNAMIC_BASE != 0,
                'DEP' : self.imageNtHeaders.OptionalHeader.DllCharacteristics & ImageDllCharacteristics.NX_COMPAT != 0}

    @classmethod
    def isSupportedFile(cls, fileName):
        with open(fileName, 'rb') as f:
            return f.read(2) == b'MZ'
