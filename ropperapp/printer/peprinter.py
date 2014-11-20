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

from ropperapp.printer.printer import *
from ropperapp.loaders.pe import *
import datetime


class PEPrinter(FileDataPrinter):

    @classmethod
    def validType(cls):
        return Type.PE

    def printInformations(self, binary):

        self.__printImageHeaders(binary)
        self.__printOptionalHeaders(binary)

    def __printImageHeaders(self, pefile):
        fh = pefile.imageNtHeaders.FileHeader
        data = [
            (cstr('Characteristics', Color.BLUE),
                cstr(self._toHex(fh.Characteristics), Color.WHITE)),
            (cstr('Machine', Color.BLUE),
                cstr(IMAGE_FILE_MACHINE[fh.Machine], Color.WHITE)),
            (cstr('NumberOfSections', Color.BLUE),
                cstr((fh.NumberOfSections), Color.WHITE)),
            (cstr('PointerToSymbolTable', Color.BLUE),
                cstr(self._toHex(fh.PointerToSymbolTable, pefile.arch.addressLength), Color.WHITE)),
            (cstr('SizeOfOptionalHeader', Color.BLUE),
                cstr((fh.SizeOfOptionalHeader), Color.WHITE)),
            (cstr('TimeDateStamp', Color.BLUE),
                cstr((datetime.datetime.fromtimestamp(
                    fh.TimeDateStamp
                    ).strftime('%Y-%m-%d %H:%M:%S')), Color.WHITE))
        ]

        self._printTable('Image Headers', (cstr('Name',Color.LIGHT_GRAY), cstr('Value',Color.LIGHT_GRAY)), data)

    def __printOptionalHeaders(self, pefile):
        oh = pefile.imageNtHeaders.OptionalHeader
        addressLength = pefile.arch.addressLength
        data = [
            (cstr('AddressOfEntryPoint', Color.BLUE),
                cstr(self._toHex(oh.AddressOfEntryPoint, addressLength), Color.WHITE)),
            (cstr('BaseOfCode', Color.BLUE),
                cstr(self._toHex(oh.BaseOfCode, addressLength), Color.WHITE)),
            (cstr('CheckSum', Color.BLUE),
                cstr(self._toHex(oh.CheckSum,4), Color.WHITE)),
            (cstr('DllCharacteristics', Color.BLUE),
                cstr(self._toHex(oh.DllCharacteristics,2), Color.WHITE)),
            (cstr('FileAlignment', Color.BLUE),
                cstr(self._toHex(oh.FileAlignment,4), Color.WHITE)),
            (cstr('ImageBase', Color.BLUE),
                cstr(self._toHex(oh.ImageBase, addressLength), Color.WHITE)),
            (cstr('LoaderFlags', Color.BLUE),
                cstr(self._toHex(oh.LoaderFlags,4), Color.WHITE)),
            (cstr('Magic', Color.BLUE),
                cstr(self._toHex(oh.Magic,4), Color.WHITE)),
            (cstr('MajorImageVersion', Color.BLUE),
                cstr(self._toHex(oh.MajorImageVersion,2), Color.WHITE)),
            (cstr('MajorLinkerVersion', Color.BLUE),
                cstr(self._toHex(oh.MajorLinkerVersion,2), Color.WHITE)),
            (cstr('MajorOperatingSystemVersion', Color.BLUE),
                cstr(self._toHex(oh.MajorOperatingSystemVersion,2), Color.WHITE)),
            (cstr('MajorSubsystemVersion', Color.BLUE),
                cstr(self._toHex(oh.MajorSubsystemVersion,2), Color.WHITE)),
            (cstr('MinorImageVersion', Color.BLUE),
                cstr(self._toHex(oh.MinorImageVersion,2), Color.WHITE)),
            (cstr('NumberOfRvaAndSizes', Color.BLUE),
                cstr(self._toHex(oh.NumberOfRvaAndSizes,4), Color.WHITE)),
            (cstr('SectionAlignment', Color.BLUE),
                cstr(self._toHex(oh.SectionAlignment,4), Color.WHITE)),
            (cstr('SizeOfCode', Color.BLUE),
                cstr(self._toHex(oh.SizeOfCode,4), Color.WHITE)),
            (cstr('SizeOfHeaders', Color.BLUE),
                cstr(self._toHex(oh.SizeOfHeaders,4), Color.WHITE)),
            (cstr('SizeOfHeapCommit', Color.BLUE),
                cstr(self._toHex(oh.SizeOfHeapCommit,4), Color.WHITE)),
            (cstr('SizeOfHeapReserve', Color.BLUE),
                cstr(self._toHex(oh.SizeOfHeapReserve,4), Color.WHITE)),
            (cstr('SizeOfImage', Color.BLUE),
                cstr(self._toHex(oh.SizeOfImage,4), Color.WHITE)),
            (cstr('SizeOfInitializedData', Color.BLUE),
                cstr(self._toHex(oh.SizeOfInitializedData,4), Color.WHITE)),
            (cstr('SizeOfStackCommit', Color.BLUE),
                cstr(self._toHex(oh.SizeOfStackCommit,4), Color.WHITE)),
            (cstr('SizeOfStackReserve', Color.BLUE),
                cstr(self._toHex(oh.SizeOfStackReserve,4), Color.WHITE)),
            (cstr('SizeOfUninitializedData', Color.BLUE),
                cstr(self._toHex(oh.SizeOfUninitializedData,4), Color.WHITE)),
            (cstr('Subsystem', Color.BLUE),
                cstr(self._toHex(oh.Subsystem,4), Color.WHITE)),
            (cstr('Win32VersionValue', Color.BLUE),
                cstr(self._toHex(oh.Win32VersionValue,4), Color.WHITE))
        ]

        self._printTable('Image Optional Headers', (cstr('Name', Color.LIGHT_GRAY), cstr('Value',Color.LIGHT_GRAY)), data)

    def printDllCharacteristics(self, pefile):
        dllc = pefile.imageNtHeaders.OptionalHeader.DllCharacteristics
        yes = cstr('Yes', Color.YELLOW)
        no = cstr('NO', Color.GREEN)
        data = [
            (cstr('DynamicBase', Color.BLUE), yes if (
                dllc & ImageDllCharacteristics.DYNAMIC_BASE) > 0 else no),
            (cstr('ForceIntegrity', Color.BLUE), yes if (
                dllc & ImageDllCharacteristics.FORCE_INTEGRITY) > 0 else no),
            (cstr('NxCompat', Color.BLUE), yes if (
                dllc & ImageDllCharacteristics.NX_COMPAT) > 0 else no),
            (cstr('No Isolation', Color.BLUE), yes if (
                dllc & ImageDllCharacteristics.NO_ISOLATION) > 0 else no),
            (cstr('No SEH', Color.BLUE), yes if (dllc & ImageDllCharacteristics.NO_SEH)
             > 0 else no),
            (cstr('No Bind', Color.BLUE), yes if (dllc & ImageDllCharacteristics.NO_BIND)
             > 0 else no),
            (cstr('WdmDriver', Color.BLUE), yes if (
                dllc & ImageDllCharacteristics.WDM_DRIVER) > 0 else no),
            (cstr('TerminalServerAware', Color.BLUE), yes if (
                dllc & ImageDllCharacteristics.TERMINAL_SERVER_AWARE) > 0 else no)
        ]

        self._printTable('DllCharacteristics', (cstr('Name', Color.LIGHT_GRAY), cstr('Value', Color.LIGHT_GRAY)), data)

    def printEntryPoint(self, binary):
        self._printLine(self._toHex(binary.entryPoint, binary.arch.addressLength))

    def printImageBase(self, binary):
        self._printLine(
            self._toHex(binary.imageBase, binary.arch.addressLength))

    def printImports(self, pefile):
        if '.idata' in pefile.sections:
            s = pefile.sections['.idata']
            data = []
            for descriptorData in s.importDescriptorTable:
                for function in descriptorData.functions:
                    data.append((cstr(descriptorData.dll, Color.BLUE),
                                cstr(self._toHex(pefile.imageNtHeaders.OptionalHeader.ImageBase + function[2],pefile.arch.addressLength), Color.CYAN),
                                cstr(hex(function[0]), Color.LIGHT_GRAY),
                                cstr(function[1], Color.WHITE)))

            self._printTable(
                'Imports', (cstr('DLL', Color.LIGHT_GRAY), cstr('Address', Color.LIGHT_GRAY), cstr('Hint/Ordinal', Color.LIGHT_GRAY), cstr('Function', Color.LIGHT_GRAY)), data)
        else:
            print('No imports!')

    def printSections(self, pefile):

        data = []
        for section in pefile.sectionHeader:
            data.append((cstr(section.Name, Color.BLUE),
                        cstr(self._toHex(section.VirtualAddress,pefile.arch.addressLength), Color.CYAN),
                        cstr(self._toHex(section.SizeOfRawData), Color.LIGHT_GRAY),
                        cstr(self._toHex(section.PointerToRawData,pefile.arch.addressLength), Color.WHITE),
                        cstr(self._toHex(section.PointerToRelocations,pefile.arch.addressLength), Color.LIGHT_GRAY),
                        cstr(self._toHex(section.NumberOfRelocations), Color.WHITE),))

        self._printTable(
            'Section Header', (cstr('Name', Color.LIGHT_GRAY), cstr('VAddr', Color.LIGHT_GRAY), cstr('RawDataSize', Color.LIGHT_GRAY), cstr('RawDataPtr', Color.LIGHT_GRAY), cstr('RelocPtr', Color.LIGHT_GRAY), cstr('NrOfReloc', Color.LIGHT_GRAY)), data)


    def printArchitecture(self, binary):
        self._printLine(str(binary.arch))

    def printFileType(self, binary):
        self._printLine(str(binary.type))
