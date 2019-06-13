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
from ropper.printer.printer import *
from ropper.loaders.pe import *
from filebytes.pe import *
import datetime


class PEPrinter(FileDataPrinter):

    @classmethod
    def validType(cls):
        return Type.PE

    def printInformation(self, binary):

        self.__printImageHeaders(binary)
        self.__printOptionalHeaders(binary)

    def __printImageHeaders(self, pefile):
        fh = pefile._binary.imageNtHeaders.header.FileHeader
        data = [
            (cstr('Characteristics', Color.BLUE),
                cstr(self._toHex(fh.Characteristics), Color.WHITE)),
            (cstr('Machine', Color.BLUE),
                cstr(pe.IMAGE_FILE_MACHINE[fh.Machine], Color.WHITE)),
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
        oh = pefile._binary.imageNtHeaders.header.OptionalHeader
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
        dllc = pefile._binary.imageNtHeaders.header.OptionalHeader.DllCharacteristics
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
            (cstr('ControlFLowGuard', Color.BLUE), yes if (
                dllc & ImageDllCharacteristics.CONTROL_FLOW_GUARD) > 0 else no),
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
        imports = pefile._binary.dataDirectory[pe.ImageDirectoryEntry.IMPORT]
        if imports:
            data = []
            for descriptorData in imports:
                for function in descriptorData.importAddressTable:
                    if function.ordinal:
                        data.append((cstr(descriptorData.dllName, Color.BLUE),
                                cstr(self._toHex(pefile._binary.imageBase + function.rva,pefile.arch.addressLength), Color.CYAN),
                                cstr(hex(function.ordinal), Color.LIGHT_GRAY),
                                cstr('', Color.WHITE)))
                    else:
                        data.append((cstr(descriptorData.dllName, Color.BLUE),
                                cstr(self._toHex(pefile._binary.imageBase+function.rva,pefile.arch.addressLength), Color.CYAN),
                                cstr(hex(function.importByName.hint) if function.importByName else '', Color.LIGHT_GRAY),
                                cstr(function.importByName.name if function.importByName else '', Color.WHITE)))

            self._printTable(
                'Imports', (cstr('DLL', Color.LIGHT_GRAY), cstr('Address', Color.LIGHT_GRAY), cstr('Hint/Ordinal', Color.LIGHT_GRAY), cstr('Function', Color.LIGHT_GRAY)), data)
        else:
            print('No imports!')

    def printSections(self, pefile):

        data = []
        for section in pefile._binary.sections:
            data.append((cstr(section.header.Name, Color.BLUE),
                        cstr(self._toHex(section.header.VirtualAddress,pefile.arch.addressLength), Color.CYAN),
                        cstr(self._toHex(section.header.SizeOfRawData), Color.LIGHT_GRAY),
                        cstr(self._toHex(section.header.PointerToRawData,pefile.arch.addressLength), Color.WHITE),
                        cstr(self._toHex(section.header.PointerToRelocations,pefile.arch.addressLength), Color.LIGHT_GRAY),
                        cstr(self._toHex(section.header.NumberOfRelocations), Color.WHITE),))

        self._printTable(
            'Section Header', (cstr('Name', Color.LIGHT_GRAY), cstr('VAddr', Color.LIGHT_GRAY), cstr('RawDataSize', Color.LIGHT_GRAY), cstr('RawDataPtr', Color.LIGHT_GRAY), cstr('RelocPtr', Color.LIGHT_GRAY), cstr('NrOfReloc', Color.LIGHT_GRAY)), data)


    def printArchitecture(self, binary):
        self._printLine(str(binary.arch))

    def printFileType(self, binary):
        self._printLine(str(binary.type))
