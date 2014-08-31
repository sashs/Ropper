from printer import FileDataPrinter
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
        data = [
            ('Characteristics', self._toHex(
                pefile.imageNtHeaders.FileHeader.Characteristics)),
            ('Machine', IMAGE_FILE_MACHINE[
             pefile.imageNtHeaders.FileHeader.Machine]),
            ('NumberOfSections', (
                pefile.imageNtHeaders.FileHeader.NumberOfSections)),
            ('PointerToSymbolTable', self._toHex(
                pefile.imageNtHeaders.FileHeader.PointerToSymbolTable)),
            ('SizeOfOptionalHeader', (
                pefile.imageNtHeaders.FileHeader.SizeOfOptionalHeader)),
            ('TimeDateStamp', (
                datetime.datetime.fromtimestamp(
                    pefile.imageNtHeaders.FileHeader.TimeDateStamp
                ).strftime('%Y-%m-%d %H:%M:%S')))
        ]

        self._printTable('Image Headers', ('Name', 'Value'), data)

    def __printOptionalHeaders(self, pefile):

        data = [
            ('AddressOfEntryPoint', self._toHex(
                pefile.imageNtHeaders.OptionalHeader.AddressOfEntryPoint)),
            ('BaseOfCode', self._toHex(pefile.imageNtHeaders.OptionalHeader.BaseOfCode)),
            ('CheckSum', self._toHex(pefile.imageNtHeaders.OptionalHeader.CheckSum)),
            ('DllCharacteristics', self._toHex(
                pefile.imageNtHeaders.OptionalHeader.DllCharacteristics)),
            ('FileAlignment', self._toHex(
                pefile.imageNtHeaders.OptionalHeader.FileAlignment)),
            ('ImageBase', hex(pefile.imageNtHeaders.OptionalHeader.ImageBase)),
            ('LoaderFlags', self._toHex(
                pefile.imageNtHeaders.OptionalHeader.LoaderFlags)),
            ('Magic', self._toHex(pefile.imageNtHeaders.OptionalHeader.Magic)),
            ('MajorImageVersion', self._toHex(
                pefile.imageNtHeaders.OptionalHeader.MajorImageVersion)),
            ('MajorLinkerVersion', self._toHex(
                pefile.imageNtHeaders.OptionalHeader.MajorLinkerVersion)),
            ('MajorOperatingSystemVersion', self._toHex(
                pefile.imageNtHeaders.OptionalHeader.MajorOperatingSystemVersion)),
            ('MajorSubsystemVersion', self._toHex(
                pefile.imageNtHeaders.OptionalHeader.MajorSubsystemVersion)),
            ('MinorImageVersion', self._toHex(
                pefile.imageNtHeaders.OptionalHeader.MinorImageVersion)),
            ('NumberOfRvaAndSizes', self._toHex(
                pefile.imageNtHeaders.OptionalHeader.NumberOfRvaAndSizes)),
            ('SectionAlignment', self._toHex(
                pefile.imageNtHeaders.OptionalHeader.SectionAlignment)),
            ('SizeOfCode', self._toHex(pefile.imageNtHeaders.OptionalHeader.SizeOfCode)),
            ('SizeOfHeaders', self._toHex(
                pefile.imageNtHeaders.OptionalHeader.SizeOfHeaders)),
            ('SizeOfHeapCommit', self._toHex(
                pefile.imageNtHeaders.OptionalHeader.SizeOfHeapCommit)),
            ('SizeOfHeapReserve', self._toHex(
                pefile.imageNtHeaders.OptionalHeader.SizeOfHeapReserve)),
            ('SizeOfImage', self._toHex(
                pefile.imageNtHeaders.OptionalHeader.SizeOfImage)),
            ('SizeOfInitializedData', self._toHex(
                pefile.imageNtHeaders.OptionalHeader.SizeOfInitializedData)),
            ('SizeOfStackCommit', self._toHex(
                pefile.imageNtHeaders.OptionalHeader.SizeOfStackCommit)),
            ('SizeOfStackReserve', self._toHex(
                pefile.imageNtHeaders.OptionalHeader.SizeOfStackReserve)),
            ('SizeOfUninitializedData', self._toHex(
                pefile.imageNtHeaders.OptionalHeader.SizeOfUninitializedData)),
            ('Subsystem', self._toHex(pefile.imageNtHeaders.OptionalHeader.Subsystem)),
            ('Win32VersionValue', self._toHex(
                pefile.imageNtHeaders.OptionalHeader.Win32VersionValue))
        ]

        self._printTable('Image Optional Headers', ('Name', 'Value'), data)

    def printDllCharacteristics(self, pefile):
        dllc = pefile.imageNtHeaders.OptionalHeader.DllCharacteristics

        data = [
            ('DynamicBase', 'Yes' if (
                dllc & ImageDllCharacteristics.DYNAMIC_BASE) > 0 else 'No'),
            ('ForceIntegrity', 'Yes' if (
                dllc & ImageDllCharacteristics.FORCE_INTEGRITY) > 0 else 'No'),
            ('NxCompat', 'Yes' if (
                dllc & ImageDllCharacteristics.NX_COMPAT) > 0 else 'No'),
            ('No Isolation', 'Yes' if (
                dllc & ImageDllCharacteristics.NO_ISOLATION) > 0 else 'No'),
            ('No SEH', 'Yes' if (dllc & ImageDllCharacteristics.NO_SEH)
             > 0 else 'No'),
            ('No Bind', 'Yes' if (dllc & ImageDllCharacteristics.NO_BIND)
             > 0 else 'No'),
            ('WdmDriver', 'Yes' if (
                dllc & ImageDllCharacteristics.WDM_DRIVER) > 0 else 'No'),
            ('TerminalServerAware', 'Yes' if (
                dllc & ImageDllCharacteristics.TERMINAL_SERVER_AWARE) > 0 else 'No')
        ]

        self._printTable('DllCharacteristics', ('Name', 'Value'), data)

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
                    data.append((descriptorData.dll, self._toHex(
                        pefile.imageNtHeaders.OptionalHeader.ImageBase + function[2]), hex(function[0]), function[1]))

            self._printTable(
                'Imports', ('DLL', 'Address', 'Hint', 'Function'), data)
        else:
            print('No imports!')
