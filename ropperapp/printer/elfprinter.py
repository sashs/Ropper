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

from printer import FileDataPrinter
from ropperapp.loaders.elf import *


class ELFPrinter(FileDataPrinter):

    @classmethod
    def validType(cls):
        return Type.ELF

    def printInformations(self, binary):
        ehdr = binary.ehdr
        data = [('Class', ELFCLASS[ehdr.e_ident[EI.CLASS]]),
                ('Machine', EM[ehdr.e_machine]),
                ('Version', ehdr.e_version),
                ('EntryPoint', self._toHex(
                    ehdr.e_entry, int(binary.arch.addressLength) / 8)),
                ('ProgramHeader Offset', ehdr.e_phoff),
                ('SectionHeader Offset', ehdr.e_shoff),
                ('Flags', self._toHex(ehdr.e_flags, int(binary.arch.addressLength) / 8)),
                ('ELF Header Size', ehdr.e_ehsize),
                ('ProgramHeader Size', ehdr.e_phentsize),
                ('ProgramHeader Number', ehdr.e_phnum),
                ('SectionHeader Size', ehdr.e_shentsize),
                ('SectionHeader Number', ehdr.e_shnum)
                ]

        self._printTable('ELF Header', ('Name', 'Value'), data)

    def printSymbols(self, binary):

        for section, symbols in binary.symbols.items():
            data = []
            for idx in range(len(symbols)):
                symbol = symbols[idx]
                data.append(
                    (str(idx), STT[symbol.type], STB[symbol.bind], symbol.name))
            self._printTable('Symbols from %s' %
                             section, ('Nr', 'Type', 'Bind', 'Name'), data)

    def printSections(self, binary):
        data = []
        for index in range(len(binary.shdrs)):
            data.append(('[%.2d]' % index, binary.shdrs[index].name, SHT[
                        binary.shdrs[index].struct.sh_type]))

        self._printTable('Sections', ('Nr', 'Name', 'Type'), data)

    def printSegments(self, elffile):
        phdrs = elffile.phdrs

        data = []
        for phdr in phdrs:
            data.append((PT[phdr.p_type], self._toHex(phdr.p_offset, int(elffile.arch.addressLength)), self._toHex(phdr.p_paddr, int(elffile.arch.addressLength)), self._toHex(
                phdr.p_filesz, int(elffile.arch.addressLength)), self._toHex(phdr.p_memsz, int(elffile.arch.addressLength)), PF.shortString(phdr.p_flags)))

        self._printTable(
            'Segments', ('Type', 'Offset', 'VAddress', 'FileSize', 'MemSize',
                         'Flags'), data)

    def printEntryPoint(self, binary):
        self._printLine(self._toHex(binary.entryPoint, binary.arch.addressLength))

    def printImageBase(self, binary):
        self._printLine(
            self._toHex(binary.imageBase, binary.arch.addressLength))

    def printImports(self, elffile):

        for section, relocs in elffile.relocations.items():
            data = []
            for reloc in relocs:
                data.append((self._toHex(reloc.struct.r_offset, elffile.arch.addressLength), R_386[
                            reloc.type], reloc.symbol.name))
            self._printTable('Relocation section: %s' % section, ('Offset', 'Type',
                                                            'Name'), data)
