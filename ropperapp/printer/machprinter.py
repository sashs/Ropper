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
from ropperapp.loaders.mach_o import *


class MachOPrinter(FileDataPrinter):

    @classmethod
    def validType(cls):
        return Type.MACH_O

    def printInformations(self, binary):
        hdr = binary.header
        data = [('CPU', CpuType[hdr.cputype]),
                ('Subtype', CPU_SUBTYPE_X86[hdr.cpusubtype]),
                ('Filetype', self._toHex(hdr.filetype)),
                ('Number Of Commands', self._toHex(hdr.ncmds)),
                ('Size of Commands', self._toHex(hdr.sizeofcmds)),
                ('Flags', self._toHex(hdr.flags))]

        self._printTable('Mach-O Header', ('Name', 'Value'), data)

    def printSegments(self, binary):
        lcs = binary.loaderCommands
        data = []

        for lc in lcs:
            lc = lc.struct
            if lc.cmd == LC.SEGMENT or lc.cmd == LC.SEGMENT_64:
                data.append((lc.segname,
                self._toHex(lc.vmaddr, binary.arch.addressLength),
                self._toHex(lc.vmsize),
                self._toHex(lc.fileoff),
                self._toHex(lc.filesize),
                VM_PROT.shortString(lc.maxprot),
                VM_PROT.shortString(lc.initprot)))


        self._printTable('Segment Commands',('Name', 'VAddr', 'VSize', 'FOffset', 'FSize','Maxprot', 'Initprot'), data)

    def printSections(self, binary):
        lcs = binary.loaderCommands
        data = []

        for lc in lcs:
            if lc.struct.cmd == LC.SEGMENT or lc.struct.cmd == LC.SEGMENT_64:
                for section in lc.sections:
                    section = section.struct
                    data.append((section.sectname,
                    section.segname,
                    self._toHex(section.addr, binary.arch.addressLength),
                    self._toHex(section.size),
                    self._toHex(section.offset),
                    self._toHex(section.align),
                    self._toHex(section.nreloc),
                    self._toHex(section.reloff)))

        self._printTable('Sections', ('Name','Segment', 'Address','Size','Offset','Align','Nr. of Relocs','RelocOffset'), data)


    def printLoaderCommands(self, binary):
        lcs = binary.loaderCommands
        data = []

        for lc in lcs:
            lc = lc.struct
            data.append((LC[lc.cmd], self._toHex(lc.cmdsize)))

        self._printTable('Loader Commands', ('Type', 'Size'), data)

    def printEntryPoint(self, binary):
        self._printLine(self._toHex(binary.entryPoint, binary.arch.addressLength))

    def printImageBase(self, binary):
        self._printLine(
            self._toHex(binary.imageBase, binary.arch.addressLength))
