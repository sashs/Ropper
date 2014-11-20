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

from ropperapp.printer.printer import  *
from ropperapp.loaders.mach_o import *


class MachOPrinter(FileDataPrinter):

    @classmethod
    def validType(cls):
        return Type.MACH_O

    def printInformations(self, binary):
        hdr = binary.header
        data = [(cstr('CPU', Color.BLUE), cstr(CpuType[hdr.cputype], Color.WHITE)),
                (cstr('Subtype', Color.BLUE), cstr(CPU_SUBTYPE_X86[hdr.cpusubtype], Color.WHITE)),
                (cstr('Filetype', Color.BLUE), cstr(self._toHex(hdr.filetype), Color.WHITE)),
                (cstr('Number Of Commands', Color.BLUE), cstr(self._toHex(hdr.ncmds), Color.WHITE)),
                (cstr('Size of Commands', Color.BLUE), cstr(self._toHex(hdr.sizeofcmds), Color.WHITE)),
                (cstr('Flags', Color.BLUE), cstr(self._toHex(hdr.flags), Color.WHITE))]

        self._printTable('Mach-O Header', (cstr('Name', Color.LIGHT_GRAY), cstr('Value', Color.LIGHT_GRAY)), data)

    def printSegments(self, binary):
        lcs = binary.loaderCommands
        data = []

        for lc in lcs:
            lc = lc.struct
            if lc.cmd == LC.SEGMENT or lc.cmd == LC.SEGMENT_64:
                data.append((cstr(lc.segname, Color.BLUE),
                cstr(self._toHex(lc.vmaddr, binary.arch.addressLength), Color.WHITE),
                cstr(self._toHex(lc.vmsize), Color.LIGHT_GRAY),
                cstr(self._toHex(lc.fileoff), Color.WHITE),
                cstr(self._toHex(lc.filesize), Color.LIGHT_GRAY),
                cstr(VM_PROT.shortString(lc.maxprot), Color.YELLOW),
                cstr(VM_PROT.shortString(lc.initprot), Color.YELLOW)))


        self._printTable('Segment Commands',(cstr('Name', Color.LIGHT_GRAY),
                                            cstr('VAddr', Color.LIGHT_GRAY),
                                            cstr('VSize', Color.LIGHT_GRAY),
                                            cstr('FOffset', Color.LIGHT_GRAY),
                                            cstr('FSize', Color.LIGHT_GRAY),
                                            cstr('Maxprot', Color.LIGHT_GRAY),
                                            cstr('Initprot', Color.LIGHT_GRAY)), data)

    def printSections(self, binary):
        lcs = binary.loaderCommands
        data = []

        for lc in lcs:
            if lc.struct.cmd == LC.SEGMENT or lc.struct.cmd == LC.SEGMENT_64:
                for section in lc.sections:
                    section = section.struct
                    data.append((cstr(section.sectname, Color.BLUE),
                    cstr(section.segname, Color.WHITE),
                    cstr(self._toHex(section.addr, binary.arch.addressLength), Color.LIGHT_GRAY),
                    cstr(self._toHex(section.size), Color.WHITE),
                    cstr(self._toHex(section.offset), Color.LIGHT_GRAY),
                    cstr(self._toHex(section.align), Color.WHITE),
                    cstr(self._toHex(section.nreloc), Color.LIGHT_GRAY),
                    cstr(self._toHex(section.reloff), Color.WHITE)))

        self._printTable('Sections', (cstr('Name', Color.LIGHT_GRAY),
                                    cstr('Segment', Color.LIGHT_GRAY),
                                    cstr('Address', Color.LIGHT_GRAY),
                                    cstr('Size', Color.LIGHT_GRAY),
                                    cstr('Offset', Color.LIGHT_GRAY),
                                    cstr('Align', Color.LIGHT_GRAY),
                                    cstr('Nr. of Relocs', Color.LIGHT_GRAY),
                                    cstr('RelocOffset', Color.LIGHT_GRAY)),
                                    data)



    def printLoaderCommands(self, binary):
        lcs = binary.loaderCommands
        data = []

        for lc in lcs:
            lc = lc.struct
            data.append((cstr(LC[lc.cmd], Color.BLUE), cstr(self._toHex(lc.cmdsize), Color.WHITE)))

        self._printTable('Loader Commands', (cstr('Type', Color.LIGHT_GRAY), cstr('Size', Color.LIGHT_GRAY)), data)

    def printEntryPoint(self, binary):
        self._printLine(self._toHex(binary.entryPoint, binary.arch.addressLength))

    def printImageBase(self, binary):
        self._printLine(
            self._toHex(binary.imageBase, binary.arch.addressLength))

    def printArchitecture(self, binary):
        self._printLine(str(binary.arch))

    def printFileType(self, binary):
        self._printLine(str(binary.type))
