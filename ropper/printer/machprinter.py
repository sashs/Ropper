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

from ropper.printer.printer import  *
from ropper.loaders.mach_o import *
from filebytes.mach_o import *


class MachOPrinter(FileDataPrinter):

    @classmethod
    def validType(cls):
        return Type.MACH_O

    def printInformation(self, binary):
        hdr = binary._binary.machHeader.header
        data = [(cstr('CPU', Color.BLUE), cstr(CpuType[hdr.cputype], Color.WHITE)),
                (cstr('Subtype', Color.BLUE), cstr(CPU_SUBTYPE_X86[hdr.cpusubtype], Color.WHITE)),
                (cstr('Filetype', Color.BLUE), cstr(self._toHex(hdr.filetype), Color.WHITE)),
                (cstr('Number Of Commands', Color.BLUE), cstr(self._toHex(hdr.ncmds), Color.WHITE)),
                (cstr('Size of Commands', Color.BLUE), cstr(self._toHex(hdr.sizeofcmds), Color.WHITE)),
                (cstr('Flags', Color.BLUE), cstr(self._toHex(hdr.flags), Color.WHITE))]

        self._printTable('Mach-O Header', (cstr('Name', Color.LIGHT_GRAY), cstr('Value', Color.LIGHT_GRAY)), data)

    def printSegments(self, binary):
        lcs = binary._binary.loadCommands
        data = []

        for lc in lcs:
            lc = lc.header
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
        lcs = binary._binary.loadCommands
        data = []

        for lc in lcs:
            if lc.header.cmd == LC.SEGMENT or lc.header.cmd == LC.SEGMENT_64:
                for section in lc.sections:
                    section = section.header
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



    def printLoadCommands(self, binary):
        lcs = binary._binary.loadCommands
        data = []

        for lc in lcs:
            lc = lc.header
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
