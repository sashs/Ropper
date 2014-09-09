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


    def printEntryPoint(self, binary):
        self._printLine(self._toHex(binary.entryPoint, binary.arch.addressLength))

    def printImageBase(self, binary):
        self._printLine(
            self._toHex(binary.imageBase, binary.arch.addressLength))
