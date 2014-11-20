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

from ropperapp.loaders.pe_intern.pe_gen import *



class IMAGE_OPTIONAL_HEADER(Structure):
    _fields_ = [('Magic', c_ushort),
                ('MajorLinkerVersion', c_byte),
                ('MinorLinkerVersion', c_byte),
                ('SizeOfCode', c_uint),
                ('SizeOfInitializedData', c_uint),
                ('SizeOfUninitializedData', c_uint),
                ('AddressOfEntryPoint', c_uint),
                ('BaseOfCode', c_uint),
                ('BaseOfData', c_uint),
                ('ImageBase', c_uint),
                ('SectionAlignment', c_uint),
                ('FileAlignment', c_uint),
                ('MajorOperatingSystemVersion', c_ushort),
                ('MinorOperatingSystemVersion', c_ushort),
                ('MajorImageVersion', c_ushort),
                ('MinorImageVersion', c_ushort),
                ('MajorSubsystemVersion', c_ushort),
                ('MinorSubsystemVersion', c_ushort),
                ('Win32VersionValue', c_uint),
                ('SizeOfImage', c_uint),
                ('SizeOfHeaders', c_uint),
                ('CheckSum', c_uint),
                ('Subsystem', c_ushort),
                ('DllCharacteristics', c_ushort),
                ('SizeOfStackReserve', c_uint),
                ('SizeOfStackCommit', c_uint),
                ('SizeOfHeapReserve', c_uint),
                ('SizeOfHeapCommit', c_uint),
                ('LoaderFlags', c_uint),
                ('NumberOfRvaAndSizes', c_uint),
                ('DataDirectory', IMAGE_DATA_DIRECTORY * 16)]


class IMAGE_NT_HEADERS(Structure):
    _fields_ = [('Signature', c_char * 4),
                ('FileHeader', IMAGE_FILE_HEADER),
                ('OptionalHeader', IMAGE_OPTIONAL_HEADER)]
