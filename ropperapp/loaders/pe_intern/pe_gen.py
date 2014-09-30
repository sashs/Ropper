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

from ropperapp.common.enum import Enum
from ctypes import *
from ropperapp.disasm.arch import *


class IMAGE_FILE_MACHINE(Enum):
    UKNOWN = 0
    AM33 = 0x1d3
    AMD64 = 0x8664
    ARM = 0x1c0
    ARMV = 0x1c4
    EBC = 0xebc
    I386 = 0x14c
    IA64 = 0x200
    M32R = 0x9041
    MIPS16 = 0x266
    MIPSFPU = 0x366
    MIPSFPU16 = 0x466
    POWERPC = 0x1f0
    POWERPCFP = 0x1f1
    THUMB = 0x1c2
    WCEMIPSV2 = 0x169

class IMAGE_SCN(Enum):
    TYPE_NO_PAD = 0x00000008
    CNT_CODE = 0x00000020
    CNT_INITIALIZED_DATA = 0x00000040
    CNT_UNINITIALIZED_DATA = 0x00000080
    LNK_OTHER = 0x00000100
    LNK_INFO = 0x00000200
    LNK_REMOVE = 0x00000800
    LNK_COMDAT = 0x00001000
    GPREL = 0x00008000
    MEM_PURGEABLE = 0x00020000
    MEM_LOCKED = 0x00040000
    MEM_PRELOAD = 0x00080000
    ALIGN_1BYTES = 0x00100000
    ALIGN_2BYTES = 0x00200000
    ALIGN_4BYTES = 0x00300000
    ALIGN_8BYTES = 0x00400000
    ALIGN_16BYTES = 0x00500000
    ALIGN_32BYTES = 0x00600000
    ALIGN_64BYTES = 0x00700000
    ALIGN_128BYTES = 0x00800000
    ALIGN_256BYTES = 0x00900000
    ALIGN_512BYTES = 0x00A00000
    ALIGN_1024BYTES = 0x00B00000
    ALIGN_2048BYTES = 0x00C00000
    ALIGN_4096BYTES = 0x00D00000
    ALIGN_8192BYTES = 0x00E00000
    LNK_NRELOC_OVFL = 0x01000000



class ImageDllCharacteristics(Enum):
    DYNAMIC_BASE = 0x0040
    FORCE_INTEGRITY = 0x0080
    NX_COMPAT = 0x0100
    NO_ISOLATION = 0x0200
    NO_SEH = 0x0400
    NO_BIND = 0x0800
    WDM_DRIVER = 0x2000
    TERMINAL_SERVER_AWARE = 0x8000

def getArch(*params):
    return ARCH[params[0]] 

ARCH = {int(IMAGE_FILE_MACHINE.AMD64):
        x86_64, int(IMAGE_FILE_MACHINE.I386): x86,
        int(IMAGE_FILE_MACHINE.ARM) : ARM,
        int(IMAGE_FILE_MACHINE.ARMV) : ARMTHUMB}


class ImageDirectoryEntry(Enum):
    _enum_ = ('EXPORT',
              'IMPORT',
              'RESOURCE',
              'EXCEPTION',
              'SECURITY',
              'BASERELOC',
              'DEBUG',
              'COPYRIGHT',
              'GLOBALPTR',
              'TLS',
              'LOAD_CONFIG',
              'BOUND_IMPORT',
              'IAT',
              'DELAY_IMPORT',
              'COM_DESCRIPTOR')

    NUMBEROF_DIRECTORY_ENTRIES = 16


class IMAGE_DOS_HEADER(Structure):
    _fields_ = [('e_magic', c_char * 2),
                ('e_cblp', c_ushort),
                ('e_cp', c_ushort),
                ('e_crlc', c_ushort),
                ('e_cparhdr', c_ushort),
                ('e_minalloc', c_ushort),
                ('e_maxalloc', c_ushort),
                ('e_ss', c_ushort),
                ('e_sp', c_ushort),
                ('e_csum', c_ushort),
                ('e_ip', c_ushort),
                ('e_cs', c_ushort),
                ('e_lfarlc', c_ushort),
                ('e_ovno', c_ushort),
                ('e_res', c_ushort * 4),
                ('e_oemid', c_ushort),
                ('e_oeminfo', c_ushort),
                ('e_res2', c_ushort * 10),
                ('e_lfanew', c_uint)]       # Offset zum PE-Header


class IMAGE_FILE_HEADER(Structure):
    _fields_ = [('Machine', c_ushort),
                ('NumberOfSections', c_ushort),
                ('TimeDateStamp', c_uint),
                ('PointerToSymbolTable', c_uint),
                ('NumberOfSymbols', c_uint),
                ('SizeOfOptionalHeader', c_ushort),
                ('Characteristics', c_ushort)
                ]


class IMAGE_DATA_DIRECTORY(Structure):
    _fields_ = [('VirtualAddress', c_uint),
                ('Size', c_uint)]


class IMAGE_SECTION_HEADER(Structure):
    _fields_ = [('Name', c_char * 8),
                ('PhysicalAddress_or_VirtualSize', c_uint),
                ('VirtualAddress', c_uint),
                ('SizeOfRawData', c_uint),
                ('PointerToRawData', c_uint),
                ('PointerToRelocations', c_uint),
                ('PointerToLinenumbers', c_uint),
                ('NumberOfRelocations', c_ushort),
                ('NumberOfLinenumbers', c_ushort),
                ('Characteristics', c_uint)]


class IMAGE_IMPORT_BY_NAME(Structure):
    _fields_ = [('Hint', c_ushort),
                ('Name', c_char)]


class IMAGE_THUNK_DATA(Union):
    _fields_ = [('ForwarderString', c_uint),
                ('Function', c_uint),
                ('Ordinal', c_uint),
                ('AddressOfData', c_uint)]


class IMAGE_IMPORT_DESCRIPTOR(Structure):
    _fields_ = [('OriginalFirstThunk', c_uint),
                ('TimeDateStamp', c_uint),
                ('ForwarderChain', c_uint),
                ('Name', c_uint),
                ('FirstThunk', c_uint)]
