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


class VM_PROT(Enum):
    READ = 0x1
    WRITE = 0x2
    EXEC = 0x4

    def shortString(self, perm):
        toReturn = ''
        toReturn += 'R' if perm & int(self.READ) > 0 else ' '
        toReturn += 'W' if perm & int(self.WRITE) > 0 else ' '
        toReturn += 'E' if perm & int(self.EXEC) > 0 else ' '

        return toReturn


class TypeFlags(Enum):
    MASK = 0xff000000
    ABI64 = 0x01000000


class CpuType(Enum):
    ANY = -1
    I386 = 7
    X86_64 = I386 | TypeFlags.ABI64
    MIPS = 8
    ARM = 12
    ARM64 = ARM | TypeFlags.ABI64
    SPARC = 14
    POWERPC = 18
    POWERPC64 = POWERPC | TypeFlags.ABI64
    LC_SEGMENT = 1
    LC_SEMGENT_64 = 0x19
    S_ATTR_SOME_INSTRUCTIONS = 0x400
    S_ATTR_PURE_INSTRUCTIONS = 0x80000000


class SubTypeFlags(Enum):
    MASK = 0xff000000
    LIB64 = 0x80000000


class CPU_SUBTYPE_X86(Enum):
    X86 = 3
    X86_64 = X86 | SubTypeFlags.LIB64
    X86_64_H = 8
    I486 = 4
    I486SX = 0x84
    I586 = 5
    PENTPRO = 0x16
    PENTII_M3 = 0x36
    PENTII_M5 = 0x56
    CELERON = 0x67
    CELERON_MOBILE = 0x77
    PENTIUM_3_M = 0x18
    PENTIUM_3_XEON = 0x28
    PENTIUM_M = 0x09
    PENTIUM_4 = 0x0a
    PENTIUM_4_M = 0x1a
    ITANIUM = 0x0b
    ITANIUM_2 = 0x1b
    XEON = 0x0c
    XEON_MP = 0x1c


class LC(Enum):
    SEGMENT = 0x00000001
    SYMTAB = 0x00000002
    SYMSEG = 0x00000003
    THREAD = 0x00000004
    UNIXTHREAD = 0x00000005
    LOADFVMLIB = 0x00000006
    IDFVMLIB = 0x00000007
    IDENT = 0x00000008
    FVMFILE = 0x00000009
    PREPAGE = 0x0000000A
    DYSYMTAB = 0x0000000B
    LOAD_DYLIB = 0x0000000C
    ID_DYLIB = 0x0000000D
    LOAD_DYLINKER = 0x0000000E
    ID_DYLINKER = 0x0000000F
    PREBOUND_DYLIB = 0x00000010
    ROUTINES = 0x00000011
    SUB_FRAMEWORK = 0x00000012
    SUB_UMBRELLA = 0x00000013
    SUB_CLIENT = 0x00000014
    SUB_LIBRARY = 0x00000015
    TWOLEVEL_HINTS = 0x00000016
    PREBIND_CKSUM = 0x00000017
    LOAD_WEAK_DYLIB = 0x80000018
    SEGMENT_64 = 0x00000019
    ROUTINES_64 = 0x0000001A
    UUID = 0x0000001B
    RPATH = 0x8000001C
    CODE_SIGNATURE = 0x0000001D
    SEGMENT_SPLIT_INFO = 0x0000001E
    REEXPORT_DYLIB = 0x8000001F
    LAZY_LOAD_DYLIB = 0x00000020
    ENCRYPTION_INFO = 0x00000021
    DYLD_INFO = 0x00000022
    DYLD_INFO_ONLY = 0x80000022
    LOAD_UPWARD_DYLIB = 0x80000023
    VERSION_MIN_MACOSX = 0x00000024
    VERSION_MIN_IPHONEOS = 0x00000025
    FUNCTION_STARTS = 0x00000026
    DYLD_ENVIRONMENT = 0x00000027
    MAIN = 0x80000028
    DATA_IN_CODE = 0x00000029
    SOURCE_VERSION = 0x0000002A
    DYLIB_CODE_SIGN_DRS = 0x0000002B
    LINKER_OPTIONS = 0x0000002D
    LINKER_OPTIMIZATION_HINT = 0x0000002E


class S_ATTR(Enum):
    SOME_INSTRUCTIONS = 0x00000400
    PURE_INSTRUCTIONS = 0x80000000


class LoadCommand(LittleEndianStructure):
    _fields_ = [('cmd', c_uint),
                ('cmdsize', c_uint)]


class UuidCommand(LittleEndianStructure):
    _fields_ = [('cmd', c_uint),
                ('cmdsize', c_uint),
                ('uuid', c_ubyte * 16)]


ARCH = {int(CpuType.I386): x86,
        int(CpuType.X86_64): x86_64,
        int(CpuType.POWERPC) : PPC,
        int(CpuType.POWERPC64) : PPC64,
        int(CpuType.ARM) : ARM,
        int(CpuType.ARM64) : ARM64}
