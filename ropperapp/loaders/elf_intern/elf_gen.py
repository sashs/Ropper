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
from ropperapp.disasm.arch import *


class ET(Enum):
    NONE = 0x0
    REL = 0x1
    EXEC = 0x2
    DYN = 0x3
    CORE = 0x4
    LOOS = 0xfe00
    HIOS = 0xfeff
    LOPROC = 0xff00
    HIPROC = 0xffff


class EM(Enum):
    NONE = 0  # No machine
    M32 = 1  # AT&T WE 32100
    SPARC = 2  # SPARC
    INTEL_386 = 3  # Intel 80386
    MOTOROLA_68k = 4  # Motorola 68000
    MOTOROLA_88K = 5  # Motorola 88000
    INTEL_80860 = 7  # Intel 80860
    MIPS = 8  # MIPS RS3000
    S370 = 9
    MIPS_RS3_LE = 10

    PARISC = 15
    VPP500 = 17
    SPARC32PLUS = 18
    INTEL_80960 = 19
    PPC = 20
    PPC64 = 21
    S390 = 22

    V800 = 36
    FR20 = 37
    RH32 = 38
    RCE = 39
    ARM = 40
    FAKE_ALPHA = 41
    SH = 42
    SPARCV9 = 43
    TRICORE = 44
    ARC = 45
    H8_300 = 46
    H8_300H = 47
    H8S = 48
    H8_500 = 49
    IA_64 = 50
    MIPS_X = 51
    COLDFIRE = 52
    MOTOROLA_68HC12 = 53
    MMA = 54
    PCP = 55
    NCPU = 56
    NDR1 = 57
    STARCORE = 58
    ME16 = 59
    ST100 = 60
    TINYJ = 61
    X86_64 = 62
    FX66 = 66
    ST9PLUS = 67
    ST7 = 68
    MOTOROLA_68HC16 = 69
    MOTOROLA_68HC11 = 70
    MOTOROLA_68HC08 = 71
    MOTOROLA_68HC05 = 72
    SVX = 73
    ST19 = 74
    VAX = 75
    CRIS = 76
    JAVELIN = 77
    FIREPATH = 78
    ZSP = 79
    MMIX = 80
    HUANY = 81
    PRISM = 82
    AVR = 83
    FR30 = 84
    D10V = 85
    D30V = 86
    V850 = 87
    M32R = 88
    MN10300 = 89
    MN10200 = 90
    PJ = 91
    OPENRISC = 92
    ARC_A5 = 93
    XTENSA = 94
    NUM = 95
    ARM64 = 183


class EI(Enum):
    MAG3 = 0x0
    MAG3 = 0x1
    MAG3 = 0x2
    MAG3 = 0x3
    CLASS = 0x4
    DATA = 0x5
    VERSION = 0x6
    OSABI = 0x7
    ABIVERSION = 0x8
    PAD = 0x9
    NIDENT = 0xf


class ELFOSABI(Enum):
    SYSV = 0
    HPUX = 1
    STANDALONE = 255


class ELFCLASS(Enum):
    NONE = 0
    BITS_32 = 1
    BITS_64 = 2


class ELFDATA(Enum):
    NONE = 0
    LSB = 1
    MSB = 2


class SHN(Enum):
    UNDEF = 0
    LOPROC = 0xff00
    HIPROC = 0xff1f
    LOOS = 0xff20
    HIOS = 0xff3f
    ABS = 0xfff1
    COMMON = 0xfff2
    HIRESERVE = 0xffff


class SHT(Enum):
    NULL = 0x0
    PROGBITS = 0x1
    SYMTAB = 0x2
    STRTAB = 0x3
    RELA = 0x4
    HASH = 0x5
    DYNAMIC = 0x6
    NOTE = 0x7
    NOBITS = 0x8
    REL = 0x9
    SHLIB = 0xa
    DYNSYM = 0xb
    INIT_ARRAY = 0xe
    FINI_ARRAY = 0xf
    PREINIT_ARRAY = 0x10
    GROUP = 0x11
    SYMTAB_SHNDX = 0x12
    NUM = 0x13
    LOOS = 0x60000000
    GNU_HASH = 0x6ffffff6
    GNU_LIBLIST = 0x6ffffff7
    CHECKSUM = 0x6ffffff8
    LOSUNW = 0x6ffffffa
    SUNW_COMDAT = 0x6ffffffb
    SUNW_syminfo = 0x6ffffffc
    GNU_verdef = 0x6ffffffd
    GNU_verneed = 0x6ffffffe
    HIOS = 0x6fffffff
    LOPROC = 0x70000000
    HIPROC = 0x7fffffff
    LOUSER = 0x80000000
    HIUSER = 0x8fffffff


class STT(Enum):
    _enum_ = 'NOTYPE OBJECT FUNC SECTION FILE COMMON TLS NUM'

    LOOS = 10
    HIOS = 12
    LOPROC = 13
    HIPROC = 15


class STB(Enum):
    _enum_ = 'LOCAL GLOBAL WEAK NUM'

    LOOS = 10
    HIOS = 12
    LOPROC = 13
    HIPROC = 15


class PT(Enum):
    _enum_ = 'NULL LOAD DYNAMIC INTERP NOTE SHLIB PHDR TLS NUM'

    LOPROC = 0x70000000
    HIPROC = 0x7fffffff

    GNU_EH_FRAME = 0x6474e550
    GNU_STACK = 0x6474e551
    GNU_RELRO = 0x6474e552


class R_386(Enum):
    _enum_ = 'NONE R_32 PC32 GOT32 PLT32 COPY GLOB_DAT JMP_SLOT RELATIVE GOTOFF GOTPC PLT32'

    TLS_TPOFF = 14
    TLS_IE = 15
    TLS_GOTIE = 16
    TLS_LE = 17
    TLS_GD = 18
    TLS_LDM = 19
    R16 = 20
    PC16 = 21
    R8 = 22
    PC8 = 23
    TLS_GD_32 = 24
    TLS_GD_PUSH = 25
    TLS_GD_CALL = 26
    TLS_GD_POP = 27
    TLS_LDM_32 = 28
    TLS_LDM_PUSH = 29
    TLS_LDM_CALL = 30
    TLS_LDM_POP = 31
    TLS_LDO_32 = 32
    TLS_IE_32 = 33
    TLS_LE_32 = 34
    TLS_DTPMOD32 = 35
    TLS_DTPOFF32 = 36
    TLS_TPOFF32 = 37
    NUM = 38


class PF(Enum):

    READ = 4
    WRITE = 2
    EXEC = 1

    def shortString(self, perm):
        toReturn = ''
        toReturn += 'R' if perm & int(self.READ) > 0 else ' '
        toReturn += 'W' if perm & int(self.WRITE) > 0 else ' '
        toReturn += 'E' if perm & int(self.EXEC) > 0 else ' '

        return toReturn

def getArch(*params):
    arch = ARCH[params[0]]
    if arch==ARM and (params[1] & 1) == 1:
        return ARMTHUMB
    return arch


ARCH = {(EM.INTEL_386 , ELFCLASS.BITS_32): x86,
        (EM.INTEL_80860, ELFCLASS.BITS_32): x86,
        (EM.IA_64, ELFCLASS.BITS_64): x86_64,
        (EM.X86_64, ELFCLASS.BITS_64): x86_64,
        (EM.MIPS, ELFCLASS.BITS_32): MIPS,
        (EM.MIPS, ELFCLASS.BITS_64): MIPS64,
        (EM.ARM, ELFCLASS.BITS_32) : ARM,
        (EM.ARM64, ELFCLASS.BITS_64) : ARM64,
        (EM.PPC, ELFCLASS.BITS_32) : PPC,
        (EM.PPC, ELFCLASS.BITS_64) : PPC64}
