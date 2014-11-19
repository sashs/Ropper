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

from ctypes import *
from ropperapp.loaders.elf_intern.elf_gen import *
from ropperapp.disasm.arch import x86_64


Elf64_Addr = c_ulonglong
Elf64_Off = c_ulonglong
Elf64_Half = c_ushort
Elf64_Word = c_uint
Elf64_Sword = c_int
Elf64_Xword = c_ulonglong
Elf64_Sxword = c_longlong
uchar = c_ubyte

R_SYM = lambda i: i >> 32
R_TYPE = lambda i: i & 0xffffffff


class Ehdr(LittleEndianStructure):
    _fields_ = [('e_ident', uchar * 16),
                ('e_type', Elf64_Half),
                ('e_machine', Elf64_Half),
                ('e_version', Elf64_Word),
                ('e_entry', Elf64_Addr),
                ('e_phoff', Elf64_Off),
                ('e_shoff', Elf64_Off),
                ('e_flags', Elf64_Word),
                ('e_ehsize', Elf64_Half),
                ('e_phentsize', Elf64_Half),
                ('e_phnum', Elf64_Half),
                ('e_shentsize', Elf64_Half),
                ('e_shnum', Elf64_Half),
                ('e_shstrndx', Elf64_Half)
                ]


class Shdr(LittleEndianStructure):
    _fields_ = [('sh_name', Elf64_Word),
                ('sh_type', Elf64_Word),
                ('sh_flags', Elf64_Xword),
                ('sh_addr', Elf64_Addr),
                ('sh_offset', Elf64_Off),
                ('sh_size', Elf64_Xword),
                ('sh_link', Elf64_Word),
                ('sh_info', Elf64_Word),
                ('sh_addralign', Elf64_Xword),
                ('sh_entsize', Elf64_Xword)
                ]


class Sym(LittleEndianStructure):
    _fields_ = [('st_name', Elf64_Word),
                ('st_info', uchar),
                ('st_other', uchar),
                ('st_shndx', Elf64_Half),
                ('st_value', Elf64_Addr),
                ('st_size', Elf64_Xword)
                ]


class Rel(LittleEndianStructure):
    _fields_ = [('r_offset', Elf64_Addr),
                ('r_info', Elf64_Xword)]


class Rela(LittleEndianStructure):
    _fields_ = [('r_offset', Elf64_Addr),
                ('r_info', Elf64_Xword),
                ('r_addend', Elf64_Sxword)
                ]


class Phdr(LittleEndianStructure):
    _fields_ = [('p_type', Elf64_Word),
                ('p_flags', Elf64_Word),
                ('p_offset', Elf64_Off),
                ('p_vaddr', Elf64_Addr),
                ('p_paddr', Elf64_Addr),
                ('p_filesz', Elf64_Xword),
                ('p_memsz', Elf64_Xword),
                ('p_align', Elf64_Xword)
                ]
