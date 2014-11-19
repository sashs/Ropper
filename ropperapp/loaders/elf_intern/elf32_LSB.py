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
from ropperapp.disasm.arch import x86


R_SYM = lambda i: i >> 8
R_TYPE = lambda i: i & 0xff


class Ehdr(LittleEndianStructure):
    _fields_ = [('e_ident', c_ubyte * 16),
                ('e_type', c_ushort),
                ('e_machine', c_ushort),
                ('e_version', c_uint),
                ('e_entry', c_uint),
                ('e_phoff', c_uint),
                ('e_shoff', c_uint),
                ('e_flags', c_uint),
                ('e_ehsize', c_ushort),
                ('e_phentsize', c_ushort),
                ('e_phnum', c_ushort),
                ('e_shentsize', c_ushort),
                ('e_shnum', c_ushort),
                ('e_shstrndx', c_ushort)]


class Shdr(LittleEndianStructure):
    _fields_ = [('sh_name', c_uint),
                ('sh_type', c_uint),
                ('sh_flags', c_uint),
                ('sh_addr', c_uint),
                ('sh_offset', c_uint),
                ('sh_size', c_uint),
                ('sh_link', c_uint),
                ('sh_info', c_uint),
                ('sh_addralign', c_uint),
                ('sh_entsize', c_uint)
                ]


class Sym(LittleEndianStructure):
    _fields_ = [('st_name', c_uint),
                ('st_value', c_uint),
                ('st_size', c_uint),
                ('st_info', c_ubyte),
                ('st_other', c_ubyte),
                ('st_shndx', c_ushort)
                ]


class Rel(LittleEndianStructure):
    _fields_ = [('r_offset', c_uint),
                ('r_info', c_uint)]


class Rela(LittleEndianStructure):
    _fields_ = [('r_offset', c_uint),
                ('r_info', c_uint),
                ('r_addend', c_int)
                ]


class Phdr(LittleEndianStructure):
    _fields_ = [('p_type', c_uint),
                ('p_offset', c_uint),
                ('p_vaddr', c_uint),
                ('p_paddr', c_uint),
                ('p_filesz', c_uint),
                ('p_memsz', c_uint),
                ('p_flags', c_uint),
                ('p_align', c_uint)
                ]
