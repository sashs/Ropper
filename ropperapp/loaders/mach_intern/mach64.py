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



class MachHeader(LittleEndianStructure):
    _fields_ = [('magic', c_uint),
                ('cputype', c_uint),
                ('cpusubtype', c_uint),
                ('filetype', c_uint),
                ('ncmds', c_uint),
                ('sizeofcmds', c_uint),
                ('flags', c_uint),
                ('reserved', c_uint),
                ]


class SegmentCommand(LittleEndianStructure):
    _fields_ = [('cmd', c_uint),
                ('cmdsize', c_uint),
                ('segname', c_char * 16),
                ('vmaddr', c_ulonglong),
                ('vmsize', c_ulonglong),
                ('fileoff', c_ulonglong),
                ('filesize', c_ulonglong),
                ('maxprot', c_uint),
                ('initprot', c_uint),
                ('nsects', c_uint),
                ('flags', c_uint)]


class Section(LittleEndianStructure):
    _fields_ = [('sectname', c_char * 16),
                ('segname', c_char * 16),
                ('addr', c_ulonglong),
                ('size', c_ulonglong),
                ('offset', c_uint),
                ('align', c_uint),
                ('reloff', c_uint),
                ('nreloc', c_uint),
                ('flags', c_uint),
                ('reserved1', c_uint),
                ('reserved2', c_uint)
    ]

class TwoLevelHintsCommand(LittleEndianStructure):
    _fields_ = [('cmd', c_uint),
                ('cmdsize', c_uint),
                ('offset', c_uint),
                ('nhints', c_uint)]

class TwoLevelHint(LittleEndianStructure):
    _fields_ = [('isub_image', c_uint),
                ('itoc', c_uint)]

class LcStr(Union):
    _fields_ = [('offset', c_uint)]
