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

from ropperapp.common.abstract import *
from re import compile
from capstone import *
from . import gadget


class Architecture(AbstractSingleton):

    def __init__(self, arch, mode, addressLength, align):
        super(Architecture, self).__init__()

        self._arch = arch
        self._mode = mode

        self._addressLength = addressLength
        self._align = align

        self._endings = {}
        self._badInstructions = []

        self._initGadgets()
        self._initBadInstructions()

        self._endings[gadget.GadgetType.ALL] = self._endings[
            gadget.GadgetType.ROP] + self._endings[gadget.GadgetType.JOP]

    def _initGadgets(self):
        pass

    def _initBadInstructions(self):
        pass

    @property
    def arch(self):
        return self._arch

    @property
    def align(self):
        return self._align

    @property
    def mode(self):
        return self._mode

    @property
    def addressLength(self):
        return self._addressLength

    @property
    def endings(self):
        return self._endings

    @property
    def badInstructions(self):
        return self._badInstructions


class ArchitectureX86(Architecture):

    def __init__(self):
        Architecture.__init__(self, CS_ARCH_X86, CS_MODE_32, 4, 1)

    def _initGadgets(self):
        self._endings[gadget.GadgetType.ROP] = [('\xc3', 1),
                                                ('\xc2[\x00-\xff]{2}', 3)]

        self._endings[gadget.GadgetType.JOP] = [(
            '\xff[\x20\x21\x22\x23\x26\x27]', 2),
            ('\xff[\xe0\xe1\xe2\xe3\xe4\xe6\xe7]', 2),
            ('\xff[\x10\x11\x12\x13\x16\x17]', 2),
            ('\xff[\xd0\xd1\xd2\xd3\xd4\xd6\xd7]', 2)]

    def _initBadInstructions(self):
        self._badInstructions = ['int3']


class ArchitectureX86_64(ArchitectureX86):

    def __init__(self):
        ArchitectureX86.__init__(self)

        self._mode = CS_MODE_64

        self._addressLength = 8


class ArchitectureMips(Architecture):

    def __init__(self):
        Architecture.__init__(self, CS_ARCH_MIPS, CS_MODE_32, 4, 4)

    def _initGadgets(self):
        self._endings[gadget.GadgetType.ROP] = []
        self._endings[gadget.GadgetType.JOP] = [('\x09\xf8\x20\x03', 4),
                                                ('\x08\x00\x20\x03', 4),
                                                ('\x08\x00\xe0\x03', 4)]


class ArchitectureMips64(ArchitectureMips):

    def __init__(self):
        ArchitectureMips.__init__()

        self._mode = CS_MODE_64

        self._addressLength = 8

    def _initGadgets(self):
        self._endings[gadget.GadgetType.ROP] = []


x86 = ArchitectureX86()
x86_64 = ArchitectureX86_64()
MIPS = ArchitectureMips()
