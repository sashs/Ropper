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

import re
import ropperapp.common.enum as enum
from ropperapp.common.utils import toHex


class GadgetType(enum.Enum):
    _enum_ = 'ROP JOP ALL'


class Gadget(object):

    def __init__(self):
        super(Gadget, self).__init__()

        self.__lines = []
        self._gadget = ''
        self._vaddr = 0x0

    @property
    def vaddr(self):
        return self._vaddr

    def append(self, address, inst):
        self.__lines.append((address, inst))
        self._gadget += inst + '\n'

    def match(self, filter):
        if not filter or len(filter) == 0:
            return True
        return bool(re.search(filter, self._gadget))

    def __len__(self):
        return len(self.__lines)

    def __cmp__(self, other):
        if isinstance(other, self.__class__) and len(self) == len(other):
            return cmp(str(self),str(other))
        return -1

    def __str__(self):
        toReturn = ''
        for line in self.__lines:
            toReturn += line[0] + ' ' + line[1] + '\n'

        return toReturn[:-1]
