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
from ropperapp.common.error import *

class RopChain(Abstract):

    def __init__(self, binary, gadgets, imagebase):
        self._gadgets = gadgets
        self._binary = binary
        self._imageBase = imagebase

    @abstractmethod
    def create(self):
        pass

    @classmethod
    def name(cls):
        return None

    @classmethod
    def availableGenerators(cls):
        return []

    @classmethod
    def archs(self):
        return []

    @classmethod
    def get(cls, binary, name, gadgets, imagebase):
        for subclass in cls.__subclasses__():
            if binary.arch in subclass.archs():
                gens = subclass.availableGenerators()
                for gen in gens:
                    if gen.name() == name:
                        return gen(binary, gadgets, imagebase)
        raise RopChainError('generator %s is for arch %s not available' % (name, binary.arch.__class__.__name__))
