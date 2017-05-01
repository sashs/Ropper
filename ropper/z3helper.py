# coding=utf-8
#
# Copyright 2016 Sascha Schirra
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
try:
    from z3 import *
except:
    pass

class ExpressionBuilder(object):

    def __init__(self):
        self.__z3objects = {}

    def __getattr__(self, name):
        if name in self.__z3objects:
            return self.__z3objects[name]
        return super(ExpressionBuilder, self).__getattribute__(name)

    def _createRegs(self, regsDict):
        for regs in regsDict.values():
            for reg in regs:
                self.__z3objects[reg] = BitVec(reg, int(reg.split('_')[-1],10))

    def _createMem(self, mems):
        for mem in mems:
            sizes = mem.split('_')
            self.__z3objects[mem] = Array(mem, BitVecSort(int(sizes[-2],10)),BitVecSort(int(sizes[-1],10)))

    def build(self, regs, mems, expression, constraint):
        self._createRegs(regs)
        self._createMem(mems)
        return z3.And(eval(expression), z3.Not(eval(constraint)))


