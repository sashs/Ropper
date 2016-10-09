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
from ropper.semantic import CommandClass

class SExpressions(CommandClass):

    @staticmethod
    def get(data, slice):  
        reg = data.arch.translate_register_name(data.offset, data.result_size)
        slice.regs.append(reg)  

    @staticmethod
    def load(data, slice):
        SExpressions.use(data.addr)(data.addr, slice)

    @staticmethod
    def rdtmp( data, slice):
        reg = 't%d' % data.tmp
        slice.regs.append(reg)   

    @staticmethod
    def binop(data, slice):
        SExpressions.use(data.args[1])(data.args[1], slice)
        SExpressions.use(data.args[0])(data.args[0], slice)

    @staticmethod
    def unop(data, slice):
        SExpressions.use(data.args[0])(data.args[0], slice)


class SStatements(CommandClass):

    @staticmethod
    def put(stmt, slice, number):
        dest = stmt.arch.translate_register_name(stmt.offset, stmt.data.result_size)
        if dest not in slice.regs:
            return

        del slice.regs[slice.regs.index(dest)]
        slice.instructions.append(number)
        SExpressions.use(stmt.data)(stmt.data, slice)

    @staticmethod
    def wrtmp(stmt, slice, number):
        tmp = 't'+str(stmt.tmp)
        dest = tmp
        if dest not in slice.regs:
            return

        del slice.regs[slice.regs.index(dest)]
        slice.instructions.append(number)
        SExpressions.use(stmt.data)(stmt.data, slice)
        

    @staticmethod
    def imark(stmt, slice, number):
        pass

class Slice(object):

    def __init__(self, reg):
        self.instructions = []
        self.regs = [reg] 


class Slicer(object):

    def slicing(self, irsb, reg):
        
        stmts = irsb.statements[::-1]
        slice = Slice(reg)
        stmt_number = 1
        for stmt in stmts:
            
            func = SStatements.use(stmt)
            func(stmt, slice, stmt_number)
            stmt_number += 1
            if not slice.regs:
                break
        return slice