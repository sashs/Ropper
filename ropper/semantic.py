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
import sys
from ropper.common.error import RopperError
try:
    if sys.version_info.major < 3:
        import z3
        from z3 import *
        import pyvex
        import archinfo
except ImportError as e:
    raise RopperError(e)

from ropper.common.utils import toHex, isHex
import ropper.arch
import ropper.common.enum as enum

import math
import re



class Category(enum.Enum):
    _enum_ = 'NONE WRITE_MEM_FROM_MEM WRITE_REG_FROM_MEM WRITE_REG_FROM_REG WRITE_MEM_FROM_REG NEG_REG STACK_PIVOTING LOAD_REG LOAD_MEM STACK_PIVOT SYSCALL JMP CALL WRITE_MEM INC_REG CLEAR_REG SUB_REG ADD_REG SUB_REG MUL_REG DIV_REG XCHG_REG PUSHAD WRITE_MEM'

class Analyser(object):

    def __init__(self):
        self.__work = True
        if 'z3' not in globals():
            self.__work = False
            return

    def analyse(self, gadget):
        if not self.__work:
            return False
        #print(gadget)
        try:
            address = gadget.address + 1 if isinstance(gadget.arch, ropper.arch.ArchitectureArmThumb) else gadget.address
            irsb = pyvex.IRSB(str(gadget.bytes), address, gadget.arch.info, num_bytes=len(gadget.bytes))
            irsb_anal = IRSBAnalyser()
            anal = irsb_anal.analyse(irsb)
            #print(anal.spOffset)
            return anal

        except pyvex.PyVEXError:
            pass


class InstructionAnalysis(object):

    MEM_COUNTER = 0

    def __init__(self, arch):
        self.__spOffset = 0
        self.__clobberedRegs = []
        self.__offsets = {}
        self.__tmps = {}
        self.__expressions = []
        self.__usedRegs = set()

    @property
    def usedRegs(self):
        return self.__usedRegs

    def addRegister(self, reg):
        self.__usedRegs.update([reg])
        
    @property
    def expressions(self):
        return self.__expressions

    @property
    def spOffset(self):
        return self.__spOffset

    @spOffset.setter
    def spOffset(self, offset):
        self.__spOffset = offset

    @property
    def clobberedRegs(self):
        return self.__clobberedRegs

    @property
    def offsets(self):
        return self.__offsets

    @property
    def tmps(self):
        return self.__tmps

    def getValueForTmp(self, tmp):
        while not isinstance(tmp, (int, long)) and tmp is not None:
            tmp = self.tmps.get(tmp)

        return tmp

class Analysis(object):

    def __init__(self, arch, irsb):
        self.__instructions = []
        self.__mem = None
        self.__arch = arch
        self.__regs = {}
        self.mems = []
        self.__regCount = {}
        self.__mem_counter = 0
        self.irsb = irsb

    def __repr__(self):
        return 'None'

    @property
    def memCounter(self):
        return self.__mem_counter

    @property
    def regs(self):
        return self.__regs

    @property
    def arch(self):
        return self.__arch

    @property
    def instructions(self):
        return self.__instructions
    
    @property
    def currentInstruction(self):
        if not len(self.instructions):
            return self.newInstruction()
        return self.__instructions[-1]

    @property
    def clobberedRegs(self):
        to_return = set()
        for ia in self.instructions:
            to_return.update(ia.clobberedRegs)
        return to_return

    @property
    def usedRegs(self):
        to_return = set()
        for ia in self.instructions:
            to_return.update(ia.usedRegs)
        return to_return

    def newInstruction(self):
        self.__instructions.append(InstructionAnalysis(self.arch))
        return self.__instructions[-1]

    @property
    def spOffset(self):
        offset = 0
        for inst in self.instructions:
            if inst.spOffset is None:
                return None
            offset += inst.spOffset
        return offset

    @property
    def expressions(self):
        to_return = []
        for ia in self.instructions:
            to_return.extend(ia.expressions)
        return to_return

    @property
    def _memory(self):
        if self.__mem is None:
            #self.__mem = z3.Array('memory_%d' % self.__mem_counter , z3.BitVecSort(self.__arch.bits), z3.BitVecSort(8))
            self.__mem = 'memory%d_%d_%d' % (self.__mem_counter, self.__arch.bits, 8)
            self.mems.append(self.__mem)
            self.__mem_counter += 1
        return self.__mem

    def readMemory(self, addr, size, analyse=True):
        #to_return = z3.Select(self._memory, addr)
        to_return = 'self.%s[%s]' % (self._memory, addr)
        for i in range(1, size/8):
            #to_return = z3.Concat(z3.Select(self._memory, addr+i), to_return)
            value = 'self.%s[%s]' % (self._memory, '%s + %d' % (addr, i))
            to_return = 'Concat(%s, %s)' % (value, to_return)

        return to_return

    def writeMemory(self, addr, size, data):
        size = size/8
        old = self._memory
        for i in range(size):
            #old = z3.Store(old, addr+i, z3.Extract((i+1)*8-1,i*8,data))
            
            value = 'Extract(%d, %d, %s)' % ((i+1)*8-1, i*8, data)
            old = 'Store(%s, %s + %d, %s)' % (old, addr, i, value)
        
        self.__mem = None
        return 'self.%s == self.%s' % (old, self._memory)

    def writeRegister(self, offset, size, value):
        reg = self.__arch.translate_register_name(offset & 0xfffffffe, size)

        real_size = self.__arch.registers.get(reg)
        if real_size == None:
            real_size = self.arch.bits*2
        else:
            real_size = real_size[1]*8

        count = self.__regCount.get((reg),1)
        self.__regCount[(reg)] = count + 1

        reg_list = self.__regs.get((reg))
        if not reg_list:
            reg_list = ['%s_%d_%d' % (reg, 0, real_size)]
            self.__regs[(reg)] = reg_list
        
        reg_list.append('%s_%d_%d' % (reg, count, real_size))

        if size < real_size:
            return 'Extract(%d, 0, self.%s) == %s' %(size-1,self.__regs[(reg)][-1],value)
        else:
            return 'self.%s == %s' % (self.__regs[(reg)][-1], value)

    def readRegister(self, offset, size, level=-1):
        name = offset
        real_size = 0

        if isinstance(name, (int, long)):
            name = self.__arch.translate_register_name(offset & 0xfffffffe, size)
        self.currentInstruction.usedRegs.update([name])
        real_size = self.__arch.registers.get(name)
        if real_size == None:
            real_size = self.arch.bits*2
        else:
            real_size = real_size[1]*8

        reg_list = self.__regs.get((name))

        if not reg_list:
            reg_list = ['%s_%d_%d' % (name, self.__regCount.get(name,0), real_size)]
            self.__regs[(name)] = reg_list

        if size < real_size:
            if offset &1:
                return 'Extract(%d, 8, self.%s)' % (size+8-1, self.__regs[(name)][level])
            else:
                return 'Extract(%d, 0, self.%s)' % (size-1, self.__regs[(name)][level])

        else:
            return 'self.%s' % self.__regs[(name)][level]

class AnalysisResult(object):

    def __init__(self, arch, regs, usedRegs, clobberedRegs, mems, expressions, spOffset):
        self.arch = arch
        self.regs = regs
        self.usedRegs = usedRegs
        self.clobberedRegs = clobberedRegs
        self.mems = mems
        self.expressions = expressions
        self.spOffset = spOffset

class IRSB_DATA(enum.Enum):
    _enum_ = 'WRITE_REG READ_REG SP_OFFSET CONSTANT'


class CommandClass(object):

    @classmethod
    def use(cls, name):
        if not isinstance(name, str):
            name = name.__class__.__name__.lower()
        return getattr(cls, name, cls.dummy)

    @staticmethod
    def dummy(*args, **kwargs):
        pass


class ZExpressions(CommandClass):

    @staticmethod
    def get(dest, data, analysis):
        return (analysis.readRegister(data.offset, data.result_size),(analysis.arch.translate_register_name(data.offset & 0xfffffffe, data.result_size),))

    @staticmethod
    def load(dest, data, analysis):
        addr = ZExpressions.use(data.addr)(dest, data.addr, analysis)[0]
        return (analysis.readMemory(addr, data.result_size),(addr.replace('self.',''),))

    @staticmethod
    def store(dest, data, analysis):
        addr = ZExpressions.use(data.addr)(dest, data.addr, analysis)[0]
        return (analysis.readMemory(addr, data.result_size, False),(addr.replace('self.',''),))

    @staticmethod
    def const(dest, data, analysis):
        analysis.currentInstruction.tmps[dest] = data.con.value if not math.isnan(data.con.value) else 0
        return ('BitVecVal(%d, %d)' % (analysis.currentInstruction.tmps[dest], data.con.size), (data.con.value,))

    @staticmethod
    def rdtmp(dest, data, analysis):
        tmp = '%s_%d' % (str(data), data.result_size)
        analysis.currentInstruction.tmps[dest] = tmp
        analysis.regs[tmp] = [tmp]
        return ('self.%s' % (tmp), (tmp,))

    @staticmethod
    def binop(dest, data, analysis):
        arg1 = ZExpressions.use(data.args[0])(dest, data.args[0], analysis)
        arg2 = ZExpressions.use(data.args[1])(dest, data.args[1], analysis)

        return (ZOperations.use(data.op)(arg1[0], arg2[0], analysis), (arg1[0].replace('self.',''), arg2[0].replace('self.','')))

    @staticmethod
    def unop(dest, data, analysis):
        arg1 = ZExpressions.use(data.args[0])(dest, data.args[0], analysis)
        return (ZOperations.use(data.op)(arg1[0], analysis), arg1[1])
        
    @staticmethod
    def dummy(dest, data, analysis):
        pass


class ZOperations(CommandClass):

    @staticmethod
    def Iop_Add32(arg1, arg2, analysis):
        return '%s + %s' % (arg1, arg2)

    @staticmethod
    def Iop_Add16(arg1, arg2, analysis):
        return '%s + %s' % (arg1, arg2)

    @staticmethod
    def Iop_Add8(arg1, arg2, analysis):
        return '%s + %s' % (arg1, arg2)

    @staticmethod
    def Iop_Xor32(arg1, arg2, analysis):
        return '%s ^ %s' % (arg1, arg2)

    @staticmethod
    def Iop_Xor16(arg1, arg2, analysis):
        return '%s ^ %s' % (arg1, arg2)

    @staticmethod
    def Iop_Xor8(arg1, arg2, analysis):
        return '%s ^ %s' % (arg1, arg2)

    @staticmethod
    def Iop_Mul32(arg1, arg2, analysis):
        return '%s * %s' % (arg1, arg2)

    @staticmethod
    def Iop_Mul16(arg1, arg2, analysis):
        return '%s * %s' % (arg1, arg2)

    @staticmethod
    def Iop_Mul8(arg1, arg2, analysis):
        return '%s * %s' % (arg1, arg2)

    @staticmethod
    def Iop_Div32(arg1, arg2, analysis):
        return '%s / %s' % (arg1, arg2)

    @staticmethod
    def Iop_Div16(arg1, arg2, analysis):
        return '%s / %s' % (arg1, arg2)

    @staticmethod
    def Iop_Div8(arg1, arg2, analysis):
        return '%s / %s' % (arg1, arg2)

    @staticmethod
    def Iop_Sub32(arg1, arg2, analysis):
        return '%s - %s' % (arg1, arg2)

    @staticmethod
    def Iop_Sub16(arg1, arg2, analysis):
        return '%s - %s' % (arg1, arg2)

    @staticmethod
    def Iop_Sub8(arg1, arg2, analysis):
        return '%s - %s' % (arg1, arg2)

    @staticmethod
    def Iop_Add64(arg1, arg2, analysis):
        return '%s + %s' % (arg1, arg2)

    @staticmethod
    def Iop_Xor64(arg1, arg2, analysis):
        return '%s ^ %s' % (arg1, arg2)

    @staticmethod
    def Iop_And64(arg1, arg2, analysis):
        return '%s & %s' % (arg1, arg2)

    @staticmethod
    def Iop_And32(arg1, arg2, analysis):
        return '%s & %s' % (arg1, arg2)

    @staticmethod
    def Iop_And16(arg1, arg2, analysis):
        return '%s & %s' % (arg1, arg2)

    @staticmethod
    def Iop_And8(arg1, arg2, analysis):
        return '%s & %s' % (arg1, arg2)

    @staticmethod
    def Iop_Or64(arg1, arg2, analysis):
        return '%s | %s' % (arg1, arg2)

    @staticmethod
    def Iop_Or32(arg1, arg2, analysis):
        return '%s | %s' % (arg1, arg2)

    @staticmethod
    def Iop_Or16(arg1, arg2, analysis):
        return '%s | %s' % (arg1, arg2)

    @staticmethod
    def Iop_Or8(arg1, arg2, analysis):
        return '%s | %s' % (arg1, arg2)


    @staticmethod
    def Iop_Mul64(arg1, arg2, analysis):
        return '%s * %s' % (arg1, arg2)

    @staticmethod
    def Iop_Div64(arg1, arg2, analysis):
        return '%s / %s' % (arg1, arg2)

    @staticmethod
    def Iop_Sub64(arg1, arg2, analysis):
        return '%s - %s' % (arg1, arg2)

    @staticmethod
    def Iop_32Uto64(arg1, analysis):
        return 'ZeroExt(32,%s)' % arg1

    @staticmethod
    def Iop_32to64(arg1, analysis):
        return 'SignExt(32,%s)' % arg1

    @staticmethod
    def Iop_8to32(arg1, analysis):
        return 'SignExt(24,%s)' % arg1

    @staticmethod
    def Iop_16to32(arg1, analysis):
        return 'SignExt(16,%s)' % arg1

    @staticmethod
    def Iop_8to32(arg1, analysis):
        return 'ZeroExt(24,%s)' % arg1

    @staticmethod
    def Iop_8Uto32(arg1, analysis):
        return 'ZeroExt(24,%s)' % arg1

    @staticmethod
    def Iop_16Uto32(arg1, analysis):
        return 'ZeroExt(16,%s)' % arg1

    @staticmethod
    def Iop_64Uto32(arg1, analysis):
        return 'Extract(31,0,%s)' % arg1

    @staticmethod
    def Iop_64to32(arg1, analysis):
        return 'Extract(31,0,%s)' % arg1

    @staticmethod
    def Iop_32to8(arg1, analysis):
        return 'Extract(7,0,%s)' % arg1

    @staticmethod
    def Iop_32Uto8(arg1, analysis):
        return 'Extract(7,0,%s)' % arg1

    @staticmethod
    def Iop_32to16(arg1, analysis):
        return 'Extract(15,0,%s)' % arg1

    @staticmethod
    def Iop_32Uto16(arg1, analysis):
        return 'Extract(15,0,%s)' % arg1


class ZStatements(CommandClass):

    @staticmethod
    def put(stmt, analysis):
        dest = stmt.arch.translate_register_name(stmt.offset, stmt.data.result_size)
        value = ZExpressions.use(stmt.data)(dest,stmt.data, analysis)

        if not dest.startswith('cc_'):
             
            analysis.currentInstruction.clobberedRegs.append(dest)

        if stmt.offset == stmt.arch.sp_offset:
            analysis.currentInstruction.spOffset = analysis.currentInstruction.getValueForTmp(str(stmt.data))

        return (analysis.writeRegister(stmt.offset, stmt.data.result_size, value[0]),dest, value[1])
   
    @staticmethod
    def wrtmp(stmt, analysis):
        tmp = 't'+str(stmt.tmp)
        value = ZExpressions.use(stmt.data)( tmp, stmt.data, analysis)
        tmp = '%s_%s' % (tmp, stmt.data.result_size)
        analysis.regs[tmp] = [tmp]
        if value is None or value[0] is None:
            return False
      
        return ('self.%s == %s' % (tmp, value[0]), tmp, value[1])

    @staticmethod
    def store(stmt, analysis):
        addr = ZExpressions.use(stmt.addr)(None, stmt.addr, analysis)[0]
        value = ZExpressions.use(stmt.data)(str(addr), stmt.data, analysis)
        
        return (analysis.writeMemory(addr, stmt.data.result_size, value[0]),addr[0],value[1])

    @staticmethod
    def imark(stmt, analysis):
        analysis.newInstruction()

    @staticmethod
    def dummy(stmt, analysis):
        pass

class IRSBAnalyser(object):

    def __init__(self):
        self.__cRegs = []

    def analyse(self, irsb):
        anal = Analysis(irsb.arch, irsb)
        sp_offset = 0
        for stmt in irsb.statements:
            name = stmt.__class__.__name__.lower()
            func = ZStatements.use(stmt)
            expr = func(stmt, anal)
            ci = anal.currentInstruction
            ci.expressions.append(expr)

            
        return anal#AnalysisResult(anal.arch, anal.regs, anal.usedRegs, anal.clobberedRegs, anal.mems, anal.expressions, anal.spOffset)


class Slice(object):

    def __init__(self, regs):
        self.instructions = []
        self.expressions = []
        self.regs = []
        self.regs.extend(regs) 


class Slicer(object):

    def slice(self, irsb, reg):
        slice = Slice(reg)
        
        for expr in irsb[::-1]:
            if expr and expr[1] in slice.regs:
                if expr[2][0] and type(expr[2][0]) is str and not expr[2][0].isdigit():
                    slice.regs.append(expr[2][0])
                if len(expr[2]) == 2 and type(expr[2][1]) is str and not expr[2][1].isdigit():
                    slice.regs.append(expr[2][1])
                slice.expressions.append(expr[0])

        return slice


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
                self.__z3objects[reg] = z3.BitVec(reg, int(reg.split('_')[-1],10))

    def _createMem(self, mems):
        for mem in mems:
            sizes = mem.split('_')
            self.__z3objects[mem] = z3.Array(mem, z3.BitVecSort(int(sizes[-2],10)), z3.BitVecSort(int(sizes[-1],10)))

    def build(self, regs, mems, expression, constraint):
        self._createRegs(regs)
        self._createMem(mems)
        return z3.And(eval(expression), z3.Not(eval(constraint)))