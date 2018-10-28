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
    import z3
    from z3 import *
    from z3.z3types import Z3Exception
    import pyvex
    import archinfo
except ImportError as e:
    pass

from ropper.common.utils import toHex, isHex
from ropper.z3helper import create_number_expression, create_register_expression, create_read_memory_expression
import ropper.arch
import ropper.common.enum as enum

import math
import re

if sys.version_info.major == 3:
    long = int

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
        try:
            thumb = 1 if isinstance(gadget.arch, ropper.arch.ArchitectureArmThumb) else 0
            irsb = pyvex.IRSB(bytes(gadget.bytes), gadget.address+thumb, gadget.arch.info, bytes_offset=thumb, num_bytes=len(gadget.bytes), opt_level=0)
            irsb_anal = IRSBAnalyser()
            anal = irsb_anal.analyse(irsb)
            archinfo = gadget.arch.info
            anal.spOffset = self.findSpOffset(gadget, anal, archinfo.register_names[archinfo.registers['sp'][0]])
            return anal

        except pyvex.PyVEXError as e:
            pass
        except:
            pass

    def findSpOffset(self, g, anal, sp ):
        if sp not in anal.regs:
            return 0
        slicer = Slicer()
        slice_instructions = []
        slice = slicer.slice(anal.expressions, [sp])
        solver = z3.Solver()
        
        expr_len = len(anal.expressions)
        expr = None
        tmp = None

        for inst in anal.expressions:
            
            if not inst:
                continue
            if expr is None:
                expr = inst[0]
            else:
                expr = 'And(%s, %s)' % (expr, inst[0])

        if expr:
            expr = ExpressionBuilder().build(anal.regs, anal.mems, expr)
            sp1 = anal.regs[sp][0]
            sp2 = anal.regs[sp][-1]
            size = int(sp1.split('_')[-1])
            sp1 = z3.BitVec(sp1, size)
            sp2 = z3.BitVec(sp2, size)
            diff = z3.BitVec('diff', size)
            solver.add(z3.And(expr, diff == sp2 - sp1))
            solver.check()
            spOffset = solver.model()[diff].as_signed_long()
            solver = z3.Solver()
            solver.add(z3.And(expr, sp2 - sp1 == spOffset))
            if solver.check() == z3.unsat:
                return 'Undef'
            return spOffset
            
                
class InstructionAnalysis(object):

    MEM_COUNTER = 0

    def __init__(self, arch):
        self.__spOffset = 0
        self.__clobberedRegs = {}
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
        self.__registerAccessors = {}
        self.mems = []
        self.__regCount = {}
        self.__mem_counter = 0
        self.irsb = irsb
        self.register_assignments = {}

    def __repr__(self):
        return 'None'

    @property
    def memCounter(self):
        return self.__mem_counter

    @property
    def regs(self):
        return self.__registerAccessors

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
        to_return = dict()
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
        return create_read_memory_expression(self._memory, addr, size)

    def writeMemory(self, addr, size, data):
        size = size/8
        old = self._memory
        for i in range(int(size)):
            #old = z3.Store(old, addr+i, z3.Extract((i+1)*8-1,i*8,data))
            
            value = 'Extract(%d, %d, %s)' % ((i+1)*8-1, i*8, data)
            old = 'Store(%s, %s + %d, %s)' % (old, addr, i, value)
        
        self.__mem = None
        return '%s == %s' % (old, self._memory)

    def writeRegister(self, offset, size, value):
        reg = self.__arch.translate_register_name(offset & 0xfffffffe, size)

        real_size = self.__arch.registers.get(reg)
        if real_size == None:
            real_size = self.arch.bits*2
        else:
            real_size = real_size[1]*8

        count = self.__regCount.get((reg),0)
        self.__regCount[(reg)] = count + 1

        reg_list = self.__registerAccessors.get((reg))
        if not reg_list:
            reg_list = []
            self.__registerAccessors[(reg)] = reg_list

        self.register_assignments[reg] = value
        
        reg_list.append('%s_%d_%d' % (reg, count, real_size))

        if size < real_size:
            return 'Extract(%d, 0, %s) == %s' %(size-1,self.__registerAccessors[(reg)][-1],value)
        else:
            return '%s == %s' % (self.__registerAccessors[(reg)][-1], value)

    def __getRegisterAccessor(self, register, size):
        register_list = self.__registerAccessors.get((register))

        if not register_list:
            register_list = ['%s_%d_%d' % (register, self.__regCount.get(register, 0), size)]
            self.__regCount[register] = 1
            self.__registerAccessors[register] = register_list

        return register_list[-1]

    def readRegister(self, offset, size):
        name = offset
        register_size = 0

        if isinstance(name, (int, long)):
            name = self.__arch.translate_register_name(offset & 0xfffffffe, size)
        self.currentInstruction.usedRegs.update([name])
        register_size = self.__arch.registers.get(name)
        if register_size == None:
            register_size = self.arch.bits*2
        else:
            register_size = register_size[1]*8

        reg_acc = self.__getRegisterAccessor(name, register_size)

        return create_register_expression(reg_acc, size, bool(offset & 1) if type(offset) is not str else False)

class SemanticInformation(object):

    def __init__(self, regs, usedRegs, clobberedRegs, mems, expressions, spOffset, checked_constraints=None, irsb=None):
        
        self.regs = regs
        self.usedRegs = usedRegs
        self.clobberedRegisters = clobberedRegs
        self.mems = mems
        self.expressions = expressions
        self.spOffset = spOffset
        self._checkedConstraints = {} if checked_constraints is None else checked_constraints
        self.irsb = irsb
    @property    
    def checkedConstraints(self):
        return self._checkedConstraints

    def __repr__(self):
        return 'SemanticInformation(%s, %s, %s, %s, %s, %s, %s, %s)' % (repr(self.regs), repr(self.usedRegs), repr(self.clobberedRegisters), repr(self.mems), repr(self.expressions), repr(self.spOffset), repr(self.checkedConstraints), repr(self.irsb))

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
        return (analysis.readRegister(data.offset, data.result_size(analysis.irsb.tyenv)),(analysis.arch.translate_register_name(data.offset & 0xfffffffe, data.result_size(analysis.irsb.tyenv)),))

    @staticmethod
    def load(dest, data, analysis):
        addr = ZExpressions.use(data.addr)(dest, data.addr, analysis)[0]
        return (analysis.readMemory(addr, data.result_size(analysis.irsb.tyenv)),(addr,))

    @staticmethod
    def store(dest, data, analysis):
        addr = ZExpressions.use(data.addr)(dest, data.addr, analysis)[0]
        return (analysis.readMemory(addr, data.result_size(analysis.irsb.tyenv), False),(addr,))

    @staticmethod
    def const(dest, data, analysis):
        analysis.currentInstruction.tmps[dest] = data.con.value if not math.isnan(data.con.value) else 0
        return ('BitVecVal(%d, %d)' % (analysis.currentInstruction.tmps[dest], data.con.size), (data.con.value,))

    @staticmethod
    def rdtmp(dest, data, analysis):
        tmp = '%s_%d' % (str(data), data.result_size(analysis.irsb.tyenv))
        analysis.currentInstruction.tmps[dest] = tmp
        analysis.regs[tmp] = [tmp]
        return ('%s' % (tmp), (tmp,))

    @staticmethod
    def binop(dest, data, analysis):
        arg1 = ZExpressions.use(data.args[0])(dest, data.args[0], analysis)
        arg2 = ZExpressions.use(data.args[1])(dest, data.args[1], analysis)

        return (ZOperations.use(data.op)(arg1[0], arg2[0], analysis), (arg1[0], arg2[0]))

    @staticmethod
    def unop(dest, data, analysis):
        arg1 = ZExpressions.use(data.args[0])(dest, data.args[0], analysis)
        return (ZOperations.use(data.op)(arg1[0], analysis), arg1[1])
    
    @staticmethod
    def triop(dest, data, analysis):
        # TODO used for floating point operations, should be implemented in a future version
        return None

    @staticmethod
    def qop(dest, data, analysis):
        # TODO should be implemented in a future version
        return None

    @staticmethod
    def ccall(dest, data, analysis):
        # TODO should be implemented in a future version
        #analysis.printable=True
        return None
      
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
        dest = analysis.arch.translate_register_name(stmt.offset, stmt.data.result_size(analysis.irsb.tyenv))
        value = ZExpressions.use(stmt.data)(dest,stmt.data, analysis)

        if not dest.startswith('cc_'):
            analysis.currentInstruction.clobberedRegs[dest] = None

        if stmt.offset == analysis.arch.sp_offset:
            analysis.currentInstruction.spOffset = analysis.currentInstruction.getValueForTmp(str(stmt.data))
        
        if value is not None:
            analysis.register_assignments[dest] = value[1][0] if len(value[1]) == 1 else value[0]
        else:
            analysis.register_assignments[dest] = None
            

        return (analysis.writeRegister(stmt.offset, stmt.data.result_size(analysis.irsb.tyenv), value[0]),dest, value[1])
   
    @staticmethod
    def wrtmp(stmt, analysis):
        tmp = 't'+str(stmt.tmp)
        value = ZExpressions.use(stmt.data)( tmp, stmt.data, analysis)
        tmp = '%s_%s' % (tmp, stmt.data.result_size(analysis.irsb.tyenv))
        analysis.regs[tmp] = [tmp]
        if value is not None:
            analysis.register_assignments[tmp] = value[1][0] if len(value[1]) == 1 else value[0]
        else:
            analysis.register_assignments[tmp] = None
        if value is None or value[0] is None:
            return False
      
        return ('%s == %s' % (tmp, value[0]), tmp, value[1])

    @staticmethod
    def store(stmt, analysis):
        addr = ZExpressions.use(stmt.addr)(None, stmt.addr, analysis)[0]
        value = ZExpressions.use(stmt.data)(str(addr), stmt.data, analysis)
        
        return (analysis.writeMemory(addr, stmt.data.result_size(analysis.irsb.tyenv), value[0]),addr[0],value[1])

    @staticmethod
    def imark(stmt, analysis):
        analysis.newInstruction()

    @staticmethod
    def dummy(stmt, analysis):
        pass

class IRSBAnalyser(object):

    def __init__(self):
        self.__cRegs = []

    def __resolveAssignments(self, analysis):
        to_return = {}
        for orig in analysis.clobberedRegs.keys():
            reg = orig
            while True:
                tmp = analysis.register_assignments.get(reg)
                if tmp is None:
                    to_return[orig] = None
                    break
                elif analysis.arch.registers.get(tmp) is not None:
                    to_return[orig] = tmp
                    break
                
                reg = tmp

        return to_return
            

    def analyse(self, irsb):
        anal = Analysis(irsb.arch, irsb)
        sp_offset = 0
        for stmt in irsb.statements:
            name = stmt.__class__.__name__.lower()
            func = ZStatements.use(stmt)
            anal.printable = False
            expr = func(stmt, anal)
           # if anal.printable:
            #    print(stmt)
            ci = anal.currentInstruction
            ci.expressions.append(expr)

        clobbered_regs = self.__resolveAssignments(anal)
        return SemanticInformation(anal.regs, anal.usedRegs, clobbered_regs, anal.mems, anal.expressions, anal.spOffset, irsb=irsb._pp_str())


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
                if expr[0]:
                    slice.expressions.append(expr[0])

        return slice


class ExpressionBuilder(object):

    def __init__(self):
        self.__z3objects = {}

    def __getattr__(self, name):
        if name in self.__z3objects:
            return self.__z3objects[name]
        return super(ExpressionBuilder, self).__getattribute__(name)

    def _createRegs(self, objects, regsDict):
        for regs in regsDict.values():
            for reg in regs:
                objects[reg] = z3.BitVec(reg, int(reg.split('_')[-1],10))

    def _createMem(self, objects, mems):
        for mem in mems:
            sizes = mem.split('_')
            objects[mem] = z3.Array(mem, z3.BitVecSort(int(sizes[-2],10)), z3.BitVecSort(int(sizes[-1],10)))

    def build(self, regs, mems, expression, constraint=None):
        z3objects = {}
        self._createRegs(z3objects, regs)
        self._createMem(z3objects, mems)
        if constraint is None:
            return eval(expression, globals(), z3objects)
        f = True
        f = z3.And(f,eval(expression, globals(), z3objects))
        g = eval(constraint, globals(), z3objects)
        
        return z3.And(f, z3.Not(g))
#        return z3.Not(eval(expression, globals(), z3objects) == eval(constraint, globals(), z3objects))
#        return z3.And(eval(expression, globals(), z3objects), z3.Not(eval(constraint, globals(), z3objects))
