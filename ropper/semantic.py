from ropper.common.utils import toHex, isHex
import ropper.common.enum as enum
import sys
import math
import re

try:
    if sys.version_info.major < 3:
        import z3
        import pyvex
        import archinfo
except:
    pass

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
            irsb = pyvex.IRSB(str(gadget.bytes), gadget.address, gadget.arch.info, num_bytes=len(gadget.bytes), traceflags=256)
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
        self.__sim = State(arch, self)
        self.__categories = []
        self.__usedRegs = set()

    @property
    def usedRegs(self):
        return self.__usedRegs

    def addRegister(self, reg):
        self.__usedRegs.update([reg])

    @property
    def state(self):
        return self.__sim

    @property
    def categories(self):
        return self.__categories

    @categories.setter
    def categories(self, category):
        self.__categories = categories
        
    @property
    def expressions(self):
        return self.__expressions

    @property
    def spOffset(self):
        if self.__spOffset:
            return self.__spOffset
        return 0

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
        while not isinstance(tmp, (int, long)) and not tmp is None:
            tmp = self.tmps.get(tmp)

        return tmp


class Analysis(object):

    def __init__(self, arch, irsb):
        self.__instructions = []
        self.__mem = None
        self.__arch = arch
        self.__regs = {}
        self.__regCount = {}
        self.__mem_counter = 0
        self.irsb = irsb

    @property
    def regs(self):
        return self.__regs

    @property
    def arch(self):
        return self.__arch

    @property
    def categories(self):
        to_return = set()
        for ia in self.instructions:
            to_return.update([ia.state.getCategory()])
        return to_return

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

    def newInstruction(self):
        self.__instructions.append(InstructionAnalysis(self.arch))
        return self.__instructions[-1]

    @property
    def spOffset(self):
        offset = 0
        for inst in self.instructions:
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
            self.__mem = z3.Array('memory_%d' % self.__mem_counter , z3.BitVecSort(self.__arch.bits), z3.BitVecSort(8))
            self.__mem_counter += 1
        return self.__mem

    def readMemory(self, addr, size, analyse=True):
        to_return = z3.Select(self._memory, addr)
        for i in range(1, size/8):
            to_return = z3.Concat(z3.Select(self._memory, addr+i), to_return)

        if analyse==True:
            self.currentInstruction.categories.append(Category.LOAD_MEM)
        return to_return

    def writeMemory(self, addr, size, data):
        size = size/8
        old = self._memory
        for i in range(size):
            old = z3.Store(old, addr+i, z3.Extract((i+1)*8-1,i*8,data))

        self.currentInstruction.categories.append(Category.WRITE_MEM)
        self.__mem = None
        return old == self._memory

    def writeRegister(self, offset, size, value):
        reg = self.__arch.translate_register_name(offset, size)
        count = self.__regCount.get((reg,size),1)
        self.__regCount[(reg,size)] = count + 1
        reg_list = self.__regs.get((reg,size))
        if not reg_list:
            reg_list = []
            self.__regs[(reg,size)] = reg_list
        
        reg_list.append(z3.BitVec('%s_%d_%d' % (reg, size, count), size))
        return self.__regs[(reg,size)][-1] == value

    def readRegister(self, offset, size, level=-1):
        name = offset
        if isinstance(name, int):
            name = self.__arch.translate_register_name(offset, size)
        reg_list = self.__regs.get((name,size))
        if not reg_list:
            reg_list = [z3.BitVec('%s_%d_%d' % (name, size, self.__regCount.get(name,0)), size)]
            self.__regs[(name,size)] = reg_list

        return self.__regs[(name,size)][level]


class IRSB_DATA(enum.Enum):
    _enum_ = 'WRITE_REG READ_REG SP_OFFSET CONSTANT'


class Vex(object):

    @classmethod
    def use(cls, name):
        if not isinstance(name, str):
            name = name.__class__.__name__.lower()
        return getattr(cls, name, cls.dummy)

    @staticmethod
    def dummy(*args, **kwargs):
        pass


class ZExpressions(Vex):

    @staticmethod
    def get(dest, data, analysis):
        return analysis.readRegister(data.offset, data.result_size)

    @staticmethod
    def load(dest, data, analysis):
        addr = ZExpressions.use(data.addr)(dest, data.addr, analysis)
        return analysis.readMemory(addr, data.result_size)

    @staticmethod
    def store(dest, data, analysis):
        addr = ZExpressions.use(data.addr)(dest, data.addr, analysis)
        return analysis.readMemory(addr, data.result_size, False)

    @staticmethod
    def const(dest, data, analysis):
        analysis.currentInstruction.tmps[dest] = data.con.value if not math.isnan(data.con.value) else 0
        return z3.BitVecVal(analysis.currentInstruction.tmps[dest], data.con.size)
        #return analysis.currentInstruction.tmps[dest]

    @staticmethod
    def rdtmp(dest, data, analysis):
        analysis.currentInstruction.tmps[dest] = str(data)
        return z3.BitVec(str(data), data.result_size)

    @staticmethod
    def binop(dest, data, analysis):
        arg1 = ZExpressions.use(data.args[0])(dest, data.args[0], analysis)
        arg2 = ZExpressions.use(data.args[1])(dest, data.args[1], analysis)
        return ZOperations.use(data.op)(arg1, arg2, analysis)

    @staticmethod
    def unop(dest, data, analysis):
        arg1 = ZExpressions.use(data.args[0])(dest, data.args[0], analysis)
        return ZOperations.use(data.op)(arg1, analysis)
        
    @staticmethod
    def dummy(dest, data, analysis):
        pass

class SExpressions(Vex):

    @staticmethod
    def get(data, analysis):  
        reg = data.arch.translate_register_name(data.offset, data.result_size)   
        analysis.currentInstruction.state.readRegister(reg)       
        return reg

    @staticmethod
    def load( data, analysis):
        analysis.currentInstruction.state.readMemory()
        return 'mem'

    @staticmethod
    def store(data, analysis):
        analysis.currentInstruction.state.writeMemory()
        return analysis.readMemory(addr, data.result_size, False)

    @staticmethod
    def const(data, analysis):
        return data.con.value

    @staticmethod
    def rdtmp( data, analysis):
        analysis.currentInstruction.state.readTmp('t%d' % data.tmp)
        return 't%d' % data.tmp

    @staticmethod
    def binop(data, analysis):
        arg1 = SExpressions.use(data.args[0])(data.args[0], analysis)
        arg2 = SExpressions.use(data.args[1])(data.args[1], analysis)
        return arg2

    @staticmethod
    def unop(data, analysis):
        arg1 = SExpressions.use(data.args[0])(data.args[0], analysis)
        return arg1


class ZOperations(Vex):

    @staticmethod
    def Iop_Add32(arg1, arg2, analysis):
        
        analysis.currentInstruction.categories.append(Category.ADD_REG)

        return arg1 + arg2

    @staticmethod
    def Iop_Add16(arg1, arg2, analysis):
        analysis.currentInstruction.categories.append(Category.ADD_REG)

        return arg1 + arg2

    @staticmethod
    def Iop_Add8(arg1, arg2, analysis):
        analysis.currentInstruction.categories.append(Category.ADD_REG)

        return arg1 + arg2

    @staticmethod
    def Iop_Xor32(arg1, arg2, analysis):
        return arg1 ^ arg2

    @staticmethod
    def Iop_Xor16(arg1, arg2, analysis):
        return arg1 ^ arg2

    @staticmethod
    def Iop_Xor8(arg1, arg2, analysis):
        return arg1 ^ arg2

    @staticmethod
    def Iop_Mul32(arg1, arg2, analysis):
        analysis.currentInstruction.categories.append(Category.MUL_REG)
        return arg1 * arg2

    @staticmethod
    def Iop_Mul16(arg1, arg2, analysis):
        analysis.currentInstruction.categories.append(Category.MUL_REG)
        return arg1 * arg2

    @staticmethod
    def Iop_Mul8(arg1, arg2, analysis):
        analysis.currentInstruction.categories.append(Category.MUL_REG)
        return arg1 * arg2

    @staticmethod
    def Iop_Div32(arg1, arg2, analysis):
        analysis.currentInstruction.categories.append(Category.DIV_REG)
        return arg1 / arg2

    @staticmethod
    def Iop_Div16(arg1, arg2, analysis):
        analysis.currentInstruction.categories.append(Category.DIV_REG)
        return arg1 / arg2

    @staticmethod
    def Iop_Div8(arg1, arg2, analysis):
        analysis.currentInstruction.categories.append(Category.DIV_REG)
        return arg1 / arg2

    @staticmethod
    def Iop_Sub32(arg1, arg2, analysis):
        analysis.currentInstruction.categories.append(Category.SUB_REG)
        return arg1 - arg2

    @staticmethod
    def Iop_Sub16(arg1, arg2, analysis):
        analysis.currentInstruction.categories.append(Category.SUB_REG)
        return arg1 - arg2

    @staticmethod
    def Iop_Sub8(arg1, arg2, analysis):
        analysis.currentInstruction.categories.append(Category.SUB_REG)
        return arg1 - arg2

    @staticmethod
    def Iop_Add64(arg1, arg2, analysis):
        analysis.currentInstruction.categories.append(Category.ADD_REG)
        return arg1 + arg2

    @staticmethod
    def Iop_Xor64(arg1, arg2, analysis):
        return arg1 ^ arg2

    @staticmethod
    def Iop_And64(arg1, arg2, analysis):
        return arg1 & arg2

    @staticmethod
    def Iop_And32(arg1, arg2, analysis):
        return arg1 & arg2

    @staticmethod
    def Iop_And16(arg1, arg2, analysis):
        return arg1 & arg2

    @staticmethod
    def Iop_And8(arg1, arg2, analysis):
        return arg1 & arg2

    @staticmethod
    def Iop_Mul64(arg1, arg2, analysis):
        analysis.currentInstruction.categories.append(Category.MUL_REG)
        return arg1 * arg2

    @staticmethod
    def Iop_Div64(arg1, arg2, analysis):
        analysis.currentInstruction.categories.append(Category.DIV_REG)
        return arg1 / arg2

    @staticmethod
    def Iop_Sub64(arg1, arg2, analysis):
        analysis.currentInstruction.categories.append(Category.SUB_REG)
        return arg1 - arg2

    @staticmethod
    def Iop_32Uto64(arg1, analysis):
        return z3.ZeroExt(32,arg1)

    @staticmethod
    def Iop_32to64(arg1, analysis):
        return z3.SignExt(32,arg1)

    @staticmethod
    def Iop_8to32(arg1, analysis):
        return z3.SignExt(24,arg1)

    @staticmethod
    def Iop_16to32(arg1, analysis):
        return z3.SignExt(16,arg1)

    @staticmethod
    def Iop_8to32(arg1, analysis):
        return z3.ZeroExt(24,arg1)

    @staticmethod
    def Iop_8Uto32(arg1, analysis):
        return z3.ZeroExt(24,arg1)

    @staticmethod
    def Iop_16Uto32(arg1, analysis):
        return z3.ZeroExt(16,arg1)

    @staticmethod
    def Iop_64Uto32(arg1, analysis):
        return z3.Extract(31,0,arg1)

    @staticmethod
    def Iop_32to8(arg1, analysis):
        return z3.Extract(7,0,arg1)

    @staticmethod
    def Iop_32Uto8(arg1, analysis):
        return z3.Extract(7,0,arg1)

    @staticmethod
    def Iop_32to16(arg1, analysis):
        return z3.Extract(15,0,arg1)

    @staticmethod
    def Iop_32Uto16(arg1, analysis):
        return z3.Extract(15,0,arg1)


class SOperations(Vex):

    @staticmethod
    def Iop_Add32(arg1, arg2, analysis):
        return arg1 + arg2

    @staticmethod
    def Iop_Add16(arg1, arg2, analysis):
        return arg1 + arg2

    @staticmethod
    def Iop_Add8(arg1, arg2, analysis):
        return arg1 + arg2

    @staticmethod
    def Iop_Xor32(arg1, arg2, analysis):
        return arg1 ^ arg2

    @staticmethod
    def Iop_Xor16(arg1, arg2, analysis):
        return arg1 ^ arg2

    @staticmethod
    def Iop_Xor8(arg1, arg2, analysis):
        return arg1 ^ arg2

    @staticmethod
    def Iop_Mul32(arg1, arg2, analysis):
        return arg1 * arg2

    @staticmethod
    def Iop_Mul16(arg1, arg2, analysis):
        return arg1 * arg2

    @staticmethod
    def Iop_Mul8(arg1, arg2, analysis):
        return arg1 * arg2

    @staticmethod
    def Iop_Div32(arg1, arg2, analysis):
        return arg1 / arg2

    @staticmethod
    def Iop_Div16(arg1, arg2, analysis):
        return arg1 / arg2

    @staticmethod
    def Iop_Div8(arg1, arg2, analysis):
        return arg1 / arg2

    @staticmethod
    def Iop_Sub32(arg1, arg2, analysis):
        return arg1 - arg2

    @staticmethod
    def Iop_Sub16(arg1, arg2, analysis):
        return arg1 - arg2

    @staticmethod
    def Iop_Sub8(arg1, arg2, analysis):
        return arg1 - arg2

    @staticmethod
    def Iop_Add64(arg1, arg2, analysis):
        return arg1 + arg2

    @staticmethod
    def Iop_Xor64(arg1, arg2, analysis):
        return arg1 ^ arg2

    @staticmethod
    def Iop_And64(arg1, arg2, analysis):
        return arg1 & arg2

    @staticmethod
    def Iop_And32(arg1, arg2, analysis):
        if isinstance(arg1, str) and isinstance(arg2, int):
            import pdb; pdb.set_trace()
        return arg1 & arg2

    @staticmethod
    def Iop_And16(arg1, arg2, analysis):
        return arg1 & arg2

    @staticmethod
    def Iop_And8(arg1, arg2, analysis):
        return arg1 & arg2

    @staticmethod
    def Iop_Mul64(arg1, arg2, analysis):
        return arg1 * arg2

    @staticmethod
    def Iop_Div64(arg1, arg2, analysis):
        return arg1 / arg2

    @staticmethod
    def Iop_Sub64(arg1, arg2, analysis):
        return arg1 - arg2

    @staticmethod
    def Iop_32Uto64(arg1, analysis):
        return z3.ZeroExt(32,arg1)

    @staticmethod
    def Iop_32to64(arg1, analysis):
        return z3.SignExt(32,arg1)

    @staticmethod
    def Iop_8to32(arg1, analysis):
        return z3.SignExt(24,arg1)

    @staticmethod
    def Iop_16to32(arg1, analysis):
        return z3.SignExt(16,arg1)

    @staticmethod
    def Iop_8to32(arg1, analysis):
        return z3.ZeroExt(24,arg1)

    @staticmethod
    def Iop_8Uto32(arg1, analysis):
        return z3.ZeroExt(24,arg1)

    @staticmethod
    def Iop_16Uto32(arg1, analysis):
        return z3.ZeroExt(16,arg1)

    @staticmethod
    def Iop_64Uto32(arg1, analysis):
        return z3.Extract(31,0,arg1)

    @staticmethod
    def Iop_32to8(arg1, analysis):
        return z3.Extract(7,0,arg1)

    @staticmethod
    def Iop_32Uto8(arg1, analysis):
        return z3.Extract(7,0,arg1)

    @staticmethod
    def Iop_32to16(arg1, analysis):
        return z3.Extract(15,0,arg1)

    @staticmethod
    def Iop_32Uto16(arg1, analysis):
        return z3.Extract(15,0,arg1)

class ZStatements(Vex):

    @staticmethod
    def put(stmt, analysis):
        dest = stmt.arch.translate_register_name(stmt.offset, stmt.data.result_size)
        value = ZExpressions.use(stmt.data)(dest,stmt.data, analysis)

        if stmt.offset != stmt.arch.ip_offset and not dest.startswith('cc_'):
             
            analysis.currentInstruction.clobberedRegs.append(dest)

        if stmt.offset == stmt.arch.sp_offset:
            print("rsp offset",analysis.currentInstruction.getValueForTmp(str(stmt.data)),str(stmt.data))
            analysis.currentInstruction.spOffset = analysis.currentInstruction.getValueForTmp(str(stmt.data))
            #analysis.currentInstruction.loadedFromSp = False

        return analysis.writeRegister(stmt.offset, stmt.data.result_size, value)
   
    @staticmethod
    def wrtmp(stmt, analysis):
        tmp = 't'+str(stmt.tmp)
        return z3.BitVec(tmp ,stmt.data.result_size) == ZExpressions.use(stmt.data)( tmp, stmt.data, analysis)

    @staticmethod
    def store(stmt, analysis):
        addr = ZExpressions.use(stmt.addr)(None, stmt.addr, analysis)
        value = ZExpressions.use(stmt.data)(str(addr), stmt.data, analysis)
        
        return analysis.writeMemory(addr, stmt.data.result_size, value)

    @staticmethod
    def imark(stmt, analysis):
        if not analysis.currentInstruction.categories:
            analysis.currentInstruction.categories.append(Category.NONE)
        analysis.newInstruction()

    @staticmethod
    def dummy(stmt, analysis):
        pass

class SStatements(Vex):

    @staticmethod
    def put(stmt, analysis):
        dest = stmt.arch.translate_register_name(stmt.offset, stmt.data.result_size)
        value = SExpressions.use(stmt.data)(stmt.data, analysis)

        if stmt.offset not in (stmt.arch.sp_offset, stmt.arch.ip_offset) and not dest.startswith('cc_'):
            analysis.currentInstruction.state.writeRegister(dest, value)
            #analysis.currentInstruction.loadedFromSp = False
   
    @staticmethod
    def wrtmp(stmt, analysis):
        tmp = 't'+str(stmt.tmp)
        value = SExpressions.use(stmt.data)(stmt.data, analysis)
        analysis.currentInstruction.state.writeTmp(tmp, value)
        
    @staticmethod
    def store(stmt, analysis):
        analysis.currentInstruction.state.writeMemory()

    @staticmethod
    def imark(stmt, analysis):
        pass

class IRSBAnalyser(object):

    def __init__(self):
        self.__cRegs = []

    def analyse(self, irsb):
        #irsb.pp()
        anal = Analysis(irsb.arch, irsb)
        sp_offset = 0
        for stmt in irsb.statements:
            name = stmt.__class__.__name__.lower()
            func = ZStatements.use(stmt)
            expr = func(stmt, anal)
            if expr is not None:
                ci = anal.currentInstruction
                ci.expressions.append(expr)

            SStatements.use(stmt)(stmt, anal)
            
        return anal

class State(object):

    def __init__(self, arch, instruction):
        self.__tmps = {}
        self.__regs = {}
        self.__writeMem = False
        self.__readMem = False
        self.__arch = arch
        self.__binop = {}
        self.__instruction = instruction

    def __resolveValue(self, value):
        tmp = value

        while re.match('t%d', value):
            tmp = self.__tmps.get(value)

        return tmp


    def readMemory(self):
        self.__readMem = True

    def writeMemory(self):
        self.__writeMem = True

    def readRegister(self, reg):
        self.__instruction.addRegister(reg)

    def writeRegister(self, reg, value):
        if isinstance(value, str) and re.match('t%d', value):
            value = self.__resolveValue(value)
        self.__regs[reg] = value
        self.__instruction.addRegister(reg)

    def readTmp(self, tmp):
        pass

    def writeTmp(self, tmp, value):
        self.__tmps[tmp] = value

    def getCategory(self):
        if self.__readMem and self.__writeMem:
            return Category.WRITE_MEM_FROM_MEM
        if len(self.__regs) > 0:
            if self.__readMem:
                return Category.WRITE_REG_FROM_MEM
            for reg in self.__regs:
                if reg in self.__arch.translate_register_name(self.__arch.sp_offset):
                    continue
                return Category.WRITE_REG_FROM_REG
        return Category.NONE
