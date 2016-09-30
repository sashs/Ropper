from ropper.common.utils import toHex, isHex
import ropper.common.enum as enum
import sys
import math

try:
    if sys.version_info.major < 3:
        import z3
        import pyvex
        import archinfo
except:
    pass


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

    def __init__(self):
        self.__spOffset = 0
        self.__clobberedRegs = []
        self.__offsets = {}
        self.__tmps = {}
        self.__expressions = []
        
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
        while not isinstance(tmp, int) and not tmp is None:
            tmp = self.tmps.get(tmp)

        return tmp


class Analysis(object):

    def __init__(self, arch, irsb):
        self.__instructions = []
        self.__mem = None
        self.__arch = arch
        self.__regs = {}
        self.__regCount = {}
        self.irsb = irsb

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
        to_return = []
        for ia in self.instructions:
            to_return.extend(ia.clobberedRegs)
        return to_return

    def newInstruction(self):
        self.__instructions.append(InstructionAnalysis())
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
            self.__mem = z3.Array('memory' , z3.BitVecSort(self.__arch.bits), z3.BitVecSort(8))
        return self.__mem

    def readMemory(self, addr, size):
        to_return = z3.Select(self._memory, addr)
        for i in range(1, size/8):
            to_return = z3.Concat(z3.Select(self._memory, addr+i), to_return)
        return to_return

    def writeMemory(self, addr, size, data):
        pass

    def writeRegister(self, offset, size, value):
        reg = self.__arch.translate_register_name(offset, size)
        count = self.__regCount.get((reg,size),0)
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
            reg_list = [z3.BitVec('%s_%d' % (name, self.__regCount.get(name,-1)), size)]
            self.__regs[(name,size)] = reg_list

        return self.__regs[(name,size)][level]

    def close(self):
        self.__mem = None


class IRSB_DATA(enum.Enum):
    _enum_ = 'WRITE_REG READ_REG SP_OFFSET CONSTANT'


class Vex(object):

    @classmethod
    def use(cls, name):
        if not isinstance(name, str):
            name = name.__class__.__name__.lower()
        return getattr(cls, name, cls.dummy)

    @staticmethod
    def dummy(dest, data, analysis):
        pass


class Expressions(Vex):

    @staticmethod
    def get(dest, data, analysis):
        return analysis.readRegister(data.offset, data.result_size)

    @staticmethod
    def load(dest, data, analysis):
        addr = Expressions.use(data.addr)(dest, data.addr, analysis)
        return analysis.readMemory(addr, data.result_size)

    @staticmethod
    def store(dest, data, analysis):
        addr = Expressions.use(data.addr)(dest, data.addr, analysis)
        return analysis.readMemory(addr, data.result_size)

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
        return Operations.use(data.op)(dest, data, analysis)
        
    @staticmethod
    def dummy(dest, data, analysis):
        pass


class Operations(Vex):

    @staticmethod
    def Iop_Add32(dest, data, analysis):
        arg1 = Expressions.use(data.args[0])(dest, data.args[0], analysis)
        arg2 = Expressions.use(data.args[1])(dest, data.args[1], analysis)

        return arg1 + arg2

    @staticmethod
    def Iop_Xor32(dest, data, analysis):
        arg1 = Expressions.use(data.args[0])(dest, data.args[0], analysis)
        arg2 = Expressions.use(data.args[1])(dest, data.args[1], analysis)

        return arg1 ^ arg2

    @staticmethod
    def Iop_Sub32(dest, data, analysis):
        arg1 = Expressions.use(data.args[0])(dest, data.args[0], analysis)
        arg2 = Expressions.use(data.args[1])(dest, data.args[1], analysis)

        return arg1 - arg2


class IRSBAnalyser(object):

    def __init__(self):
        self.__cRegs = []

    def analyse(self, irsb):
        #irsb.pp()
        anal = Analysis(irsb.arch, irsb)
        sp_offset = 0
        for stmt in irsb.statements:
            name = stmt.__class__.__name__.lower()
            func = getattr(self, name, self.not_found)
            ci = anal.currentInstruction
            expr = func(stmt, anal)
            if expr is not None:
                ci.expressions.append(expr)
            
        #print('Offset', anal.spOffset)
        return anal

    def put(self, stmt, analysis):
        if stmt.offset == stmt.arch.sp_offset:
            analysis.currentInstruction.spOffset = analysis.currentInstruction.getValueForTmp(str(stmt.data))
        elif stmt.offset == stmt.arch.ip_offset:
            analysis.newInstruction()
        dest = stmt.arch.translate_register_name(stmt.offset, stmt.data.result_size)

        value = Expressions.use(stmt.data)(dest,stmt.data, analysis)
        return analysis.writeRegister(stmt.offset, stmt.data.result_size, value)

    def wrtmp(self, stmt, analysis):
        return z3.BitVec('t'+str(stmt.tmp),stmt.data.result_size) == Expressions.use(stmt.data)( 't'+str(stmt.tmp), stmt.data, analysis)

    def store(self, stmt, analysis):
        pass
        #print(stmt.data.__class__.__)

    def not_found(self, stmt, analysis):
        pass
        #print('No func for: %s' % stmt.__class__.__name__.lower())

