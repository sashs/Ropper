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

from ropper.common.abstract import *
from ropper.common.enum import Enum
from ropper.common.error import NotSupportedError
from ropper.search import Searcher
from ropper.search import Searcherx86
from ropper.search import SearcherARM
from re import compile
from capstone import *
from . import gadget
try:
    import sys
    if sys.version_info.major < 3:
        import archinfo
except:
    pass

# Optional keystone support
try:
    import keystone
except:
    pass

class Endianess(Enum):
    _enum_ = 'LITTLE BIG'

class Architecture(AbstractSingleton):

    def __init__(self, arch, mode, addressLength, align, endianess=Endianess.LITTLE):
        super(Architecture, self).__init__()
        self._name = 'raw'
        self._arch = arch
        self._mode = mode
        self._info = None

        self._ksarch = (None,None)

        self._addressLength = addressLength
        self._align = align

        self._endings = {}
        self._badInstructions = []
        self._categories = {}
        self._maxInvalid = 1

        self._endianess = endianess

        self._searcher = Searcher()

        self._initGadgets()
        self._initBadInstructions()
        self._initCategories()
        
        self._initEndianess(endianess)

        self._endings[gadget.GadgetType.ALL] = self._endings[
            gadget.GadgetType.ROP] + self._endings[gadget.GadgetType.JOP] + self._endings[gadget.GadgetType.SYS]

    def _initGadgets(self):
        self._endings[gadget.GadgetType.ROP] = []
        self._endings[gadget.GadgetType.JOP] = []
        self._endings[gadget.GadgetType.SYS] = []

    def _initBadInstructions(self):
        pass

    def _initCategories(self):
        pass

    def _initEndianess(self, endianess):
        if endianess == Endianess.BIG:
            for key in self.endings:
                tmp = []
                for pattern, size in self.endings[key]:
                    tmp.append((pattern[::-1], size))
                self.endings[key] = tmp 

    @property
    def info(self):
        return self._info
    

    @property
    def ksarch(self):
        return self._ksarch

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

    @property
    def searcher(self):
        return self._searcher

    @property
    def maxInvalid(self):
        return self._maxInvalid

    @property
    def endianess(self):
        return self._endianess

    def getRegisterName(self, reg):
        if self.info is None:
            return reg
        info = self.info.registers.get(reg)
        if not info:
            return reg
        return self.info.translate_register_name(info[0], info[1]*8)

    def __str__(self):
        return self._name

    def __repr__(self):
        return repr(str(self))


class ArchitectureX86(Architecture):

    def __init__(self):
        super(ArchitectureX86, self).__init__( CS_ARCH_X86, CS_MODE_32, 4, 1)
        self._name = 'x86'
        self._maxInvalid = 6
        if 'keystone' in globals():
            self._ksarch = (keystone.KS_ARCH_X86, keystone.KS_MODE_32)

        if 'archinfo' in globals():
            self._info = archinfo.ArchX86()

        self._searcher = Searcherx86()
        self._pprs = [b'[\x58-\x5f]{2}\xc3', # pop reg; pop reg; ret
                        b'\x83\xc4\x04[\x58-\x5f]\xc3', # add esp, 4; pop reg; ret
                        b'[\x58-\x5f]\x83\xc4\x04\xc3', # pop reg; add esp, 4; ret
                        b'\x83\xc4\x08\xc3',            # add esp, 8; ret;
                        b'\xff\x54\x24[\x08\x14\x1c\x2c\x44\x50]',            # call [esp+n] 
                        b'\xff\x64\x24[\x08\x14\x1c\x2c\x44\x50]',            # jmp [esp+n]
                        b'\xff\x65[\x0c\x24\x30\xfc\xf4\xe8]',                            # jmp [ebp+n]
                        b'\xff\x55[\x0c\x24\x30\xfc\xf4\xe8]'                             # call [ebp+n]
                        ]

    @property
    def pprs(self):
        return self._pprs

    def _initGadgets(self):
        super(ArchitectureX86, self)._initGadgets()
        self._endings[gadget.GadgetType.ROP] = [(b'\xc3', 1),                           # ret
                                                (b'\xc2[\x00-\xff]{2}', 3)]             # ret xxx

        self._endings[gadget.GadgetType.SYS] = [(b'\xcd\x80', 2),                           # int 0x80
                                                (b'\x0f\x05',2),                            # syscall
                                                (b'\x0f\x34',2),                            # sysenter
                                                (b'\x65\xff\x15\x10\x00\x00\x00', 7)]       # call gs:[10]

        self._endings[gadget.GadgetType.JOP] = [(
            b'\xff[\x20\x21\x22\x23\x26\x27]', 2),
            (b'\xff[\xe0\xe1\xe2\xe3\xe4\xe6\xe7]', 2),
            (b'\xff[\x10\x11\x12\x13\x16\x17]', 2),
            (b'\xff[\xd0\xd1\xd2\xd3\xd4\xd6\xd7]', 2),
            (b'\xff[\x14\x24]\x24', 3),
            (b'\xff[\x55\x65]\x00', 3),
            (b'\xff[\xa0\xa1\xa2\xa3\xa6\xa7][\x00-\x0ff]{4}', 6),
            (b'\xff\xa4\x24[\x00-\xff]{4}', 7),
            (b'\xff[\x50-\x53\x55-\x57][\x00-\xff]{1}', 3),                             # call [reg + value]
            (b'\xff[\x60-\x63\x65-\x67][\x00-\xff]{1}', 3),                             # jmp [reg + value]
            #(b'\xe9[\x00-\xff]{4}', 5),                                                 # jmp value
            #(b'\xe8[\x00-\xff]{4}', 5),                                                 # call value
            (b'\xff[\x90\x91\x92\x93\x94\x96\x97][\x00-\x0ff]{4}', 6)]

    def _initBadInstructions(self):
        self._badInstructions = ['retf','enter','loop','loopne','int3', 'db', 'ret', 'jmp', 'les', 'lds', 'jle','jl', 'jb','jbe','jg','jge','ja','jae', 'jne', 'je', 'js']

    def _initCategories(self):
        self._categories = {
                gadget.Category.STACK_PIVOT : (('^sub (?P<dst>.sp), (?P<src>[x0-9a-fA-F]+)$','^add (?P<dst>.sp), (?P<src>[x0-9a-fA-F]+)$','^mov (?P<dst>.sp), .+ ptr \[(?P<src>...)\]$','^mov (?P<dst>.sp), (?P<src>...)$','^xchg (?P<dst>.sp), (?P<src>...)$','^xchg (?P<dst>...), (?P<src>.sp)$','ret.+'),('mov','call','jmp')),
                gadget.Category.LOAD_MEM : (('mov (?P<dst>...), .+ ptr \[(?P<src>...)\]',),('mov','call','jmp')),
                gadget.Category.WRITE_MEM : (('^mov .+ ptr \[(?P<dst>...)\], (?P<src>...)$',),('mov','call','jmp')),
                gadget.Category.LOAD_REG : (('pop (?P<dst>...)',),('mov','call','jmp')),
                gadget.Category.JMP : (('^jmp (?P<dst>...)$',),()),
                gadget.Category.CALL : (('^call (?P<dst>...)$',),('mov','call','jmp')),
                gadget.Category.INC_REG : (('^inc (?P<dst>...)$', '^add (?P<dst>e?..), 1$'),('mov','call','jmp')),
                gadget.Category.CLEAR_REG : (('^xor (?P<dst>...), (?P<src>...)$',),('mov','call','jmp')),
                gadget.Category.SUB_REG : (('^sub (?P<dst>...), (?P<src>...)$',),('mov','call','jmp')),
                gadget.Category.ADD_REG : (('^add (?P<dst>...), (?P<src>...)$',),('mov','call','jmp')),
                gadget.Category.XCHG_REG : (('^xchg (?P<dst>...), (?P<src>...)$',),('mov','call','jmp')),
                gadget.Category.PUSHAD : (('^pushal$',),('mov','call','jmp')),
                gadget.Category.NEG_REG : (('^neg (?P<dst>...)$',),('mov','call','jmp')),
                gadget.Category.SYSCALL : (('^int (?P<dst>0x80)$',),('mov','call','jmp'))}



class ArchitectureX86_64(ArchitectureX86):

    def __init__(self):
        super(ArchitectureX86_64, self).__init__()
        self._name = 'x86_64'
        self._maxInvalid = 8
        if 'keystone' in globals():
            self._ksarch = (keystone.KS_ARCH_X86, keystone.KS_MODE_64)

        self._endings[gadget.GadgetType.SYS] = [(b'\x0f\x05',2),
                                                (b'\x0f\x05\xc3',3)]                            # syscall

        self._mode = CS_MODE_64
        if 'archinfo' in globals():
            self._info = archinfo.ArchAMD64()

        self._addressLength = 8
        self._pprs = [b'[\x58-\x5f]{2}\xc3', # pop reg; pop reg; ret
                        b'\x83\xc4\x08[\x58-\x5f]\xc3', # add esp, 4; pop reg; ret
                        b'[\x58-\x5f]\x83\xc4\x08\xc3', # pop reg; add esp, 4; ret
                        b'\x83\xc4\x10\xc3'             # add esp, 8; ret;
                        ]
        self._pprs.append(b'\x41?[\x58-\x5f]\x48\x83\xc4\x08\xc3')
        self._pprs.append(b'\x48\x83\xc4\x08\x41?[\x58-\x5f]\xc3')
        self._pprs.append(b'(\x41?[\x58-\x5f]){2}\xc3')
        self._pprs.append(b'\x48\x83\xc4\x10\xc3')

    def _initBadInstructions(self):
        super(ArchitectureX86_64, self)._initBadInstructions()
        self._badInstructions.append('jrcxz')

    def _initCategories(self):
        self._categories = {
                gadget.Category.STACK_PIVOT : (('^mov (?P<dst>.sp), .+ ptr \[(?P<src>...)\]$','^mov (?P<dst>.sp), (?P<src>...)$','^xchg (?P<dst>.sp), (?P<src>...)$','^xchg (?P<dst>...), (?P<src>.sp)$','ret.+'),('mov','call','jmp')),
                gadget.Category.LOAD_MEM : (('mov (?P<dst>r..), .+ ptr \[(?P<src>r..)\]',),('mov','call','jmp')),
                gadget.Category.WRITE_MEM : (('^mov .+ ptr \[(?P<dst>r..)\], (?P<src>r..)$',),('mov','call','jmp')),
                gadget.Category.LOAD_REG : (('pop (?P<dst>r..)',),('mov','call','jmp')),
                gadget.Category.JMP : (('^jmp (?P<dst>r..)$',),()),
                gadget.Category.CALL : (('^call (?P<dst>r..)$',),('mov','call','jmp')),
                gadget.Category.INC_REG : (('^inc (?P<dst>...)$', '^add (?P<dst>[er]?..), 1$'),('mov','call','jmp')),
                gadget.Category.CLEAR_REG : (('^xor (?P<dst>...), (?P<src>...)$',),('mov','call','jmp')),
                gadget.Category.SUB_REG : (('^sub (?P<dst>...), (?P<src>...)$',),('mov','call','jmp')),
                gadget.Category.ADD_REG : (('^add (?P<dst>...), (?P<src>...)$',),('mov','call','jmp')),
                gadget.Category.XCHG_REG : (('^xchg (?P<dst>...), (?P<src>...)$',),('mov','call','jmp')),
                gadget.Category.PUSHAD : (('^pushal$',),('mov','call','jmp')),
                gadget.Category.NEG_REG : (('^neg (?P<dst>...)$',),('mov','call','jmp')),
                gadget.Category.SYSCALL : (('^syscall$',),('mov','call','jmp'))}






class ArchitectureMips(Architecture):

    def __init__(self, endianess=Endianess.LITTLE):
        super(ArchitectureMips,self).__init__(CS_ARCH_MIPS, CS_MODE_32, 4, 4, endianess)
        self._name = 'MIPS'

        if 'keystone' in globals():
            self._ksarch = (keystone.KS_ARCH_MIPS, keystone.KS_MODE_MIPS32)

        if 'archinfo' in globals():
            self._info = archinfo.ArchMIPS32()

    def _initGadgets(self):
        super(ArchitectureMips, self)._initGadgets()
        self._endings[gadget.GadgetType.ROP] = []
        self._endings[gadget.GadgetType.JOP] = [(b'\x09\xf8\x20\x03', 4), # jalr t9
                                                (b'\x08\x00\x20\x03', 4), # jr t9
                                                (b'\x08\x00\xe0\x03', 4)] # jr ra


class ArchitectureMipsBE(ArchitectureMips):

    def __init__(self):
        super(ArchitectureMipsBE, self).__init__(Endianess.BIG)
        self._name = 'MIPSBE'
        self._mode |= CS_MODE_BIG_ENDIAN

class ArchitectureMips64(ArchitectureMips):

    def __init__(self, endianess=Endianess.LITTLE):
        super(ArchitectureMips64, self).__init__(endianess)
        self._name = 'MIPS64'

        if 'keystone' in globals():
            self._ksarch = (keystone.KS_ARCH_MIPS, keystone.KS_MODE_64)

        self._mode = CS_MODE_MIPS64
        if 'archinfo' in globals():
            self._info = archinfo.ArchMIPS64()

        self._addressLength = 8

    def _initGadgets(self):
        super(ArchitectureMips64, self)._initGadgets()


class ArchitectureMips64BE(ArchitectureMips64):

    def __init__(self):
        super(ArchitectureMips64BE, self).__init__(Endianess.BIG)
        self._name = 'MIPS64BE'
        self._mode |= CS_MODE_BIG_ENDIAN

class ArchitectureArm(Architecture):

    def __init__(self, endianess=Endianess.LITTLE):
        super(ArchitectureArm,self).__init__(CS_ARCH_ARM, CS_MODE_ARM, 4, 4, endianess)
        self._searcher = SearcherARM()
        self._name = 'ARM'

        if 'archinfo' in globals():
            self._info = archinfo.ArchARM()
        if 'keystone' in globals():
            self._ksarch = (keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM)

    def _initGadgets(self):
        super(ArchitectureArm, self)._initGadgets()
        self._endings[gadget.GadgetType.ROP] = [(b'[\x01-\xff]\x80\xbd\xe8', 4)] # pop {[reg]*,pc}
        self._endings[gadget.GadgetType.JOP] = [(b'[\x10-\x1e]\xff\x2f\xe1', 4), # bx <reg>
                                                (b'[\x30-\x3e]\xff\x2f\xe1', 4), # blx <reg>

                                                (b'\x01\x80\xbd\xe8', 4)] # ldm sp! ,{pc}


class ArchitectureArmBE(ArchitectureArm):
    
    def __init__(self):
        super(ArchitectureArmBE, self).__init__(Endianess.BIG)
        self._name = 'ARMBE'
        self._mode |= CS_MODE_BIG_ENDIAN

    def _initEndianess(self, endianess):
        super(ArchitectureArmBE, self)._initEndianess(endianess)    
        self._endings[gadget.GadgetType.ROP] = [(b'\xe8\xbd\x80[\x01-\xff]', 4)] # pop {[reg]*,pc}
        self._endings[gadget.GadgetType.JOP] = [(b'\xe1\x2f\xff[\x10-\x1e]', 4), # bx <reg>
                                                (b'\xe1\x2f\xff[\x30-\x3e]', 4), # blx <reg>

                                                (b'\xe8\xdb\x80\x01', 4)] # ldm sp! ,{pc}

class ArchitectureArmThumb(Architecture):

    def __init__(self):
        super(ArchitectureArmThumb, self).__init__(CS_ARCH_ARM, CS_MODE_THUMB, 4, 2)
        self._searcher = SearcherARM()
        self._name = 'ARMTHUMB'
        self._maxInvalid = 2

        if 'archinfo' in globals():
            self._info = archinfo.ArchARM()

        if 'keystone' in globals():
            self._ksarch = (keystone.KS_ARCH_ARM, keystone.KS_MODE_THUMB)

    def _initGadgets(self):
        super(ArchitectureArmThumb, self)._initGadgets()
        self._endings[gadget.GadgetType.ROP] = [(b'[\x00-\xff]\xbd', 2)] # pop {[regs]*,pc}
        self._endings[gadget.GadgetType.JOP] = [(b'[\x00-\x7f]\x47', 2), # bx <reg>
                                                (b'[\x80\x88\x90\x98\xa0\xa8\xb0\xb8\xc0\xc8\xd0\xd8\xe0\xe8\xf0\xf8]\x47', 2) # blx <reg>
                                                ]




class ArchitectureArm64(Architecture):

    def __init__(self):
        super(ArchitectureArm64, self).__init__(CS_ARCH_ARM64, CS_MODE_ARM, 4, 4)
        self._name = 'ARM64'

        if 'archinfo' in globals():
            self._info = archinfo.ArchAArch64()
        if 'keystone' in globals():
            self._ksarch = (keystone.KS_ARCH_ARM64, keystone.KS_MODE_BIG_ENDIAN)

    def _initGadgets(self):
        super(ArchitectureArm64, self)._initGadgets()
        self._endings[gadget.GadgetType.ROP] = [(b'[\x00\x20\x40\x60\x80\xa0\xc0\xe0][\x00-\x02]\x5f\xd6', 4), # ret <reg>
                                                (b'[\x00\x20\x40\x60\x80]\x03\x5f\xd6', 4), # ret <reg> (x24 - x28)
                                                (b'\xc0\x03\x5f\xd6', 4)] # ret

        self._endings[gadget.GadgetType.JOP] = [(b'[\x00\x20\x40\x60\x80\xa0\xc0\xe0][\x00-\x02]\x1f\xd6', 4), # br <reg>
                                                (b'[\x00\x20\x40\x60\x80]\x03\x1f\xd6', 4), # br <reg>
                                                (b'[\x00\x20\x40\x60\x80\xa0\xc0\xe0][\x00-\x02]\x3f\xd6', 4), # blr <reg>
                                                (b'[\x00\x20\x40\x60\x80]\x03\x3f\xd6', 4)] # blr <reg>



class ArchitecturePPC(Architecture):

    def __init__(self):
        super(ArchitecturePPC, self).__init__(CS_ARCH_PPC , CS_MODE_32 + CS_MODE_BIG_ENDIAN, 4, 4)
        self._name = 'PPC'

        if 'keystone' in globals():
            self._ksarch = (keystone.KS_ARCH_PPC, keystone.KS_MODE_32)

    def _initGadgets(self):
        super(ArchitecturePPC, self)._initGadgets()
        self._endings[gadget.GadgetType.ROP] = [(b'\x4e\x80\x00\x20', 4)] # blr
        self._endings[gadget.GadgetType.JOP] = []


class ArchitecturePPC64(ArchitecturePPC):

    def __init__(self):

        Architecture.__init__(self, CS_ARCH_PPC, CS_MODE_64 + CS_MODE_BIG_ENDIAN, 4, 4)
        self._name = 'PPC64'

        if 'keystone' in globals():
            self._ksarch = (keystone.KS_ARCH_PPC, keystone.KS_MODE_64)



x86 = ArchitectureX86()
x86_64 = ArchitectureX86_64()
MIPS = ArchitectureMips()
MIPSBE = ArchitectureMipsBE()
MIPS64 = ArchitectureMips64()
MIPS64BE = ArchitectureMips64BE()
ARM = ArchitectureArm()
ARMBE = ArchitectureArmBE()
ARMTHUMB = ArchitectureArmThumb()
ARM64 = ArchitectureArm64()
PPC = ArchitecturePPC()
PPC64 = ArchitecturePPC64()

def getArchitecture(archString):
    arch = globals().get(archString, None)

    if isinstance(arch, Architecture):
        return arch

    raise NotSupportedError('Architecture is not supported: ' + archString + '\nSupported architectures are: x86, x86_64, MIPS, MIPS64, ARM, ARMTHUMB, ARM64, PPC, PPC64')
