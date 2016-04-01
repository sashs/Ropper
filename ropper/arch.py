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
from ropper.common.error import NotSupportedError
from ropper.search.search import Searcher
from ropper.search.search import Searcherx86
from ropper.search.search import SearcherARM
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
        self._categories = {}

        self._searcher = Searcher()

        self._initGadgets()
        self._initBadInstructions()
        self._initCategories()

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

    def __str__(self):
        return self.__class__.__name__


class ArchitectureX86(Architecture):

    def __init__(self):
        Architecture.__init__(self, CS_ARCH_X86, CS_MODE_32, 4, 1)

        self._searcher = Searcherx86()

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
            (b'\xff[\xd0\xd1\xd2\xd3\xd4\xd6\xd7]', 2),
            (b'\xff[\x14\x24]\x24', 3),
            (b'\xff[\x55\x65]\x00', 3),
            (b'\xff[\xa0\xa1\xa2\xa3\xa6\xa7][\x00-\x0ff]{4}', 6),
            (b'\xff\xa4\x24[\x00-\xff]{4}', 7),
            (b'\xff[\x50-\x53\x55-\x57][\x00-\xff]{1}', 3),                             # call [reg + value]
            (b'\xff[\x60-\x63\x65-\x67][\x00-\xff]{1}', 3),                             # jmp [reg + value]
            (b'\xff[\x90\x91\x92\x93\x94\x96\x97][\x00-\x0ff]{4}', 6)]

    def _initBadInstructions(self):
        self._badInstructions = ['retf','enter','loop','loopne','int3', 'db', 'jne', 'je', 'jg', 'jl', 'jle', 'jge', 'ja','jb', 'jae', 'jbe', 'int', 'ret', 'call', 'jmp']

    def _initCategories(self):
        self._categories = {
                gadget.Category.STACK_PIVOT : (('^mov (?P<dst>.sp), .+ ptr \[(?P<src>...)\]$','^mov (?P<dst>.sp), (?P<src>...)$','^xchg (?P<dst>.sp), (?P<src>...)$','^xchg (?P<dst>...), (?P<src>.sp)$','ret.+'),('mov','call','jmp')),
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
        ArchitectureX86.__init__(self)

        self._endings[gadget.GadgetType.SYS] = [(b'\x0f\x05',2),
                                                (b'\x0f\x05\xc3',3)]                            # syscall

        self._mode = CS_MODE_64

        self._addressLength = 8

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

    def __init__(self):
        Architecture.__init__(self, CS_ARCH_MIPS, CS_MODE_32, 4, 4)

    def _initGadgets(self):
        super(ArchitectureMips, self)._initGadgets()
        self._endings[gadget.GadgetType.ROP] = []
        self._endings[gadget.GadgetType.JOP] = [(b'\x09\xf8\x20\x03', 4), # jalr t9
                                                (b'\x08\x00\x20\x03', 4), # jr t9
                                                (b'\x08\x00\xe0\x03', 4)] # jr ra


class ArchitectureMips64(ArchitectureMips):

    def __init__(self):
        ArchitectureMips.__init__(self)

        self._mode = CS_MODE_64

        self._addressLength = 8

    def _initGadgets(self):
        super(ArchitectureMips64, self)._initGadgets()
        

class ArchitectureArm(Architecture):

    def __init__(self):
        Architecture.__init__(self, CS_ARCH_ARM, CS_MODE_ARM, 4, 4)
        self._searcher = SearcherARM()

    def _initGadgets(self):
        super(ArchitectureArm, self)._initGadgets()
        self._endings[gadget.GadgetType.ROP] = [(b'[\x01-\xff]\x80\xbd\xe8', 4)] # pop {[reg]*,pc}
        self._endings[gadget.GadgetType.JOP] = [(b'[\x10-\x1e]\xff\x2f\xe1', 4), # bx <reg>
                                                (b'[\x30-\x3e]\xff\x2f\xe1', 4), # blx <reg>

                                                (b'\x01\x80\xbd\xe8', 4)] # ldm sp! ,{pc}

class ArchitectureArmThumb(Architecture):

    def __init__(self):
        Architecture.__init__(self, CS_ARCH_ARM, CS_MODE_THUMB, 4, 2)
        self._searcher = SearcherARM()

    def _initGadgets(self):
        super(ArchitectureArmThumb, self)._initGadgets()
        self._endings[gadget.GadgetType.ROP] = [(b'[\x00-\xff]\xbd', 2)] # pop {[regs]*,pc}
        self._endings[gadget.GadgetType.JOP] = [(b'[\x00-\x7f]\x47', 2), # bx <reg>
                                                (b'[\x80\x88\x90\x98\xa0\xa8\xb0\xb8\xc0\xc8\xd0\xd8\xe0\xe8\xf0\xf8]\x47', 2) # blx <reg>
                                                ]




class ArchitectureArm64(Architecture):

    def __init__(self):
        Architecture.__init__(self, CS_ARCH_ARM64, CS_MODE_ARM, 4, 4)

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
        Architecture.__init__(self, CS_ARCH_PPC , CS_MODE_32 + CS_MODE_BIG_ENDIAN, 4, 4)

    def _initGadgets(self):
        super(ArchitecturePPC, self)._initGadgets()
        self._endings[gadget.GadgetType.ROP] = [(b'\x4e\x80\x00\x20', 4)] # blr
        self._endings[gadget.GadgetType.JOP] = []

class ArchitecturePPC64(ArchitecturePPC):

    def __init__(self):

        Architecture.__init__(self, CS_ARCH_PPC , CS_MODE_64 + CS_MODE_BIG_ENDIAN, 4, 4)



x86 = ArchitectureX86()
x86_64 = ArchitectureX86_64()
MIPS = ArchitectureMips()
MIPS64 = ArchitectureMips64()
ARM = ArchitectureArm()
ARMTHUMB = ArchitectureArmThumb()
ARM64 = ArchitectureArm64()
PPC = ArchitecturePPC()
PPC64 = ArchitecturePPC64()

def getArchitecture(archString):
    arch = globals().get(archString, None)

    if isinstance(arch, Architecture):
        return arch

    raise NotSupportedError('Architecture is not supported: ' + archString + '\nSupported architectures are: x86, x86_64, MIPS, MIPS64, ARM, ARMTHUMB, ARM64, PPC, PPC64')
