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

from capstone import *
from ropperapp.common.utils import *
from ropperapp.common.error import *
from ropperapp.common.enum import Enum
from .gadget import Gadget, GadgetType
from binascii import hexlify
import re
import struct
import sys


class Ropper(object):

    def __init__(self, binary):
        super(Ropper, self).__init__()
        self.__binary = binary
        self.__arch = binary.arch
        self.__disassembler = Cs(binary.arch.arch, binary.arch.mode)

    @property
    def arch(self):
        return self._arch

    def searchJmpReg(self, code, regs, virtualAddress=0x0,  badbytes='', section=None):
        if self.__arch.arch != CS_ARCH_X86:
            raise NotSupportedError(
                'Wrong architecture, pop pop ret is only supported on x86/x86_64')
        toReturn = []

        Register = Enum('Register', 'ax cx dx bx sp bp si di')
        regs = regs.split(',')
        for reg in regs:
            reg = reg.strip()[1:]
            insts = [toBytes(0xff , 0xe0 | Register[reg]), toBytes(0xff, 0xd0 | Register[reg]),  toBytes(0x50 | Register[reg] , 0xc3)]
            for inst in insts:

                toReturn.extend(self.searchOpcode(code, inst, virtualAddress, True, badbytes=badbytes, section=section))

        return sorted(toReturn, key=lambda x: str(x))

    def searchOpcode(self, code, opcode, virtualAddress=0x0, disass=False, badbytes='', section=None):

        toReturn = []
        code = bytearray(code)
        for index in range(len(code)):
            c = 0
            if code[index:index + len(opcode)] == opcode:
                opcodeGadget = Gadget(self.__arch)
                if disass:
                    for i in self.__disassembler.disasm(struct.pack('B' * len(opcode), *code[index:index + len(opcode)]), virtualAddress + index):
                        opcodeGadget.append(
                            i.address, i.mnemonic , i.op_str)
                else:
                    opcodeGadget.append(
                        virtualAddress + index, hexlify(opcode).decode('utf-8'))
                if c == 0 and opcodeGadget.addressesContainsBytes(badbytes):
                    continue
                c += 1
                opcodeGadget._binary = self.__binary
                opcodeGadget._section = section
                toReturn.append(opcodeGadget)
        return toReturn

    def searchPopPopRet(self, code, virtualAddress=0x0,  badbytes='', section=None):
        if self.__arch.arch != CS_ARCH_X86:
            raise NotSupportedError(
                'Wrong architecture, pop pop ret is only supported on x86/x86_64')

        toReturn = []

        for index in range(len(code)):
            if code[index] == 0xc3 and 0 not in code[index - 2:index + 1]:
                ppr = Gadget(self.__arch)
                c = 0
                for (address, size, mnemonic, op_str) in self.__disassembler.disasm_lite(struct.pack('BBB', *code[index - 2:index + 1]), virtualAddress + index -2):
                    if mnemonic != 'pop' and mnemonic != 'ret':
                        break
                    ppr.append(
                        address, mnemonic , op_str)
                    if c == 0 and ppr.addressesContainsBytes(badbytes):
                        break
                    c += 1
                    if mnemonic == 'ret':
                        break
                if len(ppr) == 3:
                    ppr._binary = self.__binary
                    ppr._section = section
                    toReturn.append(ppr)
        return toReturn

    def searchRopGadgets(self, code,  offset=0x0, virtualAddress=0x0, badbytes='',depth=10, gtype=GadgetType.ALL, pprinter=None, section=None):
        toReturn = []
        code = bytes(bytearray(code))

        def createGadget(code_str, codeStartAddress, ending):
            gadget = Gadget(self.__arch)
            gadget._binary = self.__binary
            gadget._section = section
            gadget.imageBase = virtualAddress
            hasret = False
            c = 0
            for i in self.__disassembler.disasm(code_str, codeStartAddress):
                if i.mnemonic not in self.__arch.badInstructions:
                    gadget.append(
                        i.address, i.mnemonic,i.op_str)
                    if c == 0 and gadget.addressesContainsBytes(badbytes):
                        return None
                    c += 1
                elif len(gadget) > 0:
                    break

                if re.match(ending[0], i.bytes):
                    hasret = True
                    break

            if hasret and len(gadget) > 0:

                return gadget

        max_prog = len(code) * len(self.__arch.endings[gtype])
        for ending in self.__arch.endings[gtype]:
            offset = 0
            tmp_code = code[:]
            match = re.search(ending[0], tmp_code)
            while match:
                offset += match.start()
                index = match.start()
                for x in range(1, (depth + 1) * self.__arch.align):
                    code_part = tmp_code[index - x:index + ending[1]]
                    gadget = createGadget(
                        code_part, offset - x, ending)
                    if gadget:
                        toReturn.append(gadget)

                tmp_code = tmp_code[index+1:]

                offset += self.__arch.align
                match = re.search(ending[0], tmp_code)
                if pprinter:
                    progress = self.__arch.endings[gtype].index(ending) * len(code) + len(code) - len(tmp_code)
                    pprinter.printProgress('loading gadgets...', float(progress) / max_prog)

        if pprinter:
            pprinter.printProgress('loading gadgets...', 1)
            pprinter.finishProgress();
        return self.__deleteDuplicates(toReturn, pprinter)

    
    def __disassembleBackward(self, code, vaddr,offset, count):
        gadget = Gadget(self.__arch)
        counter = 0
        toReturn = None
        while len(gadget) < count:
            gadget = Gadget(self.__arch)
            for i in self.__disassembler.disasm(struct.pack('B' * len(code[offset - counter:]), *bytearray(code[offset - counter:])), vaddr-counter):
                gadget.append(i.address, i.mnemonic , i.op_str)
                if i.address == vaddr:
                    toReturn = gadget
                    break
                if i.address > vaddr:
                    if len(gadget) > count:
                        return toReturn
                    gadget = Gadget(self.__arch)
                    break
            
                
            counter += self.__arch.align
            if offset - counter < 0:
                return toReturn

            if not toReturn:
                toReturn = Gadget(self.__arch)
                toReturn.append(vaddr,'bad instructions')
        return toReturn


    def disassemble(self, code, vaddr, offset, count):
        if vaddr % self.__arch.align != 0:
            raise RopperError('The address doesn\'t have the correct alignment')
        if count < 0:
            return self.__disassembleBackward(code, vaddr, offset, count*-1)
        gadget  = Gadget(self.__arch)
        c = 0
        
        for i in self.__disassembler.disasm(struct.pack('B' * len(code[offset:]), *bytearray(code[offset:])), vaddr):
            gadget.append(i.address, i.mnemonic , i.op_str)
            c += 1
            if c == count:
                break
        if not len(gadget):
            gadget.append(vaddr,'bad instructions')
        return gadget


    def __deleteDuplicates(self, gadgets, pprinter=None):
        toReturn = []
        inst = []
        gadgetString = None
        for i,gadget in enumerate(gadgets):
            gadgetString = gadget._gadget
            gadgetHash = hash(gadgetString)
            if gadgetHash not in inst:
                inst.append(gadgetHash)
                toReturn.append(gadget)
            if pprinter:
                pprinter.printProgress('clearing up...', float(i) / len(gadgets))
        if pprinter:
            pprinter.printProgress('clearing up...', 1)
            pprinter.finishProgress()
        
        return sorted(toReturn, key=Gadget.simpleInstructionString)


def toBytes(*b):
    return bytes(bytearray(b))
