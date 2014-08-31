#!/usr/bin/env python
# coding=utf-8
from capstone import *
from ropperapp.common.utils import *
from ropperapp.common.enum import Enum
from gadget import Gadget, GadgetType
import re
import struct
import sys


class Ropper(object):

    def __init__(self, arch):
        super(Ropper, self).__init__()
        self.__arch = arch
        self.__disassembler = Cs(arch.arch, arch.mode)

    @property
    def arch(self):
        return self._arch

    def searchJmpReg(self, code, regs, virtualAddress=0x0):
        if self.__arch.arch != CS_ARCH_X86:
            raise EnvironmentError(
                'Wrong architecture, pop pop ret is only supported on x86/x86_64')
        toReturn = []
        insts = [0xe0, 0xd0]

        Register = Enum('Register', 'ax cx dx bx sp bp si di')

        regs = regs.split(',')
        for reg in regs:
            reg = reg.strip()[1:]
            for inst in insts:
                
                toReturn.extend(self.searchOpcode(code, '\xff'+chr(inst | Register[reg]), virtualAddress, True))

        return sorted(toReturn)

    def searchOpcode(self, code, opcode, virtualAddress=0x0, disass=False):

        toReturn = []
        code = bytearray(code)
        for index in xrange(len(code)):
            if code[index:index + len(opcode)] == opcode:
                ppr = Gadget()
                if disass:
                    for i in self.__disassembler.disasm(struct.pack('B' * len(opcode), *code[index:index + len(opcode)]), virtualAddress + index):
                        ppr.append(
                            toHex(i.address, self.__arch.mode), i.mnemonic + ' ' + i.op_str)
                else:
                    ppr.append(
                        toHex(virtualAddress + index, self.__arch.mode), opcode.encode('hex'))

                toReturn.append(ppr)
        return toReturn

    def searchPopPopRet(self, code, virtualAddress=0x0):
        if self.__arch.arch != CS_ARCH_X86:
            raise EnvironmentError(
                'Wrong architecture, pop pop ret is only supported on x86/x86_64')

        toReturn = []

        for index in xrange(len(code)):
            if code[index] == 0xc3 and 0 not in code[index - 2:index + 1]:
                ppr = Gadget()
                for (address, size, mnemonic, op_str) in self.__disassembler.disasm_lite(struct.pack('BBB', *code[index - 2:index + 1]), virtualAddress + index):
                    if mnemonic != 'pop' and mnemonic != 'ret':
                        break
                    ppr.append(
                        toHex(address, self.__arch.mode), mnemonic + ' ' + op_str)
                if len(ppr) == 3:
                    toReturn.append(ppr)
        return toReturn

    def searchRopGadgets(self, code, virtualAddress=0x0, depth=10, gtype=GadgetType.ALL):
        toReturn = []

        code = str(bytearray(code))

        def createGadget(code_str, codeStartAddress, ending):
            gadget = Gadget()
            hasret = False
            for i in self.__disassembler.disasm(code_str, codeStartAddress):
                if i.mnemonic not in self.__arch.badInstructions:
                    gadget.append(
                        toHex(i.address, self.__arch.mode), i.mnemonic + ' ' + i.op_str)
                elif len(gadget) > 0:
                    break

                if re.match(ending[0], i.bytes):
                    hasret = True
                    break

            if hasret and len(gadget) > 1:
                return gadget

        for index in xrange(0, len(code), self.__arch.align):
            for ending in self.__arch.endings[gtype]:

                if re.match(ending[0], code[index:index + ending[1]]):
                    for x in range(1, (depth + 1) * self.__arch.align):
                        code_part = code[index - x:index + ending[1]]

                        gadget = createGadget(
                            code_part, virtualAddress + index - x, ending)

                        if gadget:
                            toReturn.append(gadget)
        return self.__deleteDuplicates(toReturn)

    def __deleteDuplicates(self, gadgets):
        toReturn = []
        inst = []
        gadgetString = None
        for gadget in gadgets:
            gadgetString = gadget._gadget
            if gadgetString not in inst:
                inst.append(gadgetString)
                toReturn.append(gadget)
        return toReturn
