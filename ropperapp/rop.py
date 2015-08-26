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
from binascii import hexlify, unhexlify
from struct import pack
import re
import struct
import sys


class Ropper(object):

    def __init__(self, printer=None):
        super(Ropper, self).__init__()
        self.printer = printer
        

    def searchJmpReg(self, binary, regs, badbytes=''):
        toReturn = []
        for section in binary.executableSections:

            gadgets = self._searchJmpReg(section, binary, regs, badbytes=self._formatBadBytes(badbytes))
            toReturn.extend(gadgets)

        return toReturn


    def _searchJmpReg(self, section, binary, regs,  badbytes=''):
        if binary.arch.arch != CS_ARCH_X86:
            raise NotSupportedError(
                'Wrong architecture, \'jmp <reg>\' only supported on x86/x86_64')
        disassembler = Cs(binary.arch.arch, binary.arch.mode)
        toReturn = []
        Register = Enum('Register', 'ax cx dx bx sp bp si di')
        
        for reg in regs:
            reg_tmp = reg.strip()[1:]
            if not Register[reg_tmp]:
                raise RopperError('Invalid register: "%s"' % reg)
            insts = [toBytes(0xff , 0xe0 | Register[reg_tmp]), toBytes(0xff, 0xd0 | Register[reg_tmp]),  toBytes(0x50 | Register[reg_tmp] , 0xc3)]
            
            for inst in insts:
                toReturn.extend(self._searchOpcode(section, binary, inst, True, badbytes=badbytes))

        return sorted(toReturn, key=lambda x: str(x))


    def _formatOpcodeString(self, opcode):
        if len(opcode) % 2 > 0:
            raise RopperError('The length of the opcode has to be a multiple of two')

        opcode = opcode.encode('ascii')
        m = re.search(b'\?', opcode)
        while m:

            if m.start() % 2 == 0:
                if opcode[m.start()+1] == '?':
                    opcode = opcode[:m.start()] + hexlify(b'[\x00-\xff]') +  opcode[m.start()+2:]
                else:
                    raise RopperError('A ? for the highest 4 bit of a byte is not supported (e.g. ?1, ?2, ..., ?a)')
            elif m.start() % 2 == 1:
                char = opcode[m.start()-1]
                if type(char) == int:
                    char = chr(char)
                high = int(char,16)
                start = high << 4
                end  = start + 0xf
                #import pdb;pdb.set_trace()
                opcode = opcode[:m.start()-1] + hexlify(b'['+pack('B',start)+b'-'+pack('B',end)+b']') + opcode[m.start()+1:]

            m = re.search(b'\?', opcode)
        try:
            opcode = unhexlify(opcode)
        except:
            raise RopperError('Invalid characters in opcode string')
        return opcode

    def _formatBadBytes(self, badbytes):
        if len(badbytes) % 2 > 0:
            raise RopperError('The length of badbytes has to be a multiple of two')

        try:
            badbytes = unhexlify(badbytes)
        except:
            raise RopperError('Invalid characters in badbytes string')
        return badbytes

    def searchOpcode(self, binary, opcode, disass=False, badbytes=''):
        opcode = self._formatOpcodeString(opcode)
        gadgets = []
        for section in binary.executableSections:
            gadgets.extend(self._searchOpcode(section, binary, opcode, badbytes=self._formatBadBytes(badbytes)))
        
        return gadgets

    def _searchOpcode(self, section, binary, opcode, disass=False, badbytes=''):

        disassembler = Cs(binary.arch.arch, binary.arch.mode)
        toReturn = []
        code = bytearray(section.bytes)
        offset = section.offset
        for match in re.finditer(opcode, code):
            c = 0
            opcodeGadget = Gadget(binary, section)

            if (offset + match.start()) % binary.arch.align == 0:
                if disass:
                    for i in disassembler.disasm(struct.pack('B' * len(opcode), *code[match.start():match.end()]), offset + match.start()):
                        opcodeGadget.append(
                            i.address, i.mnemonic , i.op_str)
                else:
                    opcodeGadget.append(
                        offset + match.start(), hexlify(match.group(0)).decode('utf-8'))
            else:
                continue
            if c == 0 and opcodeGadget.addressesContainsBytes(badbytes):
                continue
            c += 1
            toReturn.append(opcodeGadget)

        return toReturn


    def searchPopPopRet(self, binary, badbytes=''):
        toReturn = []
        for section in binary.executableSections:

            pprs = self._searchPopPopRet(section,binary, badbytes=self._formatBadBytes(badbytes))
            toReturn.extend(pprs)
        return toReturn

    def _searchPopPopRet(self, section, binary, badbytes=''):
        if binary.arch.arch != CS_ARCH_X86:
            raise NotSupportedError(
                'Wrong architecture, \'pop pop ret\' is only supported on x86/x86_64')

        disassembler = Cs(binary.arch.arch, binary.arch.mode)
        code = section.bytes
        offset = section.offset
        toReturn = []

        for index in range(len(code)):
            if code[index] == 0xc3 and 0 not in code[index - 2:index + 1]:
                ppr = Gadget(binary,section)
                c = 0
                for (address, size, mnemonic, op_str) in disassembler.disasm_lite(struct.pack('BBB', *code[index - 2:index + 1]), offset + index -2):
                    if mnemonic != 'pop' and mnemonic != 'ret':
                        break
                    ppr.append(
                        address, mnemonic , op_str)
                    if c == 0 and ppr.addressesContainsBytes(badbytes):
                        break
                    c += 1
                    if mnemonic.startswith('ret'):
                        break
                if len(ppr) == 3:
                    
                    toReturn.append(ppr)
        return toReturn

    def searchRopGadgets(self, binary, badbytes='', depth=10, gtype=GadgetType.ALL, all=False):
        gadgets = []
        for section in binary.executableSections:
            vaddr = binary.calculateImageBase(section)

            if self.printer:
                self.printer.printInfo('Loading gadgets for section: ' + section.name)
            
            newGadgets = self._searchRopGadgets(section=section, binary=binary, badbytes=self._formatBadBytes(badbytes), depth=depth, gtype=gtype)
            gadgets.extend(newGadgets)

        if not all:
            gadgets = self.__deleteDuplicates(gadgets)
        return gadgets

    def _searchRopGadgets(self, section, binary, badbytes='',depth=10, gtype=GadgetType.ALL):

        toReturn = []
        code = bytes(bytearray(section.bytes))
        offset = section.offset
        disassembler = Cs(binary.arch.arch, binary.arch.mode)
        arch = binary.arch
        def createGadget(code_str, codeStartAddress, ending):
            gadget = Gadget(binary, section)
            hasret = False
            c = 0
            for i in disassembler.disasm(code_str, codeStartAddress):
                if i.mnemonic not in binary.arch.badInstructions:
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

        max_prog = len(code) * len(arch.endings[gtype])
        for ending in arch.endings[gtype]:
            offset_tmp = 0
            tmp_code = code[:]
            
            match = re.search(ending[0], tmp_code)
            while match:
                offset_tmp += match.start()
                index = match.start()

                if offset_tmp % arch.align == 0:
                    for x in range(1, (depth + 1) * arch.align):
                        code_part = tmp_code[index - x:index + ending[1]]
                        gadget = createGadget(
                            code_part, offset + offset_tmp - x, ending)
                        if gadget:
                            toReturn.append(gadget)

                tmp_code = tmp_code[index+arch.align:]
                offset_tmp += arch.align

                match = re.search(ending[0], tmp_code)
                
                if self.printer:
                    progress = arch.endings[gtype].index(ending) * len(code) + len(code) - len(tmp_code)
                    self.printer.printProgress('loading gadgets...', float(progress) / max_prog)

        if self.printer:
            self.printer.printProgress('loading gadgets...', 1)
            self.printer.finishProgress();
        
        return toReturn


    def __disassembleBackward(self, section, binary, vaddr,offset, count):
        gadget = Gadget(binary, section)
        counter = 0
        toReturn = None
        code = bytes(bytearray(section.bytes))
        disassembler = Cs(binary.arch.arch, binary.arch.mode)

        while len(gadget) < count:
            gadget = Gadget(binary, section)
            for i in disassembler.disasm(struct.pack('B' * len(code[offset - counter:]), *bytearray(code[offset - counter:])), vaddr-counter):
                gadget.append(i.address, i.mnemonic , i.op_str)
                if i.address == vaddr:
                    toReturn = gadget
                    break
                if i.address > vaddr:
                    if len(gadget) > count:
                        return toReturn
                    gadget = Gadget(binary, section)
                    break


            counter += binary.arch.align
            if offset - counter < 0:
                return toReturn

            if not toReturn:
                toReturn = Gadget(binary, section)
                toReturn.append(vaddr,'bad instructions')
        return toReturn


    def disassemble(self, section, binary, vaddr, offset, count):
        if vaddr % binary.arch.align != 0:
            raise RopperError('The address doesn\'t have the correct alignment')

        code = bytes(bytearray(section.bytes))
        disassembler = Cs(binary.arch.arch, binary.arch.mode)

        if count < 0:
            return self.__disassembleBackward(section, binary, vaddr, offset, count*-1)
        gadget  = Gadget(binary, section)
        c = 0

        for i in disassembler.disasm(struct.pack('B' * len(code[offset:]), *bytearray(code[offset:])), offset):
            gadget.append(i.address, i.mnemonic , i.op_str)
            c += 1
            if c == count:
                break
        if not len(gadget):
            gadget.append(vaddr,'bad instructions')
        return gadget


    def __deleteDuplicates(self, gadgets):
        toReturn = []
        inst = []
        gadgetString = None
        for i,gadget in enumerate(gadgets):
            gadgetString = gadget._gadget
            gadgetHash = hash(gadgetString)
            if gadgetHash not in inst:
                inst.append(gadgetHash)
                toReturn.append(gadget)
            if self.printer:
                self.printer.printProgress('clearing up...', float(i) / len(gadgets))
        if self.printer:
            self.printer.printProgress('clearing up...', 1)
            self.printer.finishProgress()

        return sorted(toReturn, key=Gadget.simpleInstructionString)


def toBytes(*b):
    return bytes(bytearray(b))
