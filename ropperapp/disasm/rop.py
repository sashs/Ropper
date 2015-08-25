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
import re
import struct
import sys


class Ropper(object):

    def __init__(self, binary, printer=None):
        super(Ropper, self).__init__()
        self.__binary = binary
        self.__arch = binary.arch
        self.printer = printer
        self.__disassembler = Cs(binary.arch.arch, binary.arch.mode)

    @property
    def arch(self):
        return self._arch

    def searchJmpReg(self, regs, badbytes=''):
        toReturn = []
        for section in self.__binary.executableSections:
            gadgets = self.__searchJmpReg(section, regs, badbytes=self._formatBadBytes(badbytes))
            toReturn.extend(gadgets)

        return toReturn


    def __searchJmpReg(self, section, regs,  badbytes=''):
        if self.__arch.arch != CS_ARCH_X86:
            raise NotSupportedError(
                'Wrong architecture, pop pop ret is only supported on x86/x86_64')
        toReturn = []
        Register = Enum('Register', 'ax cx dx bx sp bp si di')
        
        for reg in regs:
            reg_tmp = reg.strip()[1:]
            if not Register[reg_tmp]:
                raise RopperError('Invalid register: "%s"' % reg)
            insts = [toBytes(0xff , 0xe0 | Register[reg_tmp]), toBytes(0xff, 0xd0 | Register[reg_tmp]),  toBytes(0x50 | Register[reg_tmp] , 0xc3)]
            
            for inst in insts:
                toReturn.extend(self.__searchOpcode(section, inst, True, badbytes=badbytes))

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
                high = int(opcode[m.start()-1],16)
                start = high << 4
                end  = start + 0xf
                opcode = opcode[:m.start()-1] + hexlify(b'['+chr(start)+'-'+chr(end)+']') + opcode[m.start()+1:]

            m = re.search('\?', opcode)
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

    def searchOpcode(self, opcode, disass=False, badbytes=''):
        opcode = self._formatOpcodeString(opcode)
        gadgets = []
        for section in self.__binary.executableSections:
            gadgets.extend(self.__searchOpcode(section, opcode, badbytes=self._formatBadBytes(badbytes)))
        
        return gadgets

    def __searchOpcode(self, section, opcode, disass=False, badbytes=''):
        
        toReturn = []
        code = bytearray(section.bytes)
        offset = section.offset
        for match in re.finditer(opcode, code):
            c = 0
            opcodeGadget = Gadget(self.__arch)
            opcodeGadget._binary = self.__binary
            opcodeGadget._section = section

            if (offset + match.start()) % self.__arch.align == 0:
                if disass:
                    for i in self.__disassembler.disasm(struct.pack('B' * len(opcode), *code[match.start():match.end()]), offset + match.start()):
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


    def searchPopPopRet(self, badbytes=''):
        toReturn = []
        for section in self.__binary.executableSections:

            pprs = self.__searchPopPopRet(section, badbytes=self._formatBadBytes(badbytes))
            toReturn.extend(pprs)
        return toReturn

    def __searchPopPopRet(self, section, badbytes=''):
        if self.__arch.arch != CS_ARCH_X86:
            raise NotSupportedError(
                'Wrong architecture, pop pop ret is only supported on x86/x86_64')

        code = section.bytes
        offset = section.offset
        toReturn = []

        for index in range(len(code)):
            if code[index] == 0xc3 and 0 not in code[index - 2:index + 1]:
                ppr = Gadget(self.__arch)
                ppr._binary = self.__binary
                ppr._section = section
                c = 0
                for (address, size, mnemonic, op_str) in self.__disassembler.disasm_lite(struct.pack('BBB', *code[index - 2:index + 1]), offset + index -2):
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

    def searchRopGadgets(self, badbytes='', depth=10, gtype=GadgetType.ALL, all=False):
        gadgets = []
        for section in self.__binary.executableSections:
            vaddr = self.__binary.calculateImageBase(section)

            if self.printer:
                self.printer.printInfo('Loading gadgets for section: ' + section.name)
            
            newGadgets = self.__searchRopGadgets(section=section, badbytes=self._formatBadBytes(badbytes), depth=depth, gtype=gtype)
            gadgets.extend(newGadgets)

        if not all:
            gadgets = self.__deleteDuplicates(gadgets)
        return gadgets

    def __searchRopGadgets(self, section, badbytes='',depth=10, gtype=GadgetType.ALL):
        toReturn = []
        code = bytes(bytearray(section.bytes))
        offset = section.offset

        def createGadget(code_str, codeStartAddress, ending):
            gadget = Gadget(self.__arch)
            gadget._binary = self.__binary
            gadget._section = section
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
            offset_tmp = 0
            tmp_code = code[:]
            
            match = re.search(ending[0], tmp_code)
            while match:
                offset_tmp += match.start()
                index = match.start()

                if offset_tmp % self.__arch.align == 0:
                    for x in range(1, (depth + 1) * self.__arch.align):
                        code_part = tmp_code[index - x:index + ending[1]]
                        gadget = createGadget(
                            code_part, offset + offset_tmp - x, ending)
                        if gadget:
                            toReturn.append(gadget)

                tmp_code = tmp_code[index+self.__arch.align:]
                offset_tmp += self.__arch.align

                match = re.search(ending[0], tmp_code)
                
                if self.printer:
                    progress = self.__arch.endings[gtype].index(ending) * len(code) + len(code) - len(tmp_code)
                    self.printer.printProgress('loading gadgets...', float(progress) / max_prog)

        if self.printer:
            self.printer.printProgress('loading gadgets...', 1)
            self.printer.finishProgress();
        
        return toReturn


    def __disassembleBackward(self, section, vaddr,offset, count):
        gadget = Gadget(self.__arch)
        gadget._binary = self.__binary
        gadget._section = section
        counter = 0
        toReturn = None
        code = bytes(bytearray(section.bytes))
        while len(gadget) < count:
            gadget = Gadget(self.__arch)
            gadget._binary = self.__binary
            gadget._section = section
            for i in self.__disassembler.disasm(struct.pack('B' * len(code[offset - counter:]), *bytearray(code[offset - counter:])), vaddr-counter):
                gadget.append(i.address, i.mnemonic , i.op_str)
                if i.address == vaddr:
                    toReturn = gadget
                    break
                if i.address > vaddr:
                    if len(gadget) > count:
                        return toReturn
                    gadget = Gadget(self.__arch)
                    gadget._binary = self.__binary
                    gadget._section = section
                    break


            counter += self.__arch.align
            if offset - counter < 0:
                return toReturn

            if not toReturn:
                toReturn = Gadget(self.__arch)
                toReturn.append(vaddr,'bad instructions')
        return toReturn


    def disassemble(self, section, vaddr, offset, count):
        if vaddr % self.__arch.align != 0:
            raise RopperError('The address doesn\'t have the correct alignment')

        code = bytes(bytearray(section.bytes))

        if count < 0:
            return self.__disassembleBackward(section, vaddr, offset, count*-1)
        gadget  = Gadget(self.__arch)
        gadget._binary = self.__binary
        gadget._section = section
        c = 0

        for i in self.__disassembler.disasm(struct.pack('B' * len(code[offset:]), *bytearray(code[offset:])), offset):
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
