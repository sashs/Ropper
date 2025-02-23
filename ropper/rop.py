# coding=utf-8
# Copyright 2018 Sascha Schirra
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" A ND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from ropper.common.utils import *
from ropper.common.error import *
from ropper.common.enum import Enum
from ropper.arch import x86
from multiprocessing import Process, Pool, Queue, cpu_count, current_process, JoinableQueue
from .gadget import Gadget, GadgetType
from binascii import hexlify, unhexlify
from struct import pack
import re
import multiprocessing as mp
import struct
import sys
import capstone

# Optional keystone support
try:
    import keystone
except:
    pass


class Format(Enum):
    _enum_ = 'RAW STRING HEX'

class Ropper(object):

    def __init__(self, callback=None):
        """
        callback function signature:
        def callback(section, gadgets, progress)
        """
        super(Ropper, self).__init__()
        self.__callback = callback
        self.__cs = None


    def __getCs(self, arch):
        if not self.__cs or self.__cs.arch != arch.arch or self.__cs.mode != arch.mode:
            self.__cs = capstone.Cs(arch.arch, arch.mode)
        return self.__cs

    def assemble(self, code, arch=x86, format=Format.HEX):
        if 'keystone' not in globals():
            raise RopperError('Keystone is not installed! Please install Keystone. \nLook at http://keystone-engine.org')

        ks = keystone.Ks(arch.ksarch[0], arch.ksarch[1])
        try:
            byte_list =  ks.asm(code.encode('ascii'))[0]
        except BaseException as e:
            raise RopperError(e)

        if not byte_list:
            return "invalid"
        to_return = byte_list

        if format == Format.STRING:
            to_return = '"'
            for byte in byte_list:
                to_return += '\\x%02x' % byte

            to_return += '"'
        elif format == Format.HEX:
            to_return = ''
            for byte in byte_list:
                to_return += '%02x' % byte
        elif format == Format.RAW:
            to_return = ''
            for byte in byte_list:
                to_return += '%s' % chr(byte)

        return to_return

    def disassemble(self, opcode, arch=x86):
        opcode, size= self._formatOpcodeString(opcode, regex=False)
        cs = self.__getCs(arch)

        to_return = ''
        byte_count = 0

        opcode_tmp = opcode

        while byte_count < size:
            old_byte_count = byte_count
            for i in cs.disasm(opcode_tmp,0):
                to_return += '%s %s\n' % (i.mnemonic , i.op_str)
                byte_count += len(i.bytes)

            if old_byte_count == byte_count or byte_count < len(opcode):
                byte_count += 1
                opcode_tmp = opcode[byte_count:]
                to_return += '<invalid>\n'

        return to_return

    def searchJmpReg(self, binary, regs):
        toReturn = []
        Gadget.IMAGE_BASES[binary.checksum] = binary.imageBase
        for section in binary.executableSections:

            gadgets = self._searchJmpReg(section, binary, regs)
            toReturn.extend(gadgets)

        return toReturn


    def _searchJmpReg(self, section, binary, regs):
        if binary.arch.arch != capstone.CS_ARCH_X86:
            raise NotSupportedError(
                'Wrong architecture, \'jmp <reg>\' only supported on x86/x86_64')

        cs = self.__getCs(binary.arch)
        toReturn = []
        Register = Enum('Register', 'ax cx dx bx sp bp si di')

        for reg in regs:
            reg_tmp = reg.strip()[1:]
            if not Register[reg_tmp]:
                raise RopperError('Invalid register: "%s"' % reg)
            insts = [toBytes(0xff , 0xe0 | Register[reg_tmp]), toBytes(0xff, 0xd0 | Register[reg_tmp]),  toBytes(0x50 | Register[reg_tmp] , 0xc3)]

            for inst in insts:
                toReturn.extend(self._searchOpcode(section, binary, inst, len(inst),True))

        return sorted(toReturn, key=lambda x: str(x))



    def _formatOpcodeString(self, opcode, regex=True):
        if len(opcode) % 2 > 0:
            raise RopperError('The length of the opcode has to be a multiple of two')

        opcode = opcode.encode('ascii')
        size = int(len(opcode)/2)
        for b in (b'5c',b'5d',b'5b',b'28',b'29',b'2b',b'2a',b'2e',b'3f'):

            if opcode.find(b) % 2 == 0:
                opcode = opcode.replace(b,b'%s%s' % (hexlify(b'\\'),b))

        m = re.search(b'\?', opcode)
        while m:
            if m.start() % 2 == 0:
                char = opcode[m.start()+1]
                if type(char) == int:
                    char = chr(char)
                if char == '?':
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

                opcode = opcode[:m.start()-1] + hexlify(b'['+pack('B',start)+b'-'+pack('B',end)+b']') + opcode[m.start()+1:]

            m = re.search(b'\?', opcode)
        try:

            opcode = unhexlify(opcode)

        except BaseException as e:
            #raise RopperError(e)
            raise RopperError('Invalid characters in opcode string: %s' % opcode)
        return opcode,size


    def searchInstructions(self, binary, code):
        Gadget.IMAGE_BASES[binary.checksum] = binary.imageBase
        opcode = self.assemble(code, binary.arch)
        return self.searchOpcode(binary, opcode, disass=True)


    def searchOpcode(self, binary, opcode, disass=False):
        Gadget.IMAGE_BASES[binary.checksum] = binary.imageBase
        opcode, size = self._formatOpcodeString(opcode)
        gadgets = []
        for section in binary.executableSections:
            gadgets.extend(self._searchOpcode(section, binary, opcode, size, disass))

        return gadgets


    def _searchOpcode(self, section, binary, opcode, size, disass=False):

        disassembler = self.__getCs(binary.arch)
        toReturn = []
        code = bytearray(section.bytes)
        # TODO: Another solution should be used here. This is a hack for compatibility reasons. to resolve the gadget address calculation of segments of elf files have a different base address if calculated segment.virtualAddress - segment.offset 
        offset = section.offset - (binary.originalImageBase - (section.virtualAddress - section.offset))
        for match in re.finditer(opcode, code):
            opcodeGadget = Gadget(binary.checksum, section.name, binary.arch)

            if (offset + match.start()) % binary.arch.align == 0:
                if disass:
                    could_disass = False
                    #for i in disassembler.disasm(struct.pack('B' * size, *code[match.start():match.end()]), offset + match.start()):
                    for i in disassembler.disasm(struct.pack('B' * size, *code[match.start():match.end()]), offset + match.start()):
                        opcodeGadget.append(
                            i.address, i.mnemonic , i.op_str, bytes=i.bytes)
                        could_disass = True
                    if not could_disass:
                        continue
                else:
                    opcodeGadget.append(
                        offset + match.start(), hexlify(match.group(0)).decode('utf-8'),bytes=match.group())
            else:
                continue

            toReturn.append(opcodeGadget)

        return toReturn


    def searchPopPopRet(self, binary):
        Gadget.IMAGE_BASES[binary.checksum] = binary.imageBase
        toReturn = []
        for section in binary.executableSections:

            pprs = self._searchPopPopRet(section,binary)
            toReturn.extend(pprs)


        return toReturn

    def _searchPopPopRet(self, section, binary):
        if not isinstance(binary.arch, x86.__class__ ):
            raise NotSupportedError(
                'Wrong architecture, \'pop pop ret\' is only supported on x86')

        disassembler = self.__getCs(binary.arch)
        code = section.bytes
        # TODO: Another solution should be used here. This is a hack for compatibility reasons. to resolve the gadget address calculation of segments of elf files have a different base address if calculated segment.virtualAddress - segment.offset 
        offset = section.offset - (binary.originalImageBase - (section.virtualAddress - section.offset))
        toReturn = []
        pprs = binary.arch.pprs
        for ppr in pprs:
            for match in re.finditer(ppr, code):
                if (offset + match.start()) % binary.arch.align == 0:
                    pprg = Gadget(binary.checksum,section.name, binary.arch)
                    for i in disassembler.disasm(bytes(bytearray(code)[match.start():match.end()]), offset + match.start()):
                        pprg.append(i.address, i.mnemonic , i.op_str, bytes=i.bytes)

                    toReturn.append(pprg)
        return toReturn

    def searchGadgets(self, binary, instructionCount=5, gtype=GadgetType.ALL, multiprocessing=False):
        if Gadget.IMAGE_BASES.get(binary.checksum) == None:
            Gadget.IMAGE_BASES[binary.checksum] = binary.originalImageBase
        gadgets = []
        for section in binary.executableSections:

            if self.__callback:
                self.__callback(section, None, 0)

            if not multiprocessing:
                newGadgets = self._searchGadgetsSingle(section=section, binary=binary, instruction_count=instructionCount, gtype=gtype)
            else:
                if mp.get_start_method() != 'fork':
                    mp.set_start_method('fork', force=True)
                newGadgets = self._searchGadgetsForked(section=section, binary=binary, instruction_count=instructionCount, gtype=gtype)

            gadgets.extend(newGadgets)

        return sorted(gadgets, key=Gadget.simpleInstructionString)

    def _searchGadgetsSingle(self, section, binary, instruction_count=5, gtype=GadgetType.ALL):

        toReturn = []
        code = memoryview(section.bytes)
        # TODO: Another solution should be used here. This is a hack for compatibility reasons. to resolve the gadget address calculation of segments of elf files have a different base address if calculated segment.virtualAddress - segment.offset 
        offset = section.offset - (binary.originalImageBase - (section.virtualAddress - section.offset))
        #offset = section.offset

        arch = binary.arch

        max_progress = len(code) * len(arch.endings[gtype])

        vaddrs = set()
        for ending in arch.endings[gtype]:
            offset_tmp = 0
            tmp_code = code[:]

            match = re.search(ending[0], tmp_code)
            while match:
                offset_tmp += match.start()
                index = match.start()

                if offset_tmp % arch.align == 0:
                    #for x in range(arch.align, (depth + 1) * arch.align, arch.align): # This can be used if you want to use a bytecount instead of an instruction count per gadget
                    none_count = 0

                    for x in range(0, index+1, arch.align):
                        code_part = tmp_code[index - x:index + ending[1]]
                        gadget, leng = self.__createGadget(arch, code_part, offset + offset_tmp - x, ending,binary.checksum, section.name)
                        if gadget:
                            if leng > instruction_count:
                                break
                            if gadget:
                                if gadget.address not in vaddrs:
                                    vaddrs.update([gadget.address])
                                    toReturn.append(gadget)
                            none_count = 0
                        else:
                            none_count += 1
                            if none_count == arch.maxInvalid:
                                break

                tmp_code = tmp_code[index+arch.align:]
                offset_tmp += arch.align

                match = re.search(ending[0], tmp_code)

                if self.__callback:
                    progress = arch.endings[gtype].index(ending) * len(code) + len(code) - len(tmp_code)
                    self.__callback(section, toReturn, float(progress) / max_progress)

        if self.__callback:
            self.__callback(section, toReturn, 1.0)

        return toReturn

    def _searchGadgetsForked(self, section, binary, instruction_count=5, gtype=GadgetType.ALL):

        to_return = []
        code = bytes(bytearray(section.bytes))

        processes = []
        arch = binary.arch

        max_progress = len(code) * len(arch.endings[gtype])

        ending_queue = JoinableQueue()
        gadget_queue = Queue()
        tmp_code = code[:]

        process_count = min(cpu_count()+1, len(arch.endings[gtype]))
        for ending in arch.endings[gtype]:
            ending_queue.put(ending)

        for cpu in range(process_count):
            ending_queue.put(None)

        # TODO: Another solution should be used here. This is a hack for compatibility reasons. to resolve the gadget address calculation of segments of elf files have a different base address if calculated segment.virtualAddress - segment.offset 
        offset = section.offset - (binary.originalImageBase - (section.virtualAddress - section.offset))

        for cpu in range(process_count):
            processes.append(Process(target=self.__gatherGadgetsByEndings, args=(tmp_code, arch, binary.checksum, section.name, offset, ending_queue, gadget_queue, instruction_count), name="GadgetSearch%d"%cpu))
            processes[cpu].daemon=True
            processes[cpu].start()



        count = 0
        ending_count = 0
        if self.__callback:
            self.__callback(section, to_return, 0)
        while ending_count < len(arch.endings[gtype]):
            gadgets = gadget_queue.get()
            if gadgets != None:
                to_return.extend(gadgets)

                ending_count += 1
                if self.__callback:
                    self.__callback(section, to_return, float(ending_count) / len(arch.endings[gtype]))

        return to_return

    def __gatherGadgetsByEndings(self,code, arch, fileName, sectionName, offset, ending_queue, gadget_queue, instruction_count):

        #try:
        while True:
            ending = ending_queue.get()
            if ending is None:
                ending_queue.task_done()
                break

            gadgets = self.__gatherGadgetsByEnding(code, arch, fileName, sectionName, offset, ending, instruction_count)

            gadget_queue.put(gadgets)
            ending_queue.task_done()


        #except BaseException as e:
        #    raise RopperError(e)


    def __gatherGadgetsByEnding(self, code, arch, fileName, sectionName, offset, ending, instruction_count):
        vaddrs = set()
        offset_tmp = 0

        tmp_code = code[:]
        to_return = []
        match = re.search(ending[0], tmp_code)

        while match:
            offset_tmp += match.start()
            index = match.start()

            if offset_tmp % arch.align == 0:
                #for x in range(arch.align, (depth + 1) * arch.align, arch.align): # This can be used if you want to use a bytecount instead of an instruction count per gadget
                none_count = 0

                for x in range(0, index+1, arch.align):
                    start = index - x
                    end = index + ending[1] + arch.align if (arch.hasBranchDelaySlot and index + ending[1] + arch.align < len(tmp_code)) else index + ending[1]
                    code_part = tmp_code[start:end]
                    gadget, leng = self.__createGadget(arch, code_part, offset + offset_tmp - x , ending, fileName, sectionName)
                    if gadget:
                        if leng > instruction_count:
                            break
                        if gadget:
                            to_return.append(gadget)
                        none_count = 0
                    else:
                        none_count += 1
                        if none_count == arch.maxInvalid:
                            break

            tmp_code = tmp_code[index+arch.align:]
            offset_tmp += arch.align

            match = re.search(ending[0], tmp_code)

        return to_return

    def __createGadget(self, arch, code_str, codeStartAddress, ending, binary=None, section=None):
        gadget = Gadget(binary, section, arch)
        hasret = False
        if codeStartAddress == 0x0000000001b34d74:
            print("found")
        disassembler = self.__getCs(arch)

        for i in disassembler.disasm(code_str, codeStartAddress):
            if re.match(ending[0], i.bytes):
                hasret = True

            if hasret or i.mnemonic not in arch.badInstructions:
                gadget.append(
                    i.address, i.mnemonic,i.op_str, bytes=i.bytes)

            if (hasret and not arch.hasBranchDelaySlot) or i.mnemonic in arch.badInstructions:
                break



        leng = len(gadget)
        if hasret and leng > 0:
            return gadget,leng
        return None, -1


    def __disassembleBackward(self, section, binary, vaddr,offset, count):
        gadget = Gadget(binary.checksum, section.name, binary.arch)
        counter = 0
        toReturn = None
        code = bytes(bytearray(section.bytes))
        disassembler = self.__getCs(binary.arch)

        while len(gadget) < count:
            gadget = Gadget(binary.checksum, section.name, binary.arch)
            for i in disassembler.disasm(struct.pack('B' * len(code[offset - counter:]), *bytearray(code[offset - counter:])), vaddr-counter):
                gadget.append(i.address, i.mnemonic , i.op_str, i.bytes)
                if i.address == vaddr:
                    toReturn = gadget
                    break
                if i.address > vaddr:
                    if len(gadget) > count:
                        return toReturn
                    gadget = Gadget(binary.checksum, section.name, binary.arch)
                    break


            counter += binary.arch.align
            if offset - counter < 0:
                return toReturn

            if not toReturn:
                toReturn = Gadget(binary.checksum, section.name, binary.arch)
                toReturn.append(vaddr,'bad instructions')
        return toReturn


    def disassembleAddress(self, section, binary, vaddr, offset, count):
        if vaddr % binary.arch.align != 0:
            raise RopperError('The address doesn\'t have the correct alignment')
        Gadget.IMAGE_BASES[binary.checksum] = binary.imageBase
        code = bytes(bytearray(section.bytes))
        disassembler = capstone.Cs(binary.arch.arch, binary.arch.mode)

        if count < 0:
            return self.__disassembleBackward(section, binary, vaddr, offset, count*-1)
        gadget  = Gadget(binary.checksum, section.name, binary.arch)
        c = 0

        for i in disassembler.disasm(struct.pack('B' * len(code[offset:]), *bytearray(code[offset:])), offset):
            gadget.append(i.address, i.mnemonic , i.op_str,bytes=i.bytes)
            c += 1
            if c == count:
                break
        if not len(gadget):
            gadget.append(vaddr,'bad instructions')
        return gadget





def toBytes(*b):
    return bytes(bytearray(b))
