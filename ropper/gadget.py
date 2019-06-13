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
from __future__ import print_function
import re
import hashlib
import ropper.common.enum as enum
from ropper.common.utils import toHex, isHex
from ropper.common.error import RopperError
from ropper.common.coloredstring import *
from binascii import hexlify, unhexlify
from ropper.semantic import Analyser, Category
import ropper.arch
import sys

# Optional sqlite support
try:
    import sqlite3
except:
    pass




class GadgetType(enum.Enum):
    _enum_ = 'ROP JOP SYS ALL'


class Gadget(object):

    DETAILED = False
    IMAGE_BASES = {}
    ANALYSER = Analyser()

    def __init__(self, fileName, section, arch, lines=None, bytes=None, semantic_information=None):
        #super(Gadget, self).__init__()
        if isinstance(arch, str):
            arch = ropper.arch.getArchitecture(arch)
        self.__arch = arch
        self.__lines = lines
        self.__gadget = ''
        self.__category = None
        self.__affected_regs = None
        self._fileName = fileName
        self._section = section
        self.__bytes = bytes
        self.__info = semantic_information
        self.__analysed = semantic_information is not None
        #if init:
        #    self.__initialize(lines, bytes)

    @property
    def info(self):

        return self.__info

    @info.setter
    def info(self, info):
        self.__info = info

    @property
    def arch(self):
        return self.__arch

    @property
    def lines(self):
        if self.__lines == None:
            self.__lines = []
        return self.__lines

    @property
    def _lines(self):
        if self.__lines == None:
            self.__lines = []
        return self.__lines

    @_lines.setter
    def _lines(self, value):
        self.__lines = value

    @property
    def section(self):
        return self._section

    @property
    def fileName(self):
        return self._fileName

    @property
    def _bytes(self):
        if self.__bytes == None:
            self.__bytes = bytearray()
        return self.__bytes

    @_bytes.setter
    def _bytes(self, value):
        self.__bytes = value


    @property
    def bytes(self):
        if self.__bytes == None:
            self.__bytes = bytearray()
        return self.__bytes

    @bytes.setter
    def bytes(self, bytes):
        self.__bytes = bytes

    @property
    def imageBase(self):
        return Gadget.IMAGE_BASES.get(self._fileName,0)

    @property
    def address(self):
        return self.imageBase + self.lines[0][0]

    @property
    def _gadget(self):
        if self.__gadget == '':
            for line in self.lines:
                self.__gadget += line[1] + '; '
        return self.__gadget

    @_gadget.setter
    def _gadget(self, value):
        self.__gadget = value

    def __initialize(self, lines, bytes):
        if bytes:
            self._bytes = bytes
        self.__lines = lines

    def append(self, address, mnem, args='', bytes=None):
        if args:
            self._lines.append((address, mnem + ' ' + args, mnem ,args))
            self.__gadget += mnem + ' ' + args + '; '
        else:
            self._lines.append((address, mnem, mnem,args))
            self.__gadget += mnem + '; '

        if bytes:
            self.bytes += bytes

    def match(self, filter):
        if not filter or len(filter) == 0:
            return True
        if self.__arch in (ropper.arch.ARMTHUMB, ropper.arch.ARM):
            return bool(re.match(filter, self._gadget.replace('.w','')))
        else:
            return bool(re.match(filter, self._gadget))

    def addressesContainsBytes(self, badbytes):
        line =  self._lines[0]
        for b in badbytes:

            address = self.address
            if type(b) == str:
                b = ord(b)

            # TODO: This should be changed. Only 4 bytes are checked
            for i in range(self.arch.addressLength):
                if (address & 0xff) == b:

                    return True
                address >>= 8

    def simpleInstructionString(self):
        toReturn = ''
        for line in self._lines:
            if line[3]:
                toReturn += cstr(line[2], Color.LIGHT_YELLOW)+ ' ' + cstr(line[3], Color.LIGHT_GRAY)+ cstr('; ', Color.LIGHT_BLUE)
            else:
                toReturn += cstr(line[2], Color.LIGHT_YELLOW)+ cstr('; ', Color.LIGHT_BLUE)


        return toReturn

    def simpleString(self):
        analyseColor = Color.CYAN if self.__info else Color.RED
        address = self.__lines[0][0]

        if isinstance(self.arch, ropper.arch.ArchitectureArmThumb):
            address += 1
            toReturn = '%s (%s): ' % (cstr(toHex(self._lines[0][0] + self.imageBase, self.__arch.addressLength), analyseColor),cstr(toHex(address + self.imageBase, self.__arch.addressLength), Color.GREEN))
        else:
            toReturn = '%s: ' % cstr(toHex(self._lines[0][0] + self.imageBase, self.__arch.addressLength), analyseColor)
        toReturn += self.simpleInstructionString()
        if self.__info:
            toReturn += '\nClobbered Register = %s; StackPointer-Offset = %s\n' % (", ".join(list(self.info.clobberedRegisters)),self.info.spOffset if self.info.spOffset is not None else 'Undef')
        return toReturn

    @property
    def affected_regs(self):
        if not self.__affected_regs:
            self.__affected_regs = set()

            full_line = self.simpleInstructionString()
            line = self.__lines[0][1]

            for l_tup in self.__lines:
                line = l_tup[1]
                for cat, regexs in self.__arch._categories.items():
                    for regex in regexs[0]:
                        if regex != 'ret.+':
                            r = re.compile(regex)
                            match_all = r.match(line)

                            if  match_all:
                                if 'dst' in match_all.groupdict():
                                    affected = match_all.groupdict()['dst']
                                    self.__affected_regs.add(affected)
            return self.__affected_regs
        else:
            return self.__affected_regs

    @property
    def category(self):
        if not self.__category:
            line = self.__lines[0][1]
            for cat, regexs in self.__arch._categories.items():
                for regex in regexs[0]:
                    match = re.match(regex, line)
                    if match:
                        for invalid in regexs[1]:
                            for l in self.__lines[1:]:
                                if l[1].startswith(invalid):
                                    self.__category = (Category.NONE,)
                                    return self.__category

                        self.__category = (cat, len(self.__lines) -1 ,match.groupdict())
                        self.__category[2]['affected'] = self.affected_regs
                        return self.__category
            self.__category = (Category.NONE,)

        return self.__category

    def __len__(self):
        return len(self._lines)

    def __cmp__(self, other):
        if isinstance(other, self.__class__) and len(self) == len(other):
            return cmp(str(self),str(other))
        return -1

    def disassemblyString(self):
        toReturn = ''
        for line in self._lines:
            toReturn += cstr(toHex(line[0] + self.imageBase, self.__arch.addressLength), Color.RED) +': '+ cstr(line[1], Color.LIGHT_GRAY) + '\n'

        return toReturn

    def __str__(self):
        if not Gadget.DETAILED:
            return self.simpleString()
        if not len(self._lines):
            return "empty gadget"
        address = self._lines[0][0]
        if self.__arch == ropper.arch.ARMTHUMB:
            address += 1
            toReturn = cstr('Gadget', Color.BLUE)+': %s (%s)\n' % (cstr(toHex(self._lines[0][0] + self.imageBase, self.__arch.addressLength), Color.YELLOW),cstr(toHex(address+ self.imageBase, self.__arch.addressLength), Color.GREEN))
        else:
            toReturn = cstr('Gadget', Color.BLUE)+': %s\n' % (cstr(toHex(self._lines[0][0] + self.imageBase, self.__arch.addressLength), Color.YELLOW))
        for line in self._lines:
            toReturn += cstr(toHex(line[0] + self.imageBase, self.__arch.addressLength), Color.RED) +': '+ cstr(line[1], Color.LIGHT_GRAY) + '\n'

        return toReturn

    def __repr__(self):
        return 'Gadget(%s, %s, %s, %s, %s, %s)' % (repr(self.fileName), repr(self.section), repr(self.__arch), repr(self.__lines), repr(self._bytes), repr(self.info))
