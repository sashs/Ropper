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

import re
import sqlite3
import ropperapp.common.enum as enum
from ropperapp.common.utils import toHex
from ropperapp.common.coloredstring import *

class Category(enum.Enum):
    _enum_ = 'STACK_PIVOTING LOAD_REG LOAD_MEM STACK_SHIFT SYSCALL JMP CALL WRITE_MEM INC_REG CLEAR_REG SUB_REG ADD_REG XCHG_REG NONE'



class GadgetType(enum.Enum):
    _enum_ = 'ROP JOP ALL'


class Gadget(object):

    def __init__(self, arch):
        super(Gadget, self).__init__()
        self.__arch = arch
        self.__lines = []
        self._gadget = ''
        self._vaddr = 0x0
        self.__category = None
        self.__imageBase = 0x0

    @property
    def lines(self):
        return self.__lines

    @property
    def imageBase(self):
        return self.__imageBase

    @imageBase.setter
    def imageBase(self, base):
        self.__imageBase = base

    @property
    def vaddr(self):
        return self._vaddr

    def append(self, address, inst):
        self.__lines.append((address, inst))
        self._gadget += inst + '; '

    def match(self, filter):
        if not filter or len(filter) == 0:
            return True
        return bool(re.match(filter, self._gadget))

    def addressesContainsBytes(self, badbytes):
        line =  self.__lines[0]
        for b in badbytes:

            address = line[0] + self.__imageBase
            if type(b) == str:
                b = ord(b)
            for i in range(4):
                if (address & 0xff) == b:

                    return True
                address >>= 8



    def simpleInstructionString(self):
        toReturn = ''
        for line in self.__lines:
            toReturn += cstr(line[1], Color.LIGHT_GRAY) + cstr('; ', Color.LIGHT_BLUE)

        return toReturn

    def simpleString(self):
        toReturn = '%s: ' % cstr(toHex(self.__lines[0][0] + self.__imageBase, self.__arch.addressLength), Color.RED)
        toReturn += self.simpleInstructionString()
        return toReturn

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
                        return self.__category
            self.__category = (Category.NONE,)

        return self.__category

    def __len__(self):
        return len(self.__lines)

    def __cmp__(self, other):
        if isinstance(other, self.__class__) and len(self) == len(other):
            return cmp(str(self),str(other))
        return -1

    def __str__(self):
        toReturn = cstr('Gadget', Color.GREEN)+': %s\n' % (cstr(toHex(self.__lines[0][0] + self.__imageBase, self.__arch.addressLength), Color.RED))
        for line in self.__lines:
            toReturn += cstr(toHex(line[0] + self.__imageBase, self.__arch.addressLength), Color.BLUE) +': '+ cstr(line[1], Color.WHITE) + '\n'

        return toReturn


class GadgetDAO(object):

    def __init__(self, dbname):
        self.__dbname = dbname



    def save(self, section_gadgets):
        conn = sqlite3.connect(self.__dbname)
        c = conn.cursor()
        c.execute('create table sections(nr INTEGER PRIMARY KEY ASC, name, offs, gcount INTEGER)')
        c.execute('create table gadgets(nr INTEGER PRIMARY KEY ASC, snr INTEGER, lcount INTEGER)')
        c.execute('create table lines(gnr INTEGER, addr INTEGER, inst)')
        scount = 0
        gcount = 0
        for section, gadgets in section_gadgets.items():
            c.execute('insert into sections values(?, ?,?,?)' ,(scount, section.name, section.offset, len(gadgets)))

            for gadget in gadgets:
                c.execute('insert into gadgets values(?,?,?)', (gcount, scount, len(gadget.lines)))

                for addr, line in gadget.lines:
                    c.execute('insert into lines values(?,?,?)', (gcount, addr, line))

                gcount +=1
            scount += 1
        conn.commit()
        conn.close()


    def load(self, binary):
        conn = sqlite3.connect(self.__dbname)
        c = conn.cursor()

        c.execute('select * from sections')
        sectionrows = c.fetchall()
        c.execute('select * from gadgets')
        gadgetrows = iter(c.fetchall())
        c.execute('select * from lines')
        linerows = iter(c.fetchall())
        toReturn = {}
        execSect = binary.executableSections

        for s in sectionrows:
            for section in execSect:
                if s[1] == section.name and int(s[2]) == section.offset:
                    gadgets = []
                    for gcount in range(s[3]):
                        grow = gadgetrows.next()
                        gadget = Gadget(binary.arch)
                        gadgets.append(gadget)

                        for lcount in range(grow[2]):
                            lrow = linerows.next()
                            gadget.append(int(lrow[1]), lrow[2])

                    toReturn[section] = gadgets

        conn.close()
        return toReturn
