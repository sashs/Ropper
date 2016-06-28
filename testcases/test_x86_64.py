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

from ropper.loaders.loader import *
from ropper.rop import Ropper
from ropper.arch import *
from ropper.common.error import *
from ropper.gadget import Gadget


import unittest

class ELF_x86_84(unittest.TestCase):

    def setUp(self):
        self.file = Loader.open('test-binaries/ls-x86_64')

    def test_general(self):
        self.assertEqual(self.file.arch, x86_64)
        self.assertEqual(self.file.type, Type.ELF)
        
    def test_gadgets(self):
        ropper = Ropper()
        gadgets = ropper.searchGadgets(self.file)

        gadget = gadgets[0]
        self.assertGreater(len(gadgets), 1000)
        self.assertEqual(gadget.lines[0][0] + self.file.imageBase, gadget.address)
        self.assertEqual(gadget.imageBase, 0x400000)
        self.file.imageBase = 0x0
        Gadget.IMAGE_BASES[self.file.fileName] = self.file.imageBase

        self.assertEqual(gadget.imageBase, 0x0)
        self.file.imageBase = None
        Gadget.IMAGE_BASES[self.file.fileName] = self.file.imageBase

        self.assertEqual(gadget.imageBase, 0x400000)

    def test_jmpreg(self):
        ropper = Ropper()
        regs=['rsp']
        gadgets = ropper.searchJmpReg(self.file, regs)
        gadget = gadgets[0]
        self.assertEqual(len(gadgets), 18)
        self.assertEqual(gadget.lines[0][0], 0xb1c7)

        regs=['rsp','rax']
        gadgets = ropper.searchJmpReg(self.file, regs)
        self.assertEqual(len(gadgets), 25)

        self.assertEqual(gadget.imageBase, 0x400000)
        self.file.imageBase = 0x0
        Gadget.IMAGE_BASES[self.file.fileName] = self.file.imageBase

        self.assertEqual(gadget.imageBase, 0x0)
        self.file.imageBase = None
        Gadget.IMAGE_BASES[self.file.fileName] = self.file.imageBase

        self.assertEqual(gadget.imageBase, 0x400000)

        with self.assertRaises(RopperError):
            regs=['invalid']
            ropper.searchJmpReg(self.file, regs)

    def test_ppr(self):
        ropper = Ropper()
        
        gadgets = ropper.searchPopPopRet(self.file)
        
        self.assertEqual(len(gadgets), 118)
        self.assertEqual(gadgets[0].lines[0][0], 0x52f8)


class PE_x86_84(unittest.TestCase):

    def setUp(self):
        self.file = Loader.open('test-binaries/cmd-x86_64.exe')

    def test_general(self):
        self.assertEqual(self.file.arch, x86_64)
        self.assertEqual(self.file.type, Type.PE)
        

    def test_gadgets(self):
        ropper = Ropper()
        gadgets = ropper.searchGadgets(self.file)

        gadget = gadgets[0]
        self.assertGreater(len(gadgets), 1500)
        self.assertEqual(gadget.lines[0][0] + self.file.imageBase, gadget.address)
        self.assertEqual(gadget.imageBase, 0x4ad00000)
        self.file.imageBase = 0x0
        Gadget.IMAGE_BASES[self.file.fileName] = self.file.imageBase

        self.assertEqual(gadget.imageBase, 0x0)
        self.file.imageBase = None
        Gadget.IMAGE_BASES[self.file.fileName] = self.file.imageBase

        self.assertEqual(gadget.imageBase, 0x4ad00000)

    def test_jmpreg(self):
        ropper = Ropper()
        regs=['rsp']
        gadgets = ropper.searchJmpReg(self.file, regs)
        gadget = gadgets[0]
        self.assertEqual(len(gadgets), 3)
        self.assertEqual(gadget.lines[0][0], 0x37dd)

        regs=['rsp','rax']
        gadgets = ropper.searchJmpReg(self.file, regs)
        self.assertEqual(len(gadgets), 15)
        self.assertEqual(gadget.imageBase, 0x4ad00000)
        self.file.imageBase = 0x0
        Gadget.IMAGE_BASES[self.file.fileName] = self.file.imageBase

        self.assertEqual(gadget.imageBase, 0x0)
        self.file.imageBase = None
        Gadget.IMAGE_BASES[self.file.fileName] = self.file.imageBase

        self.assertEqual(gadget.imageBase, 0x4ad00000)

    def test_ppr(self):
        ropper = Ropper()
        
        gadgets = ropper.searchPopPopRet(self.file)
        
        self.assertEqual(len(gadgets), 242)
        self.assertEqual(gadgets[0].lines[0][0], 0x14ec)


class MACHO_x86_84(unittest.TestCase):

    def setUp(self):
        self.file = Loader.open('test-binaries/ls-macho-x86_64')

    def test_general(self):
        self.assertEqual(self.file.arch, x86_64)
        self.assertEqual(self.file.type, Type.MACH_O)
        
    def test_gadgets(self):
        ropper = Ropper()
        gadgets = ropper.searchGadgets(self.file)

        gadget = gadgets[0]
        self.assertGreater(len(gadgets), 110)
        self.assertEqual(gadget.lines[0][0] + self.file.imageBase, gadget.address)
        self.assertEqual(gadget.imageBase, 0x100000000)
        self.file.imageBase = 0x0
        Gadget.IMAGE_BASES[self.file.fileName] = self.file.imageBase

        self.assertEqual(gadget.imageBase, 0x0)
        self.file.imageBase = None
        Gadget.IMAGE_BASES[self.file.fileName] = self.file.imageBase

        self.assertEqual(gadget.imageBase, 0x100000000)

    def test_jmpreg(self):
        ropper = Ropper()
        regs=['rax']
        gadgets = ropper.searchJmpReg(self.file, regs)
        gadget = gadgets[0]
        self.assertEqual(len(gadgets), 4)
        self.assertEqual(gadget.lines[0][0], 0x19bb)

        regs=['rcx','rax']
        gadgets = ropper.searchJmpReg(self.file, regs)
        self.assertEqual(len(gadgets), 7)

        self.assertEqual(gadget.imageBase, 0x100000000)
        self.file.imageBase = 0x0
        Gadget.IMAGE_BASES[self.file.fileName] = self.file.imageBase

        self.assertEqual(gadget.imageBase, 0x0)
        self.file.imageBase = None
        Gadget.IMAGE_BASES[self.file.fileName] = self.file.imageBase

        self.assertEqual(gadget.imageBase, 0x100000000)

        with self.assertRaises(RopperError):
            regs=['invalid']
            ropper.searchJmpReg(self.file, regs)

    def test_ppr(self):
        ropper = Ropper()
        
        gadgets = ropper.searchPopPopRet(self.file)
        
        self.assertEqual(len(gadgets), 32)
        self.assertEqual(gadgets[0].lines[0][0], 0x1cdc)
    
if __name__ == '__main__':
    unittest.main()
