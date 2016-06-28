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
from ropper.gadget import Gadget


import unittest

class ELF_x86(unittest.TestCase):

    def setUp(self):
        self.file = Loader.open('test-binaries/ls-x86')

    def test_general(self):
        self.assertEqual(self.file.arch, x86)
        self.assertEqual(self.file.type, Type.ELF)
        

    def test_gadgets(self):
        ropper = Ropper()
        gadgets = ropper.searchGadgets(self.file)

        gadget = gadgets[0]
        self.assertGreater(len(gadgets), 1700)
        self.assertEqual(gadget.lines[0][0] + self.file.imageBase, gadget.address)
        self.assertEqual(gadget.imageBase, 0x8048000)
        self.file.imageBase = 0x0
        Gadget.IMAGE_BASES[self.file.fileName] = self.file.imageBase

        self.assertEqual(gadget.imageBase, 0x0)
        self.file.imageBase = None
        Gadget.IMAGE_BASES[self.file.fileName] = self.file.imageBase

        self.assertEqual(gadget.imageBase, 0x8048000)


    def test_jmpreg(self):
        ropper = Ropper()
        regs=['esp']
        gadgets = ropper.searchJmpReg(self.file, regs)
        gadget = gadgets[0]
        self.assertEqual(len(gadgets), 10)
        self.assertEqual(gadget.lines[0][0], 0xc63)
        self.assertEqual(gadget.imageBase, 0x8048000)
        self.file.imageBase = 0x0
        Gadget.IMAGE_BASES[self.file.fileName] = self.file.imageBase

        self.assertEqual(gadget.imageBase, 0x0)
        self.file.imageBase = None
        Gadget.IMAGE_BASES[self.file.fileName] = self.file.imageBase

        self.assertEqual(gadget.imageBase, 0x8048000)

    def test_ppr(self):
        ropper = Ropper()
        
        gadgets = ropper.searchPopPopRet(self.file)
        
        self.assertEqual(len(gadgets), 137)
        self.assertEqual(gadgets[0].lines[0][0], 0x444a)




class PE_x86(unittest.TestCase):

    def setUp(self):
        self.file = Loader.open('test-binaries/cmd-x86.exe')

    def test_general(self):
        self.assertEqual(self.file.arch, x86)
        self.assertEqual(self.file.type, Type.PE)

    def test_gadgets_pe(self):
        ropper = Ropper()
        gadgets = ropper.searchGadgets(self.file)

        gadget = gadgets[0]
        self.assertGreater(len(gadgets), 4800)
        self.assertEqual(gadget.lines[0][0] + self.file.imageBase, gadget.address)
        self.assertEqual(gadget.imageBase, 0x4ad00000)
        self.file.imageBase = 0x0
        Gadget.IMAGE_BASES[self.file.fileName] = self.file.imageBase

        self.assertEqual(gadget.imageBase, 0x0)
        self.file.imageBase = None
        Gadget.IMAGE_BASES[self.file.fileName] = self.file.imageBase

        self.assertEqual(gadget.imageBase, 0x4ad00000)


    def test_jmpreg_pe(self):
        ropper = Ropper()
        regs=['esp']
        gadgets = ropper.searchJmpReg(self.file, regs)
        gadget = gadgets[0]
        self.assertEqual(len(gadgets), 1)
        self.assertEqual(gadget.lines[0][0], 0xc797)

        regs=['esp','eax']
        gadgets = ropper.searchJmpReg(self.file, regs)
        self.assertEqual(len(gadgets), 13)

        self.assertEqual(gadget.imageBase, 0x4ad00000)
        self.file.imageBase = 0x0
        Gadget.IMAGE_BASES[self.file.fileName] = self.file.imageBase

        self.assertEqual(gadget.imageBase, 0x0)
        self.file.imageBase = None
        Gadget.IMAGE_BASES[self.file.fileName] = self.file.imageBase

        self.assertEqual(gadget.imageBase, 0x4ad00000)

    def test_ppr_pe(self):
        ropper = Ropper()
        
        gadgets = ropper.searchPopPopRet(self.file)
        
        self.assertEqual(len(gadgets), 17)
        self.assertEqual(gadgets[0].lines[0][0], 0x1688)

if __name__ == '__main__':
    unittest.main()
