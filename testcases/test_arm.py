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

from ropperapp.loaders.loader import *
from ropperapp.disasm.rop import Ropper
from ropperapp.disasm.arch import *

import unittest

# class ELF_ARM(unittest.TestCase):

#     def setUp(self):
#         self.file = Loader.open('test-binaries/ls-arm')

#     def test_general(self):
#         self.assertEqual(self.file.arch, x86)
#         self.assertEqual(self.file.type, Type.ELF)
        

#     def test_gadgets(self):
#         ropper = Ropper(self.file)
#         gadgets = ropper.searchRopGadgets()

#         gadget = gadgets[0]
#         self.assertEqual(len(gadgets), 1711)
#         self.assertEqual(gadget.lines[0][0], 0x8567)
#         self.assertEqual(gadget.imageBase, 0x8048000)
#         self.file.manualImagebase = 0x0
#         self.assertEqual(gadget.imageBase, 0x0)
#         self.file.manualImagebase = None
#         self.assertEqual(gadget.imageBase, 0x8048000)




class ELF_ARM_THUMB(unittest.TestCase):

    def setUp(self):
        self.file = Loader.open('test-binaries/ls-arm')
        

    def test_general(self):
        self.assertEqual(self.file.arch, ARMTHUMB)
        self.assertEqual(self.file.type, Type.ELF)

    def test_gadgets_pe(self):
        ropper = Ropper(self.file)
        gadgets = ropper.searchRopGadgets()

        gadget = gadgets[0]
        self.assertEqual(len(gadgets), 1726)
        self.assertEqual(gadget.lines[0][0], 0x7ee4)
        self.assertEqual(gadget.imageBase, 0x00008000)
        self.file.manualImagebase = 0x0
        self.assertEqual(gadget.imageBase, 0x0)
        self.file.manualImagebase = None
        self.assertEqual(gadget.imageBase, 0x00008000)


if __name__ == '__main__':
    unittest.main()
