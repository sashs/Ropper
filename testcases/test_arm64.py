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
from ropperapp.rop import Ropper
from ropperapp.arch import *

import unittest

class ELF_ARM64(unittest.TestCase):

    def setUp(self):
        self.file = Loader.open('test-binaries/ls-arm64')
        

    def test_general(self):
        self.assertEqual(self.file.arch, ARM64)
        self.assertEqual(self.file.type, Type.ELF)

    def test_gadgets_pe(self):
        ropper = Ropper()
        gadgets = ropper.searchRopGadgets(self.file)

        gadget = gadgets[0]
        self.assertGreater(len(gadgets), 2350)
        self.assertEqual(gadget.lines[0][0] + self.file.calculateImageBase(gadget.section), gadget.vaddr)
        self.assertEqual(gadget.imageBase, 0x00400000)
        self.file.manualImagebase = 0x0
        self.assertEqual(gadget.imageBase, 0x0)
        self.file.manualImagebase = None
        self.assertEqual(gadget.imageBase, 0x00400000)


if __name__ == '__main__':
    unittest.main()
