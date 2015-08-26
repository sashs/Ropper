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
from ropperapp.gadget import GadgetDAO
from ropperapp.arch import *
from ropperapp.common.error import *

from sys import version_info
import unittest
import os


class GeneralTests(unittest.TestCase):

    def setUp(self):
        self.file = Loader.open('test-binaries/ls-x86_64')


    def test_search(self):
        ropper = Ropper()

        gadgets = ropper.searchRopGadgets(self.file)

        found_gadgets = self.file.arch.searcher.search(gadgets, 'mov [rax]')
        self.assertEqual(len(found_gadgets), 1)

        found_gadgets = self.file.arch.searcher.search(gadgets, 'mov [r?x]')
        self.assertEqual(len(found_gadgets), 5)

        found_gadgets = self.file.arch.searcher.search(gadgets, 'mov [r?x%]')
        self.assertEqual(len(found_gadgets), 7)


    def test_badbytes(self):
        ropper = Ropper()

        badbytes = 'adfd'
        gadgets = ropper.searchRopGadgets(self.file, badbytes=badbytes)
        gadget = gadgets[0]
        self.assertNotEqual(gadget.lines[0][0], 0x1adfd)

        badbytes = '52f8'
        gadgets = ropper.searchPopPopRet(self.file, badbytes=badbytes)
        self.assertNotEqual(gadgets[0].lines[0][0], 0x52f8)

        badbytes = 'b1c7'
        gadgets = ropper.searchJmpReg(self.file, ['rsp'], badbytes=badbytes)
        gadget = gadgets[0]
        self.assertNotEqual(gadget.lines[0][0], 0xb1c7)

        with self.assertRaises(RopperError):
            badbytes = 'b1c'
            gadgets = ropper.searchRopGadgets(self.file, badbytes=badbytes)

        with self.assertRaises(RopperError):
            badbytes = 'qwer'
            gadgets = ropper.searchRopGadgets(self.file, badbytes=badbytes)

    def test_opcode_failures(self):
        ropper = Ropper()

        if version_info.major == 3 and version_info.minor >= 2:
            # Wrong question mark position
            with self.assertRaisesRegex(RopperError,'A \? for the highest 4 bit of a byte is not supported.*'):
                ropper.searchOpcode(self.file, 'ff?4')
            # Wrong lengh
            with self.assertRaisesRegex(RopperError,'The length of the opcode has to be a multiple of two'):
                ropper.searchOpcode(self.file, 'ff4')
            # Unallowed character
            with self.assertRaisesRegex(RopperError,'Invalid characters in opcode string'):
                ropper.searchOpcode(self.file, 'ff4r')
        else:
            # Wrong question mark position
            with self.assertRaisesRegexp(RopperError,'A \? for the highest 4 bit of a byte is not supported.*'):
                ropper.searchOpcode(self.file, 'ff?4')
            # Wrong lengh
            with self.assertRaisesRegexp(RopperError,'The length of the opcode has to be a multiple of two'):
                ropper.searchOpcode(self.file, 'ff4')
            # Unallowed character
            with self.assertRaisesRegexp(RopperError,'Invalid characters in opcode string'):
                ropper.searchOpcode(self.file, 'ff4r')


    def test_database(self):
        ropper = Ropper()

        db = './testdb.db'
        if os.path.exists(db):
            os.remove(db)

        dao = GadgetDAO(db)

        gadgets = ropper.searchRopGadgets(self.file)

        dao.save(gadgets)
        self.assertTrue(os.path.exists(db))

        loaded_gadgets = dao.load(self.file)
        self.assertEqual(len(gadgets), len(loaded_gadgets))
        self.assertEqual(gadgets[0].lines[0][0], loaded_gadgets[0].lines[0][0])

        os.remove(db)





