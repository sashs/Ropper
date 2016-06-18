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
from ropper.service import RopperService


from sys import version_info
import unittest
import os
import ropper

FILE = 'test-binaries/ls-x86_64'

class GeneralTests(unittest.TestCase):

    def setUp(self):
        self.rs = RopperService()
        self.rs.addFile('test-binaries/ls-x86_64')
        self.rs.loadGadgetsFor()

    def test_search(self):

        found_gadgets = self.rs.searchdict('mov [rax]')[FILE]
        self.assertEqual(len(found_gadgets), 2)

        found_gadgets = self.rs.searchdict('mov [r?x]')[FILE]
        self.assertEqual(len(found_gadgets), 12)

        found_gadgets = self.rs.searchdict('mov [r?x%]')[FILE]
        self.assertGreater(len(found_gadgets), 12)


    def test_badbytes(self):

        self.rs.options.badbytes = 'adfd'

        badbytes = 'adfd'
        
        gadget = self.rs.files[0].gadgets[0]
        self.assertNotEqual(gadget.lines[0][0], 0x1adfd)

        self.rs.options.badbytes = '52f8'
        gadgets = self.rs.searchPopPopRet()
        self.assertNotEqual(int(gadgets[FILE][0].lines[0][0]), 0x52f8)

        self.rs.options.badbytes =  'b1c7'
        gadgets = self.rs.searchJmpReg(['rsp'])
        self.assertNotEqual(gadgets[FILE][0].lines[0][0], 0xb1c7)

        with self.assertRaises(AttributeError):
            self.rs.options.badbytes = 'b1c'
            

        with self.assertRaises(AttributeError):
            self.rs.options.badbytes = 'qwer'
            

    def test_opcode_failures(self):
        r = RopperService()

        if version_info.major == 3 and version_info.minor >= 2:
            # Wrong question mark position
            with self.assertRaisesRegex(RopperError,'A \? for the highest 4 bit of a byte is not supported.*'):
                self.rs.searchOpcode('ff?4')
            # Wrong lengh
            with self.assertRaisesRegex(RopperError,'The length of the opcode has to be a multiple of two'):
                self.rs.searchOpcode('ff4')
            # Unallowed character
            with self.assertRaisesRegex(RopperError,'Invalid characters in opcode string'):
                self.rs.searchOpcode('ff4r')
        else:
            # Wrong question mark position
            with self.assertRaisesRegexp(RopperError,'A \? for the highest 4 bit of a byte is not supported.*'):
                self.rs.searchOpcode('ff?4')
            # Wrong lengh
            with self.assertRaisesRegexp(RopperError,'The length of the opcode has to be a multiple of two'):
                self.rs.searchOpcode('ff4')
            # Unallowed character
            with self.assertRaisesRegexp(RopperError,'Invalid characters in opcode string'):
                self.rs.searchOpcode('ff4r')

