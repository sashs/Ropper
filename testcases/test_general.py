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

from ropper.loaders.loader import *
from ropper.rop import Ropper
from ropper.arch import *
from ropper.common.error import *
from ropper.service import RopperService

from filebytes.binary import BinaryError

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

        found_gadgets = self.rs.searchdict('mov [r?x%]')[FILE]
        self.assertGreater(len(found_gadgets), 12)


    def test_badbytes(self):

        self.rs.options.badbytes = 'adfd'

        badbytes = 'adfd'

        gadget = self.rs.files[0].gadgets[0]
        self.assertNotEqual(gadget.lines[0][0], 0x1adfd)


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


class RegressionTests(unittest.TestCase):
    def test_segfault_pe_001(self):
        with self.assertRaises(BinaryError):
            _ = Loader.open('test-binaries/hang-mutate_bytes2_3da2c4818ffe26a52b06b348969026f3_.exe')
