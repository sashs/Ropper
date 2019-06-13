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
        Gadget.IMAGE_BASES[self.file.checksum] = self.file.imageBase

        self.assertEqual(gadget.imageBase, 0x0)
        self.file.imageBase = None
        Gadget.IMAGE_BASES[self.file.checksum] = self.file.imageBase

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
        Gadget.IMAGE_BASES[self.file.checksum] = self.file.imageBase

        self.assertEqual(gadget.imageBase, 0x0)
        self.file.imageBase = None
        Gadget.IMAGE_BASES[self.file.checksum] = self.file.imageBase

        self.assertEqual(gadget.imageBase, 0x400000)

        with self.assertRaises(RopperError):
            regs=['invalid']
            ropper.searchJmpReg(self.file, regs)


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
        Gadget.IMAGE_BASES[self.file.checksum] = self.file.imageBase

        self.assertEqual(gadget.imageBase, 0x0)
        self.file.imageBase = None
        Gadget.IMAGE_BASES[self.file.checksum] = self.file.imageBase

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
        Gadget.IMAGE_BASES[self.file.checksum] = self.file.imageBase

        self.assertEqual(gadget.imageBase, 0x0)
        self.file.imageBase = None
        Gadget.IMAGE_BASES[self.file.checksum] = self.file.imageBase

        self.assertEqual(gadget.imageBase, 0x4ad00000)



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
        Gadget.IMAGE_BASES[self.file.checksum] = self.file.imageBase

        self.assertEqual(gadget.imageBase, 0x0)
        self.file.imageBase = None
        Gadget.IMAGE_BASES[self.file.checksum] = self.file.imageBase

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
        Gadget.IMAGE_BASES[self.file.checksum] = self.file.imageBase

        self.assertEqual(gadget.imageBase, 0x0)
        self.file.imageBase = None
        Gadget.IMAGE_BASES[self.file.checksum] = self.file.imageBase

        self.assertEqual(gadget.imageBase, 0x100000000)

        with self.assertRaises(RopperError):
            regs=['invalid']
            ropper.searchJmpReg(self.file, regs)


if __name__ == '__main__':
    unittest.main()
