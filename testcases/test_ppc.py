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
from ropper.gadget import Gadget


import unittest

class ELF_PPC(unittest.TestCase):

    def setUp(self):
        self.file = Loader.open('test-binaries/ls-ppc')

    def test_general(self):
        self.assertEqual(self.file.arch, PPC)
        self.assertEqual(self.file.type, Type.ELF)


    def test_gadgets(self):
        self.assertEqual(self.file.arch, PPC)
        self.assertEqual(self.file.type, Type.ELF)
        ropper = Ropper()
        gadgets = ropper.searchGadgets(self.file)

        gadget = gadgets[0]
        self.assertGreater(len(gadgets), 1400)
        self.assertEqual(gadget.lines[0][0] + self.file.imageBase, gadget.address)
        self.assertEqual(gadget.imageBase, 0x10000000)
        self.file.imageBase = 0x0
        Gadget.IMAGE_BASES[self.file.checksum] = self.file.imageBase

        self.assertEqual(gadget.imageBase, 0x0)
        self.file.imageBase = None
        Gadget.IMAGE_BASES[self.file.checksum] = self.file.imageBase

        self.assertEqual(gadget.imageBase, 0x10000000)


    def test_jmpreg(self):
        ropper = Ropper()
        regs=['esp']
        with self.assertRaises(NotSupportedError):
            gadgets = ropper.searchJmpReg(self.file, regs)


    def test_ppr(self):
        ropper = Ropper()

        with self.assertRaises(NotSupportedError):
            gadgets = ropper.searchPopPopRet(self.file)



if __name__ == '__main__':
    unittest.main()
