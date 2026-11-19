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
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""
Tests for the semantic-search constraint compiler.

Only the compiler is exercised here; it depends on nothing but `re`, so these
tests do not need z3 or a real binary.
"""

from types import SimpleNamespace

import unittest

from ropper.common.error import RopperError
from ropper.z3helper import ConstraintCompiler, ConstraintError

KNOWN_REGISTERS = ('rax', 'rbx', 'rcx', 'rdx')


class _FakeArchitecture(object):
    def __init__(self):
        self.info = SimpleNamespace(registers={r: None for r in KNOWN_REGISTERS})

    def getRegisterName(self, register):
        # Mirrors the real architectures: unknown names come back as None.
        return register if register in KNOWN_REGISTERS else None


class _FakeSemanticInfo(object):
    regs = {r: ('%s_0' % r, '%s_63' % r) for r in KNOWN_REGISTERS}


class ConstraintCompilerTest(unittest.TestCase):
    def setUp(self):
        self.cc = ConstraintCompiler(_FakeArchitecture(), _FakeSemanticInfo())

    def test_invalid_syntax_raises_ropper_error(self):
        """
        A constraint the parser cannot match has to surface as a RopperError so
        the console prints the message instead of "Please report this error".
        """
        for constraint in ('mov rbx, rax', 'rax'):
            with self.assertRaisesRegex(ConstraintError, 'Invalid syntax: %s' % constraint) as ctx:
                self.cc.getSymbols([constraint])
            self.assertIsInstance(ctx.exception, RopperError)

    def test_valid_constraints_are_accepted(self):
        self.assertEqual(self.cc.getSymbols(['rax == rbx']), [('rax', 'rbx')])
        self.assertEqual(self.cc.getSymbols(['rax += 0x10']), [('rax', None)])
        self.assertEqual(self.cc.getSymbols(['pop rax']), [('rax', None)])

    def test_unknown_register_in_memory_operand(self):
        """
        The message used to be built with '&' instead of '%', which raised
        TypeError and hid the real complaint.
        """
        with self.assertRaisesRegex(ConstraintError, 'Invalid register: zzz') as ctx:
            self.cc.compile('rax == [zzz]')
        self.assertIsInstance(ctx.exception, RopperError)


if __name__ == '__main__':
    unittest.main()
