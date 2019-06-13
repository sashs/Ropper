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
from ropper.console import Console
from ropper.options import Options

import unittest

class ConsoleTest(unittest.TestCase):

    def setUp(self):

        self.console = Console(Options([]))
        self.console.do_file('test-binaries/ls-x86')

    def test_commands(self):

        c = self.console

        c.do_arch('x86')
        c.do_arch('invalid')

        c.do_badbytes('000a')
        c.do_badbytes('')
        c.do_badbytes('invalid')

        c.do_color('on')
        c.do_color('off')
        c.do_color('invalid')

        c.do_detailed('on')
        c.do_detailed('off')
        c.do_detailed('invalid')

        c.do_disasm_address('0x8048abc')
        c.do_disasm_address('0x9048abc')
        c.do_disasm_address('invalid')

        c.do_file('test-binaries/ls-x86')
        c.do_file('')

        c.do_close('2')
        c.do_file('')

        c.do_load('')

        c.do_gadgets('')

        c.do_help('load')

        c.do_hex('.text')
        c.do_hex('invalid')

        c.do_imagebase('0x8')
        c.do_imagebase('8048000')
        c.do_imagebase('invalid')
        c.do_imagebase('0x8048000')

        c.do_jmp('esp')
        c.do_jmp('esp,eax')

        c.do_opcode('ffe4')
        c.do_opcode('ffe?')
        c.do_opcode('ff?e')
        c.do_opcode('ffe')

        c.do_ppr('')

        c.do_ropchain('execve')
        c.do_ropchain('mprotect address=0xbfdff000 size=0x20ffff')

        c.do_unset('nx')
        c.do_set('nx')

        c.do_search('mov e?x')

        c.do_settings('')
        c.do_settings('color off')
        c.do_settings('color')

        c.do_show('segments')
        c.do_show('sections')
        c.do_show('file_type')
        c.do_show('architecture')
        c.do_show('imports')


        c.do_string('')
        c.do_string('bin%')

        c.do_type('rop')
        c.do_type('jop')
        c.do_type('all')

        c.do_stack_pivot('')


if __name__ == '__main__':
    unittest.main()
