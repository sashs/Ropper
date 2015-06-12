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

import argparse
from ropperapp.common.error import *
from ropperapp.common.utils import isHex
import sys


class Options(object):

    def __init__(self, argv):
        super(Options, self).__init__()

        self.__argv = argv
        self.__args = None
        self.__parser = self._createArgParser()
        self._analyseArguments()

    def _createArgParser(self):
        parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
description="""You can use ropper to display information about binary files in different file formats
    and you can search for gadgets to build rop chains for different architectures

supported filetypes:
  ELF
  PE
  Mach-O
  Raw

supported architectures:
  x86 [x86]
  x86_64 [x86_64]
  MIPS [MIPS, MIPS64]
  ARM/Thumb [ARM, ARMTHUMB]
  ARM64 [ARM64]
  PowerPC [PPC, PPC64]

available rop chain generators:
  execve (execve[=<cmd>], default /bin/sh) [Linux x86]
  mprotect  (mprotect=<address>:<size>) [Linux x86]
  virtualprotect (virtualprotect=<address iat vp>:<size>) [Windows x86]
""",
epilog="""example uses:
  [Generic]
  ropper.py
  ropper.py --file /bin/ls --console

  [Informations]
  ropper.py --file /bin/ls --info
  ropper.py --file /bin/ls --imports
  ropper.py --file /bin/ls --sections
  ropper.py --file /bin/ls --segments
  ropper.py --file /bin/ls --set nx
  ropper.py --file /bin/ls --unset nx

  [Gadgets]
  ropper.py --file /bin/ls --depth 5
  ropper.py --file /bin/ls --search "sub eax" --badbytes 000a0d
  ropper.py --file /bin/ls --search "sub eax" --detail
  ropper.py --file /bin/ls --filter "sub eax"
  ropper.py --file /bin/ls --depth 5 --filter "sub eax"
  ropper.py --file /bin/ls --opcode ffe4
  ropper.py --file /bin/ls --detail
  ropper.py --file /bin/ls --ppr --nocolor
  ropper.py --file /bin/ls --jmp esp,eax
  ropper.py --file /bin/ls --type jop
  ropper.py --file /bin/ls --chain execve=/bin/sh
  ropper.py --file /bin/ls --chain execve=/bin/sh --badbytes 000a0d
  ropper.py --file /bin/ls --chain mprotect=0xbfdff000:0x21000

  [Search]
  ?\t\tany character
  %\t\tany string

  Example:

  ropper.py --file /bin/ls --search "mov e?x"
  0x000067f1: mov edx, dword ptr [ebp + 0x14]; mov dword ptr [esp], edx; call eax
  0x00006d03: mov eax, esi; pop ebx; pop esi; pop edi; pop ebp; ret ;
  0x00006d6f: mov ebx, esi; mov esi, dword ptr [esp + 0x18]; add esp, 0x1c; ret ;
  0x000076f8: mov eax, dword ptr [eax]; mov byte ptr [eax + edx], 0; add esp, 0x18; pop ebx; ret ;

  ropper.py --file /bin/ls --search "mov [%], ecx"
  0x000067ed: mov dword ptr [esp + 4], edx; mov edx, dword ptr [ebp + 0x14]; mov dword ptr [esp], edx; call eax;
  0x00006f4e: mov dword ptr [ecx + 0x14], edx; add esp, 0x2c; pop ebx; pop esi; pop edi; pop ebp; ret ;
  0x000084b8: mov dword ptr [eax], edx; ret ;
  0x00008d9b: mov dword ptr [eax], edx; add esp, 0x18; pop ebx; ret ;

  ropper.py --file /bin/ls --search "mov [%], edx" --quality 1
  0x000084b8: mov dword ptr [eax], edx; ret ;
  \n""")


        parser.add_argument(
            '-v', '--version', help="Print version", action='store_true')
        parser.add_argument(
            '--console', help='Starts interactive commandline', action='store_true')
        parser.add_argument(
            '-f', '--file', metavar="<file>", help='The file to load')
        parser.add_argument(
             '--db', metavar="<dbfile>", help='The dbfile to load')
        parser.add_argument(
            '-a', '--arch', metavar="<arch>", help='The architecture of the loaded file')
        parser.add_argument(
            '--section', help='The data of the this section should be printed', metavar='<section>')
        parser.add_argument(
            '--string', help='Looks for the string <string> in all data sections', metavar='<string>',nargs='?', const='[ -~]{2}[ -~]*')
        parser.add_argument(
            '--hex', help='Prints the selected sections in a hex format', action='store_true')
        parser.add_argument(
            '--disassemble', help='Disassembles instruction at address <address> (0x12345678:L3). The count of instructions to disassemble can be specified (0x....:L...)', metavar='<address:length>')
        parser.add_argument(
            '-i', '--info', help='Shows file header [ELF/PE/Mach-O]', action='store_true')
        parser.add_argument('-e', help='Shows EntryPoint', action='store_true')
        parser.add_argument('--imagebase', help='Shows ImageBase [ELF/PE/Mach-O]', action='store_true')
        parser.add_argument(
            '-c', '--dllcharacteristics',help='Shows DllCharacteristics [PE]', action='store_true')
        parser.add_argument(
            '-s', '--sections', help='Shows file sections [ELF/PE/Mach-O]', action='store_true')
        parser.add_argument(
            '-S', '--segments', help='Shows file segments [ELF/Mach-O]', action='store_true')
        #parser.add_argument(
        #    '--checksec', help='Shows the security mechanisms used in the file [ELF/PE/Mach-O]', action='store_true')
        parser.add_argument(
            '--imports', help='Shows imports [ELF/PE]', action='store_true')
        parser.add_argument(
            '--symbols', help='Shows symbols [ELF]', action='store_true')
        parser.add_argument(
            '--set', help='Sets options. Available options: aslr nx', metavar='<option>')
        parser.add_argument(
            '--unset', help='Unsets options. Available options: aslr nx', metavar='<option>')
        parser.add_argument('-I', metavar='<imagebase>', help='Uses this imagebase for gadgets')
        parser.add_argument(
            '-p', '--ppr', help='Searches for \'pop reg; pop reg; ret\' instructions [only x86/x86_64]', action='store_true')
        parser.add_argument(
            '-j', '--jmp', help='Searches for \'jmp reg\' instructions (-j reg[,reg...]) [only x86/x86_64]', metavar='<reg>')
        parser.add_argument(
            '--depth', help='Specifies the depth of search (default: 10)', metavar='<n bytes>', type=int)
        parser.add_argument(
            '--search', help='Searches for gadgets', metavar='<regex>')
        parser.add_argument(
            '--quality', help='The quality for gadgets which are found by search (1 = best)', metavar='<quality>', type=int)
        parser.add_argument(
            '--filter', help='Filters gadgets', metavar='<regex>')
        parser.add_argument(
            '--opcode', help='Searches for opcodes', metavar='<opcode>')
        parser.add_argument(
            '--type', help='Sets the type of gadgets [rop, jop, all] (default: all)', metavar='<type>')
        parser.add_argument(
            '--detail', help='Prints gadgets more detailed', action='store_true')
        parser.add_argument(
            '--chain', help='Generates a ropchain [generator=parameter]', metavar='<generator>')
        parser.add_argument(
            '-b', '--badbytes', help='Set bytes which should not contains in gadgets', metavar='<badbytes>', default='')
        parser.add_argument(
            '--nocolor', help='Disables colored output', action='store_true')
        return parser

    def _analyseArguments(self):

        if len(self.__argv) == 0 or (len(self.__argv) == 1 and self.__argv[0] == '--nocolor'):
            self.__argv.append('--console')
        self.__args = self.__parser.parse_args(self.__argv)

        self.__args.nocolor = self.__args.nocolor and not self.isWindows()

        if not self.__args.console and not self.__args.file and not self.__args.version:
            self.__missingArgument('[-f|--file]')

        if not self.__args.depth:
            self.__args.depth = 10

        if not self.__args.type:
            self.__args.type = 'all'

        if self.__args.I:
            if not isHex(self.__args.I):
                raise ArgumentError('Imagebase should be in hex (0x.....)')
            else:
                self.__args.I = int(self.__args.I, 16)


    def __missingArgument(self, arg):
        raise ArgumentError('Missing argument: %s' % arg)

    def __getattr__(self, key):
        if key.startswith('_'):
            return super(Options, self).__getattr__(key)
        else:
            return vars(self.__args)[key]

    def isWindows(self):
      return sys.platform.startswith('win')

    def __setattr__(self, key, value):
        if key.startswith('_'):
            super(Options, self).__setattr__(key, value)
        else:
            vars(self.__args)[key] = value
