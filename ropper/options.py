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

import argparse
from ropper.common.error import *
from ropper.common.utils import isHex
from ropper.common.coloredstring import cstr
import sys



class Options(object):



    def __init__(self, argv):
        super(Options, self).__init__()

        self.__argv = argv
        self.__args = None
        self.__parser = self._createArgParser()
        self._analyseArguments()
        self.__callbacks = []
        self.__ropper_options = {}

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
  SPARC [SPARC64]

available rop chain generators:
  execve (execve[=<cmd>], default /bin/sh) [Linux x86, x86_64]
  mprotect  (mprotect address=0xdeadbeef size=0x10000) [Linux x86, x86_64]
  virtualprotect (virtualprotect address=0xdeadbeef) [Windows x86]
""")

        parser.add_argument(
            '--help-examples', help="Print examples", action='store_true')
        
        parser.add_argument(
            '-v', '--version', help="Print version", action='store_true')
        parser.add_argument(
            '--console', help='Starts interactive commandline', action='store_true')
        parser.add_argument(
            '-f', '--file', metavar="<file>", help='The file to load', nargs='+')
        parser.add_argument(
            '-r', '--raw', help='Loads the file as raw file', action='store_true')
        parser.add_argument(
            '-a', '--arch', metavar="<arch>", help='The architecture of the loaded file')
        parser.add_argument(
            '--section', help='The data of the this section should be printed', metavar='<section>')
        parser.add_argument(
            '--string', help='Looks for the string <string> in all data sections', metavar='<string>',nargs='?', const='[ -~]{2}[ -~]*')
        parser.add_argument(
            '--hex', help='Prints the selected sections in a hex format', action='store_true')
        parser.add_argument(
            '--asm', help='A string to assemble and a format of the output (H=HEX, S=STRING, R=RAW, default: H)', nargs='*', metavar="<asm> [H|S|R]")
        parser.add_argument(
            '--disasm', help='Opcode to disassemble (e.g. ffe4, 89c8c3, ...)', metavar="<opcode>")
        parser.add_argument(
            '--disassemble-address', help='Disassembles instruction at address <address> (0x12345678:L3). The count of instructions to disassemble can be specified (0x....:L...)', metavar='<address:length>')
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
            '--stack-pivot', help='Prints all stack pivot gadgets',action='store_true')
        parser.add_argument(
            '--inst-count', help='Specifies the max count of instructions in a gadget (default: 6)', metavar='<n bytes>', type=int, default=6)
        parser.add_argument(
            '--search', help='Searches for gadgets', metavar='<regex>')
        parser.add_argument(
            '--quality', help='The quality for gadgets which are found by search (1 = best)', metavar='<quality>', type=int)
        parser.add_argument(
            '--opcode', help='Searches for opcodes (e.g. ffe4 or ffe? or ff??)', metavar='<opcode>')
        parser.add_argument(
            '--instructions', help='Searches for instructions (e.g. "jmp esp", "pop eax; ret")', metavar='<instructions>')
        parser.add_argument(
            '--type', help='Sets the type of gadgets [rop, jop, sys, all] (default: all)', metavar='<type>', default='all')
        parser.add_argument(
            '--detailed', help='Prints gadgets more detailed', action='store_true')
        parser.add_argument(
            '--all', help='Does not remove duplicate gadgets', action='store_true')
        parser.add_argument(
            '--cfg-only', help='Filters out gadgets which fail the Microsoft CFG check. Only for PE files which are compiled with CFG check enabled (check DllCharachteristics) [PE]', action='store_true')
        parser.add_argument(
            '--chain', help='Generates a ropchain [generator parameter=value[ parameter=value]]', metavar='<generator>')
        parser.add_argument(
            '-b', '--badbytes', help='Set bytes which should not contains in gadgets', metavar='<badbytes>', default='')
        parser.add_argument(
            '--nocolor', help='Disables colored output', action='store_true')
        parser.add_argument(
            '--clear-cache', help='Clears the cache', action='store_true')
        parser.add_argument(
            '--no-load', help='Don\'t load the gadgets automatically when start the console (--console)', action='store_true', default=False)
        parser.add_argument(
            '--analyse', help='just used for the implementation of semantic search', metavar='<quality>')
        parser.add_argument(
            '--semantic', help='semantic search for gadgets', metavar='constraint')
        parser.add_argument(
            '--count-of-findings', help='Max count of gadgets which will be printed with semantic search (0 = undefined, default: 5)', metavar='<count of gadgets>', type=int, default=5)
        parser.add_argument(
            '--single', help='No multiple processes are used for gadget scanning', action='store_true', default=self.isWindows())
        return parser

    def _analyseArguments(self):

        if len(self.__argv) == 0:
            self.__argv.append('--console')
        elif (len(self.__argv) == 1 and self.__argv[0] == '--nocolor'):
            self.__argv.append('--console')

        self.__args = self.__parser.parse_args(self.__argv)

        self.nocolor = self.__args.nocolor or self.isWindows()

        if not self.__args.clear_cache and not self.__args.help_examples and not self.__args.asm and not self.disasm and not self.__args.console and not self.__args.file and not self.__args.version:
            self.__missingArgument('[-f|--file]')

        if self.__args.I:
            if not isHex(self.__args.I):
                raise ArgumentError('Imagebase should be in hex (0x.....)')
            else:
                self.__args.I = int(self.__args.I, 16)

        ropper_options = {}
        ropper_options['all'] = self.__args.all
        ropper_options['color'] = not self.__args.nocolor
        ropper_options['badbytes'] = self.__args.badbytes
        ropper_options['detailed'] = self.__args.detailed
        ropper_options['inst_count'] = self.__args.inst_count
        ropper_options['type'] = self.__args.type
        ropper_options['cfg_only'] = self.__args.cfg_only
        ropper_options['count_of_findings'] = self.__args.count_of_findings
        ropper_options['multiprocessing'] = not self.__args.single
        self.ropper_options = ropper_options




    def __missingArgument(self, arg):
        raise ArgumentError('Missing argument: %s' % arg)

    def __getattr__(self, key):
        if key == 'color':
            key = 'nocolor'
        if key.startswith('_'):
            return super(Options, self).__getattr__(key)
        else:
            return vars(self.__args)[key]

    def isWindows(self):
      return sys.platform.lower().startswith('win')

    def __setattr__(self, key, value):
        if key.startswith('_'):
            super(Options, self).__setattr__(key, value)
        else:
            if key == 'nocolor':
              cstr.COLOR = not value
            vars(self.__args)[key] = value

    def setOption(self, key, value):
        if key in VALID_OPTIONS:
            old = self.getOption(key)
            result = VALID_OPTIONS[key](self, value)
            self.notifyOptionChanged(key, old, value)
            if result:
                return result[1]

            else:
              raise RopperError('Invalid value for option %s: %s' %(key, value))
        else:
            raise RopperError('Invalid option')

    def getOption(self, key):
        if key in VALID_OPTIONS:
            return self.__getattr__(key)
        else:
            raise RopperError('Invalid option: %s ' % key)

    def addOptionChangedCallback(self, func):
        self.__callbacks.append(func)

    def removeOptionChangedCallback(self, func):
        del self.__callbacks[self.__callbacks.index(func)]

    def notifyOptionChanged(self, option, old, new):
        for cb in self.__callbacks:
            cb(option, old, new)

    def _setAll(self, value):
        if value.lower() in ('on', 'off'):
            self.all = bool(value == 'on')
            return  (True,True)
        return False

    def _setInstCount(self, value):
        if value.isdigit():
            self.inst_count = int(value)
            return (True,True)
        return False

    def _setCountOfFindings(self, value):
        if value.isdigit():
            self.count_of_findings = int(value)
            return (True,True)
        return False

    def _setMultiprocessing(self, value):
        if value.lower() in ('on', 'off'):
            self.multiprocessing = bool(value == 'on')
            return (True,False)
        return False

    def _setBadbytes(self, value):
        if len(value) == 0 or isHex('0x'+value):
            self.badbytes = value
            return  (True,True)
        return False

    def _setDetailed(self, value):
        if value.lower() in ('on', 'off'):
            self.detailed = bool(value == 'on')
            return (True, False)
        return False

    def _setType(self, value):
        if value in ['rop','jop','sys','all']:
            self.type = value
            return  (True,True)
        return False

    def _setColor(self, value):
        if value.lower() in ('on', 'off'):
            self.nocolor = bool(value == 'off')
            return (True,False)
        return False

VALID_OPTIONS = {'all' : Options._setAll,
                     'inst_count' : Options._setInstCount,
                     'badbytes' : Options._setBadbytes,
                     'detailed' : Options._setDetailed,
                     'type' : Options._setType,
                     'color' : Options._setColor,
                     'multiprocessing' : Options._setMultiprocessing,
                     'count_of_findings' : Options._setCountOfFindings}
