#!/usr/bin/env python2
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

import cmd
from .loaders.loader import Loader
from .printer.printer import FileDataPrinter
from .disasm.rop import Ropper
from .common.error import *
from .disasm.gadget import GadgetType
import ropperapp
from .common.utils import isHex


class Console(cmd.Cmd):

    def __init__(self, options):
        cmd.Cmd.__init__(self)
        self.__options = options
        self.__binary = None
        self.__printer = None
        self.__gadgets = []
        self.prompt = '(ropper) '

    def start(self):
        if self.__options.version:
            self.__printVersion()
            return

        if self.__options.file:
            self.__loadFile(self.__options.file)

        if self.__options.console:
            self.cmdloop()

        self.__handleOptions(self.__options)

    def __loadFile(self, file):
        self.__binary = Loader.open(file)
        self.__printer = FileDataPrinter.create(self.__binary.type)

    def __printData(self, data):
        self.__printer.printData(self.__binary, data)

    def __printVersion(self):
        print("Version: Ropper %s" % ropperapp.VERSION)
        print("Author: Sascha Schirra")
        print("Website: http://scoding.de/ropper\n")

    def __printHelpText(self, cmd, desc):
        print('{}  -  {}\n'.format(cmd, desc))

    def __printError(self, error):
        print('ERROR: {}\n'.format(error))

    def __printInfo(self, error):
        print('INFO: {}'.format(error))

    def __setASLR(self, enable):
        self.__binary.setASLR(enable)

    def __setNX(self, enable):
        self.__binary.setNX(enable)

    def __set(self, option, enable):
        if option == 'aslr':
            self.__setASLR(enable)
        elif option == 'nx':
            self.__setNX(enable)
        else:
            raise ArgumentError('Invalid option: {}'.format(option))

    def __searchJmpReg(self, regs):
        r = Ropper(self.__binary.arch)
        gadgets = []
        for section in self.__binary.executableSections:
            vaddr = self.__options.I + section.offset if self.__options.I != None else section.virtualAddress
            gadgets.extend(
                r.searchJmpReg(section.bytes, regs, vaddr))

        self.__printer.printTableHeader('JMP Instructions')
        for gadget in gadgets:
            print(gadget)
        print('')
        print('%d times opcode found' % len(gadgets))

    def __searchOpcode(self, opcode):
        r = Ropper(self.__binary.arch)
        gadgets = []
        for section in self.__binary.executableSections:
            vaddr = self.__options.I + section.offset if self.__options.I != None else section.virtualAddress
            gadgets.extend(
                r.searchOpcode(section.bytes, opcode.decode('hex'), vaddr))

        self.__printer.printTableHeader('Opcode')
        for gadget in gadgets:
            print(gadget)
        print('')
        print('%d times opcode found' % len(gadgets))

    def __searchPopPopRet(self):
        r = Ropper(self.__binary.arch)

        for section in self.__binary.executableSections:
            vaddr = self.__options.I + section.offset if self.__options.I != None else section.virtualAddress
            pprs = r.searchPopPopRet(section.bytes, vaddr)
            self.__printer.printTableHeader('POP;POP;REG Instructions')
            for ppr in pprs:
                print(ppr)
                print('')

    def __printRopGadgets(self, gadgets):
        self.__printer.printTableHeader('Gadgets')
        for gadget in gadgets:
            print(gadget)
            print('')
        print('%d gadgets found' % len(gadgets))

    def __searchGadgets(self):
        gadgets = []
        r = Ropper(self.__binary.arch)
        for section in self.__binary.executableSections:
            vaddr = self.__options.I + section.offset if self.__options.I != None else section.virtualAddress
            newGadgets = r.searchRopGadgets(
                section.bytes, vaddr, depth=self.__options.depth, gtype=GadgetType[self.__options.type.upper()])

            gadgets.extend(newGadgets)
        return gadgets

    def __loadGadgets(self):
        self.__gadgets = self.__searchGadgets()

    def __searchAndPrintGadgets(self):
        self.__loadGadgets()
        gadgets = self.__gadgets
        if self.__options.search:
            gadgets = self.__search(self.__gadgets, self.__options.search)
        elif self.__options.filter:
            gadgets = self.__filter(self.__gadgets, self.__options.filter)
        self.__printRopGadgets(gadgets)

    def __filter(self, gadgets, filter):
        filtered = []
        for gadget in gadgets:
            if not gadget.match(filter):
                filtered.append(gadget)
        return filtered

    def __search(self, gadgets, filter):
        filtered = []
        for gadget in gadgets:
            if gadget.match(filter):
                filtered.append(gadget)
        return filtered

    def __handleOptions(self, options):
        if options.sections:
            self.__printData('sections')
        elif options.symbols:
            self.__printData('symbols')
        elif options.segments:
            self.__printData('segments')
        elif options.dllcharacteristics:
            self.__printData('dll_characteristics')
        elif options.imagebase:
            self.__printData('image_base')
        elif options.e:
            self.__printData('entry_point')
        elif options.imports:
            self.__printData('imports')
        elif options.set:
            self.__set(options.set, True)
        elif options.unset:
            self.__set(options.unset, False)
        elif options.info:
            self.__printData('informations')
        elif options.ppr:
            self.__searchPopPopRet()
        elif options.jmp:
            self.__searchJmpReg(options.jmp)
        elif options.opcode:
            self.__searchOpcode(self.__options.opcode)
        else:
            self.__searchAndPrintGadgets()

# cmd commands
    def do_show(self, text):
        if not self.__binary:
            self.__printError("No file loaded!")
            return
        elif len(text) == 0:
            self.help_show()
            return

        try:
            self.__printData(text)
        except RopperError as e:
            self.__printError(e)

    def help_show(self):
        desc = 'shows informations about the loaded file'
        if self.__printer:
            desc += ('Available informations:\n' +
                     ('\n'.join(self.__printer.availableInformations)))
        self.__printHelpText(
            'show <info>', 'shows informations about the loaded file')

    def complete_show(self, text, line, begidx, endidx):
        if self.__binary:
            return [i for i in self.__printer.availableInformations if i.startswith(
                    text)]

    def do_file(self, text):
        if len(text) == 0:
            self.help_file()
            return
        try:
            self.__loadFile(text)
            self.__printInfo('File loaded.')

        except RopperError as e:
            self.__printError(e)

    def help_file(self):
        self.__printHelpText('file <file>', 'loads a file')

    def do_set(self, text):
        if not text:
            self.help_set()
            return
        if not self.__binary:
            self.__printError('No file loaded')
            return
        try:
            self.__set(text, True)
        except RopperError as e:
            self.__printError(e)

    def help_set(self):
        desc = """Sets options.
Options:
aslr\t- Sets the ASLR-Flag (PE)
nx\t- Sets the NX-Flag (ELF|PE)"""
        self.__printHelpText('set <option>', desc)

    def complete_set(self, text, line, begidx, endidx):
        return [i for i in ['aslr', 'nx'] if i.startswith(text)]

    def do_unset(self, text):
        if not text:
            self.help_unset()
            return
        try:
            if not self.__binary:
                self.__printError('No file loaded')
                return
            self.__set(text, False)
        except RopperError as e:
            self.__printError(e)

    def help_unset(self):
        desc = """Clears options.
Options:
aslr\t- Clears the ASLR-Flag (PE)
nx\t- Clears the NX-Flag (ELF|PE)"""
        self.__printHelpText('unset <option>', desc)

    def complete_unset(self, text, line, begidx, endidx):
        return self.complete_set(text, line, begidx, endidx)

    def do_gadgets(self, text):
        if not self.__binary:
            self.__printError('No file loaded')
            return
        self.__printRopGadgets(self.__gadgets)

    def help_gadgets(self):
        self.__printHelpText('gadgets', 'shows all loaded gadgets')

    def do_load(self, text):
        if not self.__binary:
            self.__printError('No file loaded')
            return
        self.__printInfo('loading...')
        self.__loadGadgets()
        self.__printInfo('gadgets loaded.')

    def help_load(self):
        self.__printHelpText('load', 'loads gadgets')

    def do_ppr(self, text):
        if not self.__binary:
            self.__printError('No file loaded')
            return
        self.__searchPopPopRet()

    def help_ppr(self):
        self.__printHelpText('ppr', 'shows all pop,pop,ret instructions')

    def do_filter(self, text):
        if len(text) == 0:
            self.help_filter()
            return

        self.__printRopGadgets(self.__filter(self.__gadgets, text))

    def help_filter(self):
        self.__printHelpText('filter <filter>', 'filters gadgets')

    def do_search(self, text):
        if len(text) == 0:
            self.help_search()
            return

        self.__printRopGadgets(self.__search(self.__gadgets, text))

    def help_search(self):
        self.__printHelpText('searchs <regex>', 'search gadgets')

    def do_opcode(self, text):
        if len(text) == 0:
            self.help_opcode()
            return
        if not self.__binary:
            self.__printError('No file loaded')
            return

        self.__searchOpcode(text)

    def help_opcode(self):
        self.__printHelpText(
            'opcode <opcode>', 'searchs opcode in executable sections')

    def do_imagebase(self, text):
        if len(text) == 0:
            self.__options.I = None
            self.__printInfo('Gadgets have to be reloaded')
        elif isHex(text):
            self.__options.I = int(text, 16)
            self.__printInfo('Gadgets have to be reloaded')
        else:
            self.help_imagebase()

    def help_imagebase(self):
        self.__printHelpText('imagebase <base>', 'sets a new imagebase for searching gadgets')

    def do_type(self, text):
        if len(text) == 0:
            self.help_type()
            return
        self.__options.type = text
        self.__printInfo('Gadgets have to be reloaded')


    def help_type(self):
        self.__printHelpText('type <type>', 'sets the gadget type (rop, jop, all, default:all)')

    def do_jmp(self, text):
        if not self.__binary:
            self.__printError('No file loaded')
            return
        if len(text) == 0:
            self.help_jmp()
            return
        self.__searchJmpReg(text)


    def help_jmp(self):
        self.__printHelpText('jmp <reg[,reg...]>', 'searchs jmp reg instructions')

    def do_quit(self, text):
        exit(0)

    def help_quit(self):
        self.__printHelpText('quit', 'quits the application')
