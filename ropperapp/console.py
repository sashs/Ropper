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

from ropperapp.loaders.loader import Loader
from ropperapp.printer.printer import FileDataPrinter
from ropperapp.disasm.rop import Ropper
from ropperapp.common.error import *
from ropperapp.disasm.gadget import GadgetType
from ropperapp.common.utils import isHex
from ropperapp.common.coloredstring import *
from ropperapp.common.utils import *
from ropperapp.disasm.chain.ropchain import *
from ropperapp.disasm.arch import getArchitecture
from binascii import unhexlify
import ropperapp
import cmd


def printError(error):
        print(cstr('[ERROR]', Color.RED)+' {}\n'.format(error))

def secure_cmd(func):
    def cmd(self, text):
        try:
            func(self, text)
        except RopperError as e:
            printError(e)
    return cmd


class Console(cmd.Cmd):

    def __init__(self, options):
        cmd.Cmd.__init__(self)
        self.__options = options
        self.__binary = None
        self.__printer = None
        self.__gadgets = {}
        self.__allGadgets = {}
        self.__loaded = False
        self.prompt = cstr('(ropper) ', Color.YELLOW)

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
        self.__loaded = False
        self.__binary = Loader.open(file)
        if self.__options.arch:
            self.__setarch(self.__options.arch)
        if not self.__binary.arch:
            raise RopperError('An architecture have to be set')
        self.__printer = FileDataPrinter.create(self.__binary.type)


    def __printGadget(self, gadget):
        if self.__options.detail:
            print(gadget)
        else:
            print(gadget.simpleString())

    def __printData(self, data):
        self.__printer.printData(self.__binary, data)

    def __printVersion(self):
        print("Version: Ropper %s" % ropperapp.VERSION)
        print("Author: Sascha Schirra")
        print("Website: http://scoding.de/ropper\n")

    def __printHelpText(self, cmd, desc):
        print('{}  -  {}\n'.format(cmd, desc))

    def __printError(self, error):
        printError(error)

    def __printInfo(self, error):
        print(cstr('[INFO]', Color.BLUE)+' {}'.format(error))

    def __printSeparator(self,before='', behind=''):
        print(before + '-'*40 + behind)

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
        gadgets = {}
        for section in self.__binary.executableSections:

            gadgets[section] = (
                r.searchJmpReg(section.bytes, regs, 0x0, badbytes=unhexlify(self.__options.badbytes)))

        self.__printer.printTableHeader('JMP Instructions')
        counter = 0
        for section, gadget in gadgets.items():
            for g in gadget:
                vaddr = self.__options.I + section.offset if self.__options.I != None else section.virtualAddress
                g.imageBase = vaddr
                print(g.simpleString())
                counter += 1
        print('')
        print('%d times opcode found' % counter)

    def __searchOpcode(self, opcode):
        r = Ropper(self.__binary.arch)
        gadgets = {}
        for section in self.__binary.executableSections:
            gadgets[section]=(
                r.searchOpcode(section.bytes, unhexlify(opcode.encode('ascii')), 0x0, badbytes=unhexlify(self.__options.badbytes)))

        self.__printer.printTableHeader('Opcode')
        counter = 0
        for section, gadget in gadgets.items():
            for g in gadget:
                vaddr = self.__options.I + section.offset if self.__options.I != None else section.virtualAddress
                g.imageBase = vaddr
                print(g.simpleString())
                counter += 1
        print('')
        print('%d times opcode found' % counter)

    def __searchPopPopRet(self):
        r = Ropper(self.__binary.arch)

        self.__printer.printTableHeader('POP;POP;REG Instructions')
        for section in self.__binary.executableSections:

            vaddr = self.__options.I + section.offset if self.__options.I != None else section.virtualAddress
            pprs = r.searchPopPopRet(section.bytes, 0x0, badbytes=unhexlify(self.__options.badbytes))
            for ppr in pprs:
                ppr.imageBase = vaddr
                self.__printGadget(ppr)
        print('')


    def __printRopGadgets(self, gadgets):
        self.__printer.printTableHeader('Gadgets')
        counter = 0
        for section, gadget in gadgets.items():
            vaddr = self.__options.I + section.offset if self.__options.I != None else section.virtualAddress
            for g in gadget:
                g.imageBase = vaddr
                self.__printGadget(g)
                counter +=1
            #print('')
        print('\n%d gadgets found' % counter)

    def __searchGadgets(self):
        gadgets = {}
        r = Ropper(self.__binary.arch)
        for section in self.__binary.executableSections:
            vaddr = self.__options.I + section.offset if self.__options.I != None else section.virtualAddress
            newGadgets = r.searchRopGadgets(
                section.bytes, section.offset,vaddr, badbytes=unhexlify(self.__options.badbytes), depth=self.__options.depth, gtype=GadgetType[self.__options.type.upper()])


            gadgets[section] = (newGadgets)
        return gadgets

    def __loadGadgets(self):
        self.__loaded = True
        self.__allGadgets = self.__searchGadgets()
        self.__filterBadBytes()


    def __filterBadBytes(self):
        self.__gadgets = self.__allGadgets

    def __searchAndPrintGadgets(self):
        self.__loadGadgets()
        gadgets = self.__gadgets
        if self.__options.search:
            gadgets = self.__search(self.__gadgets, self.__options.search)
        elif self.__options.filter:
            gadgets = self.__filter(self.__gadgets, self.__options.filter)
        self.__printRopGadgets(gadgets)

    def __filter(self, gadgets, filter):
        filtered = {}
        for section, gadget in gadgets.items():
            fg = []
            for g in gadget:
                if not g.match(filter):
                    fg.append(g)
            filtered[section] = fg
        return filtered

    def __search(self, gadgets, filter):
        filtered = {}
        for section, gadget in gadgets.items():
            fg = []
            for g in gadget:
                if g.match(filter):
                    fg.append(g)
            filtered[section] = fg
        return filtered

    def __generateChain(self, gadgets, command):
        split = command.split('=')

        old = self.__options.nocolor
        self.__options.nocolor = True
        gadgetlist = []
        vaddr = 0
        for section, gadget in gadgets.items():
            if len(gadget) != 0:
                vaddr = self.__options.I + section.offset if self.__options.I != None else section.virtualAddress
            gadgetlist.extend(gadget)

        generator = RopChain.get(self.__binary,split[0], gadgetlist, vaddr)

        self.__printInfo('generating rop chain')
        self.__printSeparator(behind='\n\n')

        if len(split) == 2:
            generator.create(split[1])
        else:
            generator.create()

        self.__printSeparator(before='\n\n')
        self.__printInfo('rop chain generated!')
        self.__options.nocolor = old


    def __checksec(self):
        sec = self.__binary.checksec()
        data = []
        yes = cstr('Yes', Color.RED)
        no = cstr('No', Color.GREEN)
        for item, value in sec.items():
            data.append((cstr(item, Color.BLUE), yes if value else no))
        printTable('Security',(cstr('Name'), cstr('value')), data)


    def __setarch(self, arch):
        if self.__binary:
            self.__binary.arch = getArchitecture(arch)
            self.__options.arch = arch
        else:
            self.__printError('No file loaded')

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
        #elif options.checksec:
         #   self.__checksec()
        elif options.chain:
            self.__loadGadgets()
            self.__generateChain(self.__gadgets, options.chain)
        else:
            self.__searchAndPrintGadgets()

####### cmd commands ######
    @secure_cmd
    def do_show(self, text):
        if not self.__binary:
            self.__printError("No file loaded!")
            return
        elif len(text) == 0:
            self.help_show()
            return

        self.__printData(text)


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

    @secure_cmd
    def do_file(self, text):
        if len(text) == 0:
            self.help_file()
            return
        
        self.__loadFile(text)
        self.__printInfo('File loaded.')

    def help_file(self):
        self.__printHelpText('file <file>', 'loads a file')

    @secure_cmd
    def do_set(self, text):
        if not text:
            self.help_set()
            return
        if not self.__binary:
            self.__printError('No file loaded')
            return
        self.__set(text, True)
        

    def help_set(self):
        desc = """Sets options.
Options:
aslr\t- Sets the ASLR-Flag (PE)
nx\t- Sets the NX-Flag (ELF|PE)"""
        self.__printHelpText('set <option>', desc)

    def complete_set(self, text, line, begidx, endidx):
        return [i for i in ['aslr', 'nx'] if i.startswith(text)]

    @secure_cmd
    def do_unset(self, text):
        if not text:
            self.help_unset()
            return
        if not self.__binary:
            self.__printError('No file loaded')
            return
        self.__set(text, False)
       

    def help_unset(self):
        desc = """Clears options.
Options:
aslr\t- Clears the ASLR-Flag (PE)
nx\t- Clears the NX-Flag (ELF|PE)"""
        self.__printHelpText('unset <option>', desc)

    def complete_unset(self, text, line, begidx, endidx):
        return self.complete_set(text, line, begidx, endidx)

    @secure_cmd
    def do_gadgets(self, text):
        if not self.__binary:
            self.__printError('No file loaded')
            return
        if not self.__loaded:
            self.__printInfo('Gadgets have to be loaded with load')
            return
        self.__printRopGadgets(self.__gadgets)

    def help_gadgets(self):
        self.__printHelpText('gadgets', 'shows all loaded gadgets')

    @secure_cmd
    def do_load(self, text):
        if not self.__binary:
            self.__printError('No file loaded')
            return
        self.__printInfo('loading...')
        self.__loadGadgets()
        self.__printInfo('gadgets loaded.')

    def help_load(self):
        self.__printHelpText('load', 'loads gadgets')

    @secure_cmd
    def do_ppr(self, text):
        if not self.__binary:
            self.__printError('No file loaded')
            return
        self.__searchPopPopRet()

    def help_ppr(self):
        self.__printHelpText('ppr', 'shows all pop,pop,ret instructions')

    @secure_cmd
    def do_filter(self, text):
        if len(text) == 0:
            self.help_filter()
            return

        self.__printRopGadgets(self.__filter(self.__gadgets, text))

    def help_filter(self):
        self.__printHelpText('filter <filter>', 'filters gadgets')

    @secure_cmd
    def do_search(self, text):
        if len(text) == 0:
            self.help_search()
            return

        self.__printRopGadgets(self.__search(self.__gadgets, text))

    def help_search(self):
        self.__printHelpText('searchs <regex>', 'search gadgets')

    @secure_cmd
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

    @secure_cmd
    def do_imagebase(self, text):
        if len(text) == 0:
            self.__options.I = None
        elif isHex(text):
            self.__options.I = int(text, 16)
        else:
            self.help_imagebase()

    def help_imagebase(self):
        self.__printHelpText('imagebase <base>', 'sets a new imagebase for searching gadgets')

    @secure_cmd
    def do_type(self, text):
        if len(text) == 0:
            self.help_type()
            return
        if text not in ['rop','jop','all']:
            self.__printError('invalid type: %s' % text)
            return
        self.__options.type = text
        self.__printInfo('Gadgets have to be reloaded')


    def help_type(self):
        self.__printHelpText('type <type>', 'sets the gadget type (rop, jop, all, default:all)')

    @secure_cmd
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

    @secure_cmd
    def do_detailed(self, text):
        if text:
            if text == 'on':
                self.__options.detail = True
            elif text == 'off':
                self.__options.detail = False
        else:
            print('on' if self.__options.detail else 'off')

    def help_detailed(self):
        self.__printHelpText('detailed [on|off]', 'sets detailed gadget output')

    def complete_detailed(self, text, line, begidx, endidx):
        return [i for i in ['on', 'off'] if i.startswith(text)]

    @secure_cmd
    def do_settings(self, text):
        data = [
            (cstr('badbytes') , cstr(self.__options.badbytes)),
            (cstr('color') , cstr('off' if self.__options.nocolor else 'on')),
            (cstr('detailed') , cstr('on' if self.__options.detail else 'off')),
            (cstr('type') , cstr(self.__options.type))]

        printTable('Settings',(cstr('Name'), cstr('Value')), data)

    def help_settings(self):
        self.__printHelpText('settings','shows the current settings')

    @secure_cmd
    def do_badbytes(self, text):
        if len(text) ==0:
            self.__printInfo('badbytes cleared')
        if not isHex('0x'+text):
            self.__printError('not allowed characters in badbytes')
            return
        self.__options.badbytes =text
        self.__printInfo('Gadgets have to be reloaded')

    def help_badbytes(self):
        self.__printHelpText('badbytes [bytes]', 'sets/clears bad bytes')

    @secure_cmd
    def do_color(self, text):
        if self.__options.isWindows():
            self.__printInfo('No color support for windows')
            return
        if text:
            if text == 'on':
                self.__options.nocolor = False
            elif text == 'off':
                self.__options.nocolor = True
        else:
            print('off' if self.__options.nocolor else 'on')

    def help_color(self):
        self.__printHelpText('color [on|off]', 'sets colorized output')

    def complete_color(self, text, line, begidx, endidx):
        return [i for i in ['on', 'off'] if i.startswith(text)]

    @secure_cmd
    def do_ropchain(self, text):
        if len(text) == 0:
            self.help_ropchain()
            return
        if not self.__gadgets:
            self.do_load(text)
        
        self.__generateChain(self.__gadgets, text)
        

    def help_ropchain(self):
        self.__printHelpText('ropchain <generator>[=args]','uses the given generator and create a ropchain with args')

    def do_quit(self, text):
        exit(0)

    def help_quit(self):
        self.__printHelpText('quit', 'quits the application')

    @secure_cmd
    def do_arch(self, text):
        if not text:
            self.help_arch()
        self.__setarch(text)
        

    def help_arch(self):
        self.__printHelpText('arch', 'sets the architecture for the loaded file')
