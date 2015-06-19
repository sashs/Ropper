# coding=utf-8
#
# Copyright 2015 Sascha Schirra
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
from ropperapp.disasm.gadget import GadgetDAO
from ropperapp.common.utils import isHex
from ropperapp.common.coloredstring import *
from ropperapp.common.utils import *
from ropperapp.disasm.chain.ropchain import *
from ropperapp.disasm.arch import getArchitecture
from binascii import unhexlify
from sys import stdout, stdin
import ropperapp
import cmd
import re
import os

# Python2 compatibility
try: input = raw_input
except: pass


def safe_cmd(func):
    def cmd(self, text):
        try:
            func(self, text)
        except RopperError as e:
            ConsolePrinter().printError(e)
    return cmd


class Console(cmd.Cmd):

    def __init__(self, options):
        cmd.Cmd.__init__(self)
        self.__options = options
        self.__binary = None
        self.__binaries = []
        self.__cprinter = ConsolePrinter()
        self.prompt = cstr('(ropper) ', Color.YELLOW)

    @property
    def binary(self):
        if not self.__binary:
            raise RopperError('No binary loaded')
        return self.__binary

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
        self.__binaries.append(self.__binary)
        self.__binary.manualImagebase = self.__options.I
        if self.__options.arch:
            self.__setarch(self.__options.arch)
        if self.__binaries[0] != self.__binary and self.__binaries[0].arch != self.__binary.arch:
            raise RopperError('Load multiple files with different architectures is not supported')
        if not self.binary.arch:
            raise RopperError('An architecture have to be set')
        self.__binary.printer = FileDataPrinter.create(self.__binary.type)


    def __printGadget(self, gadget):
        if self.__options.detail:
            self.__cprinter.println(gadget)
        else:
            self.__cprinter.println(gadget.simpleString())

    def __printData(self, data):
        self.binary.printer.printData(self.binary, data)

    def __printVersion(self):
        self.__cprinter.println("Version: Ropper %s" % ropperapp.VERSION)
        self.__cprinter.println("Author: Sascha Schirra")
        self.__cprinter.println("Website: http://scoding.de/ropper\n")

    def __printHelpText(self, cmd, desc):
        self.__cprinter.println('{}  -  {}\n'.format(cmd, desc))

    def __printError(self, error):
        self.__cprinter.printError(error)

    def __printInfo(self, info):
        self.__cprinter.printInfo(cstr(info))

    def __printSeparator(self,before='', behind=''):
        self.__cprinter.println(before + '-'*40 + behind)

    def __setASLR(self, enable):
        self.binary.setASLR(enable)

    def __setNX(self, enable):
        self.binary.setNX(enable)

    def __set(self, option, enable):
        if option == 'aslr':
            self.__setASLR(enable)
        elif option == 'nx':
            self.__setNX(enable)
        else:
            raise ArgumentError('Invalid option: {}'.format(option))

    def __searchJmpReg(self, regs):
        r = Ropper(self.binary)
        gadgets = {}
        for section in self.binary.executableSections:
            vaddr = self.binary.manualImagebase + section.offset if self.binary.manualImagebase != None else section.virtualAddress
            gadgets[section] = (
                r.searchJmpReg(section.bytes, regs, 0x0, badbytes=unhexlify(self.__options.badbytes), section=section))

        self.binary.printer.printTableHeader('JMP Instructions')
        counter = 0
        for section, gadget in gadgets.items():
            for g in gadget:
                vaddr = self.binary.manualImagebase + section.offset if self.binary.manualImagebase != None else section.virtualAddress
                g.imageBase = vaddr
                self.__cprinter.println(g.simpleString())
                counter += 1
        self.__cprinter.println('')
        self.__cprinter.println('%d times opcode found' % counter)

    def __searchOpcode(self, opcode):
        r = Ropper(self.binary)
        gadgets = {}
        for section in self.binary.executableSections:
            vaddr = self.binary.manualImagebase + section.offset if self.binary.manualImagebase != None else section.virtualAddress
            gadgets[section]=(
                r.searchOpcode(section.bytes, unhexlify(opcode.encode('ascii')), 0x0, section=section, badbytes=unhexlify(self.__options.badbytes)))

        self.binary.printer.printTableHeader('Opcode')
        counter = 0
        for section, gadget in gadgets.items():
            for g in gadget:
                vaddr = self.binary.manualImagebase + section.offset if self.binary.manualImagebase != None else section.virtualAddress
                g.imageBase = vaddr
                self.__cprinter.println(g.simpleString())
                counter += 1
        self.__cprinter.println('')
        self.__cprinter.println('%d times opcode found' % counter)

    def __searchPopPopRet(self):
        r = Ropper(self.binary)

        self.binary.printer.printTableHeader('POP;POP;REG Instructions')
        for section in self.binary.executableSections:

            vaddr = self.binary.manualImagebase + section.offset if self.binary.manualImagebase != None else section.virtualAddress
            pprs = r.searchPopPopRet(section.bytes, 0x0, section=section, badbytes=unhexlify(self.__options.badbytes))
            for ppr in pprs:
                ppr.imageBase = vaddr
                self.__printGadget(ppr)
        self.__cprinter.println('')


    def __printRopGadgets(self, gadgets):
        self.binary.printer.printTableHeader('Gadgets')
        counter = 0
        for section, gadget in gadgets.items():
            vaddr = self.binary.manualImagebase + section.offset if self.binary.manualImagebase != None else section.virtualAddress
            for g in gadget:
                g.imageBase = vaddr
                self.__printGadget(g)
                counter +=1
            #print('')
        self.__cprinter.println('\n%d gadgets found' % counter)

    def __searchGadgets(self, binary):
        gadgets = {}
        r = Ropper(binary)
        for section in binary.executableSections:
            vaddr = self.binary.manualImagebase + section.offset if self.binary.manualImagebase != None else section.virtualAddress
            self.__printInfo('Loading gadgets for section: ' + section.name)
            newGadgets = r.searchRopGadgets(
                section.bytes, section.offset,vaddr, badbytes=unhexlify(self.__options.badbytes), depth=self.__options.depth, section=section, gtype=GadgetType[self.__options.type.upper()], pprinter=self.__cprinter)

            gadgets[section] = (newGadgets)
        return gadgets



    def __loadGadgets(self):
        self.binary.loaded = True
        self.binary.gadgets = self.__searchGadgets(self.binary)
        self.__filterBadBytes()

    def __loadAllGadgets(self):

        for binary in self.__binaries:
            self.__cprinter.printInfo('Load %s' % binary.fileName)
            binary.gadgets = self.__searchGadgets(binary)
            binary.loaded = True

    def __loadUnloadedGadgets(self):

        for binary in self.__binaries:
            if not binary.loaded:
                binary.gadgets = self.__searchGadgets(binary)
                binary.loaded = True

    def __filterBadBytes(self):
        self.binary.gadgets = self.binary.gadgets

    def __searchAndPrintGadgets(self):

        gadgets = self.binary.gadgets
        if self.__options.search:
            gadgets = self.__search(self.binary.gadgets, self.__options.search, self.__options.quality)
        elif self.__options.filter:
            gadgets = self.__filter(self.binary.gadgets, self.__options.filter)
        self.__printRopGadgets(gadgets)

    def __filter(self, gadgets, filter):
        self.__printInfo('Filtering gadgets: '+filter)
        found = self.binary.arch.searcher.filter(gadgets, filter, pprinter=self.__cprinter)
        return found

    def __search(self, gadgets, filter, quality=None):
        self.__printInfo('Searching for gadgets: '+filter)
        found = self.binary.arch.searcher.search(gadgets, filter, quality, pprinter=self.__cprinter)
        return found

    def __generateChain(self, gadgets, command):
        split = command.split('=')

        old = self.__options.nocolor
        self.__options.nocolor = True

        generator = RopChain.get(self.__binaries,split[0], self.__cprinter)

        self.__printInfo('generating rop chain')
        #self.__printSeparator(behind='\n\n')

        if len(split) == 2:
            generator.create(split[1])
        else:
            generator.create()

        #self.__printSeparator(before='\n\n')
        self.__printInfo('rop chain generated!')
        self.__options.nocolor = old


    def __checksec(self):
        sec = self.binary.checksec()
        data = []
        yes = cstr('Yes', Color.RED)
        no = cstr('No', Color.GREEN)
        for item, value in sec.items():
            data.append((cstr(item, Color.BLUE), yes if value else no))
        printTable('Security',(cstr('Name'), cstr('value')), data)


    def __setarch(self, arch):
        if self.binary:
            self.binary.arch = getArchitecture(arch)
            self.__options.arch = arch
        else:
            self.__printError('No file loaded')

    def __savedb(self, dbpath):
        if not dbpath.endswith('.db'):
            dbpath = dbpath+'.db'
        if os.path.exists(dbpath):
            self.__cprinter.printInfo('db exists')
            overwrite = input('Overwrite? [Y/n]: ')
            if not overwrite or overwrite.upper() == 'Y':
                self.__cprinter.printInfo('overwrite db')
                os.remove(dbpath)
            else:
                self.__cprinter.printInfo('choose another db name')
                return
        dao = GadgetDAO(dbpath, self.__cprinter)

        dao.save(self.binary.gadgets)

    def __loaddb(self, dbpath):
        if not dbpath.endswith('.db'):
            dbpath = dbpath+'.db'
        if not os.path.exists(dbpath):
            raise RopperError('db does not exist: '+dbpath)

        dao = GadgetDAO(dbpath, self.__cprinter)

        self.binary.gadgets = dao.load(self.binary)
        self.binary.loaded = True

    def __printStrings(self, string, sec=None):
        data = []
        if not string or string == '[ -~]{2}[ -~]*':
            string = '[ -~]{2}[ -~]*'
        else:
            string = self.binary.arch.searcher.prepareFilter(string)
        sections = list(self.__binary.dataSections)
        
        for section in sections:
            if not sec or sec == str(section.name):
                b = bytes(bytearray(section.bytes))
                for match in re.finditer(string, b):

                    data.append( (cstr(toHex(match.start() + section.virtualAddress), Color.RED) , cstr(match.group(), Color.LIGHT_GRAY)))
        printTable('Strings',(cstr('Address'), cstr('Value')), data)

    def __disassemble(self, addr, length):
        eSections = self.__binary.executableSections

        for section in  eSections:
            if section.virtualAddress <= addr and section.virtualAddress + section.size > addr:
                ropper = Ropper(self.binary)

                code = bytes(bytearray(section.bytes))
                g = ropper.disassemble(code, addr, addr - section.virtualAddress, length)
                if not g:
                    self.__cprinter.printError('Cannot disassemble address: %s' % toHex(addr))
                    return
                if length < 0:
                    length = length * -1
                if len(g) < length:
                    self.__cprinter.printInfo('Cannot disassemble specified count of instructions')
                self.binary.printer.printTableHeader('Instructions')
                self.__cprinter.println(g.disassemblyString())
                return

    def __printSectionInHex(self, section):
        section = self.__binary.getSection(section.encode('ASCII'))
        printHexFormat(section.bytes, section.virtualAddress)


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
        elif options.string:
            self.__printStrings(options.string, options.section)
        elif options.hex and options.section:
            self.__printSectionInHex(options.section)
        elif options.disassemble:
            split = options.disassemble.split(':')
            length = 1
            if not isHex(split[0]):
                raise RopperError('Number have to be in hex format 0x....')
                
            if len(split) > 1:
                if split[1][1:].isdigit() or (len(split[1]) >= 3 and split[1][1] == '-' and split[1][2:].isdigit()): # is L\d or L-\d
                    length = int(split[1][1:])
                else:
                    raise RopperError('Length have to be in the following format L + Number e.g. L3')
            self.__disassemble(int(split[0],16), length)
        #elif options.checksec:
         #   self.__checksec()
        elif options.chain:
            self.__loadGadgets()
            self.__generateChain(self.binary.gadgets, options.chain)
        elif options.db:
            self.__loaddb(options.db)
            self.__searchAndPrintGadgets()
        else:
            self.__loadGadgets()
            self.__searchAndPrintGadgets()

####### cmd commands ######
    @safe_cmd
    def do_show(self, text):
        if len(text) == 0:
            self.help_show()
            return

        self.__printData(text)


    def help_show(self):
        desc = 'shows informations about the loaded file'
        if self.binary.printer:
            desc += ('Available informations:\n' +
                     ('\n'.join(self.binary.printer.availableInformations)))
        self.__printHelpText(
            'show <info>', 'shows informations about the loaded file')

    def complete_show(self, text, line, begidx, endidx):
        if self.binary:
            return [i for i in self.binary.printer.availableInformations if i.startswith(
                    text)]

    @safe_cmd
    def do_close(self, text):  
        
        if text.isdigit():
            idx = int(text)
            if len(self.__binaries) > idx-1:
                del self.__binaries[idx-1]
                if len(self.__binaries) != 0:
                    self.__binary = self.__binaries[0]
                else:
                    self.__binary = None
            else:
                self.__cprinter.printError('Index is too small or to large')
        elif text == 'all':
            self.__binaries = []
            self.__binary = None
        else:
            self.help_close()


    def help_close(self):
        self.__printHelpText('close idx/all', 'closes opened files\nidx - index of file which should be closed\nall - closes all files')

    @safe_cmd
    def do_file(self, text):
        if len(text) == 0:
            data = []
            for index,binary in enumerate(self.__binaries):
                if self.binary == binary:
                    data.append((cstr(index+1), cstr(binary.fileName+'*') , cstr(binary.loaded)))
                else:
                    data.append((cstr(index+1), cstr(binary.fileName) , cstr(binary.loaded)))

            printTable('Opened Files',(cstr('No.'),cstr('Name'), cstr('Loaded')), data)
            
        elif text.isdigit():
            idx = int(text)-1
            if idx >= len(self.__binaries):
                raise RopperError('Index is too small or to large')
            self.__binary = self.__binaries[idx]
            self.__printInfo('File \'%s\' selected.' % self.binary.fileName)
        else:
            self.__loadFile(text)
            self.__printInfo('File loaded.')

    def help_file(self):
        self.__printHelpText('file <file>|<idx>', 'file - loads a file\nidx - select this loaded file')

    @safe_cmd
    def do_set(self, text):
        if not text:
            self.help_set()
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

    @safe_cmd
    def do_unset(self, text):
        if not text:
            self.help_unset()
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

    @safe_cmd
    def do_gadgets(self, text):

        if not self.binary.loaded:
            self.__printInfo('Gadgets have to be loaded with load')
            return

        self.__printRopGadgets(self.binary.gadgets)

    def help_gadgets(self):
        self.__printHelpText('gadgets', 'shows all loaded gadgets')

    @safe_cmd
    def do_load(self, text):
        if text == 'all':
            self.__loadAllGadgets()
        elif text == 'unloaded':
            self.__loadUnloadedGadgets()
        else:    
            self.__loadGadgets()
            self.__printInfo('gadgets loaded.')

    def help_load(self):
        self.__printHelpText('load [all|unloaded]', 'all - loads gadgets of all opened files\n\t unloaded - loads gadgets of all unloaded opened files\n\t loads gadgets')

    @safe_cmd
    def do_ppr(self, text):
        self.__searchPopPopRet()

    def help_ppr(self):
        self.__printHelpText('ppr', 'shows all pop,pop,ret instructions')

    @safe_cmd
    def do_filter(self, text):
        if len(text) == 0:
            self.help_filter()
            return

        self.__printRopGadgets(self.__filter(self.binary.gadgets, text))

    def help_filter(self):
        self.__printHelpText('filter <filter>', 'filters gadgets')

    @safe_cmd
    def do_search(self, text):
        if len(text) == 0:
            self.help_search()
            return
        match = re.match('/\d+/', text)
        qual = None
        if match:
            qual = int(match.group(0)[1:-1])
            text = text[len(match.group(0)):].strip()
        for binary in self.__binaries:
            self.__cprinter.printInfo('Search in gadgets of file \'%s\'' % binary.fileName)
            self.__printRopGadgets(self.__search(binary.gadgets, text, qual))

    def help_search(self):
        desc = 'search gadgets.\n\n'
        desc += '/quality/\tThe quality of the gadget (1 = best).'
        desc += 'The better the quality the less instructions are between the found intruction and ret\n'
        desc += '?\t\tany character\n%\t\tany string\n\n'
        desc += 'Example:\n'
        desc += 'search mov e?x\n\n'
        desc += '0x000067f1: mov edx, dword ptr [ebp + 0x14]; mov dword ptr [esp], edx; call eax;\n'
        desc += '0x00006d03: mov eax, esi; pop ebx; pop esi; pop edi; pop ebp; ret ;\n'
        desc += '0x00006d6f: mov ebx, esi; mov esi, dword ptr [esp + 0x18]; add esp, 0x1c; ret ;\n'
        desc += '0x000076f8: mov eax, dword ptr [eax]; mov byte ptr [eax + edx], 0; add esp, 0x18; pop ebx; ret ;\n\n\n'
        desc += 'search mov [%], ecx\n\n'
        desc += '0x000067ed: mov dword ptr [esp + 4], edx; mov edx, dword ptr [ebp + 0x14]; mov dword ptr [esp], edx; call eax;\n'
        desc += '0x00006f4e: mov dword ptr [ecx + 0x14], edx; add esp, 0x2c; pop ebx; pop esi; pop edi; pop ebp; ret ;\n'
        desc += '0x000084b8: mov dword ptr [eax], edx; ret ;\n'
        desc += '0x00008d9b: mov dword ptr [eax], edx; add esp, 0x18; pop ebx; ret ;\n\n\n'
        desc += 'search /1/ mov [%], ecx\n\n'
        desc += '0x000084b8: mov dword ptr [eax], edx; ret ;\n'


        self.__printHelpText('search [/<quality>/] <string>',desc )

    @safe_cmd
    def do_opcode(self, text):
        if len(text) == 0:
            self.help_opcode()
            return

        self.__searchOpcode(text)

    def help_opcode(self):
        self.__printHelpText(
            'opcode <opcode>', 'searchs opcode in executable sections')

    @safe_cmd
    def do_imagebase(self, text):
        if len(text) == 0:
            self.binary.manualImagebase = None
        elif isHex(text):
            self.binary.manualImagebase = int(text, 16)
        else:
            self.help_imagebase()

    def help_imagebase(self):
        self.__printHelpText('imagebase <base>', 'sets a new imagebase for searching gadgets')

    @safe_cmd
    def do_type(self, text):
        if len(text) == 0:
            self.help_type()
            return
        if text not in ['rop','jop','all']:
            raise RopperError('invalid type: %s' % text)

        self.__options.type = text
        self.__printInfo('Gadgets have to be reloaded')


    def help_type(self):
        self.__printHelpText('type <type>', 'sets the gadget type (rop, jop, all, default:all)')

    @safe_cmd
    def do_jmp(self, text):
        if len(text) == 0:
            self.help_jmp()
            return

        self.__searchJmpReg(text)


    def help_jmp(self):
        self.__printHelpText('jmp <reg[,reg...]>', 'searchs jmp reg instructions')

    @safe_cmd
    def do_detailed(self, text):
        if text:
            if text == 'on':
                self.__options.detail = True
            elif text == 'off':
                self.__options.detail = False
        else:
            self.__cprinter.println('on' if self.__options.detail else 'off')

    def help_detailed(self):
        self.__printHelpText('detailed [on|off]', 'sets detailed gadget output')

    def complete_detailed(self, text, line, begidx, endidx):
        return [i for i in ['on', 'off'] if i.startswith(text)]

    @safe_cmd
    def do_settings(self, text):
        data = [
            (cstr('badbytes') , cstr(self.__options.badbytes)),
            (cstr('color') , cstr('off' if self.__options.nocolor else 'on')),
            (cstr('detailed') , cstr('on' if self.__options.detail else 'off')),
            (cstr('type') , cstr(self.__options.type))]

        printTable('Settings',(cstr('Name'), cstr('Value')), data)

    def help_settings(self):
        self.__printHelpText('settings','shows the current settings')

    @safe_cmd
    def do_badbytes(self, text):
        if len(text) ==0:
            self.__printInfo('badbytes cleared')
        elif not isHex('0x'+text):
            self.__printError('not allowed characters in badbytes')
            return
        self.__options.badbytes =text
        self.__printInfo('Gadgets have to be reloaded')

    def help_badbytes(self):
        self.__printHelpText('badbytes [bytes]', 'sets/clears bad bytes\n\n Example:\nbadbytes 000a0d  -- sets 0x00, 0x0a and 0x0d as badbytes')

    @safe_cmd
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
            self.__cprinter.println('off' if self.__options.nocolor else 'on')

    def help_color(self):
        self.__printHelpText('color [on|off]', 'sets colorized output')

    def complete_color(self, text, line, begidx, endidx):
        return [i for i in ['on', 'off'] if i.startswith(text)]

    @safe_cmd
    def do_ropchain(self, text):
        if len(text) == 0:
            self.help_ropchain()
            return
        if not self.binary.gadgets:
            self.do_load(text)

        gadgets = []
        for binary in self.__binaries:
            gadgets.append(binary.gadgets)
        self.__generateChain(gadgets, text)


    def help_ropchain(self):
        self.__printHelpText('ropchain <generator>[=args]','uses the given generator and create a ropchain with args')

    def do_quit(self, text):
        exit(0)

    def help_quit(self):
        self.__printHelpText('quit', 'quits the application')

    @safe_cmd
    def do_arch(self, text):
        if not text:
            self.help_arch()
        self.__setarch(text)


    def help_arch(self):
        self.__printHelpText('arch <arch>', 'sets the architecture <arch> for the loaded file')

    def help_savedb(self):
        self.__printHelpText('savedb <dbname>', 'saves all gadgets in database <dbname>')

    def help_loaddb(self):
        self.__printHelpText('loaddb <dbname>', 'loads all gadgets from database <dbname>')

    @safe_cmd
    def do_savedb(self, text):
        if not text:
            self.help_savedb()
            return
        if not self.binary.loaded:
            self.__printInfo('Gadgets have to be loaded with load')
            return
        self.__savedb(text)


    @safe_cmd
    def do_loaddb(self, text):
        if not text:
            self.help_loaddb()
            return
        self.__loaddb(text)

    @safe_cmd
    def do_string(self, text):
        
        self.__printStrings(text)

    def help_string(self):
        self.__printHelpText('string [<string>]','Looks for string <string> in section <section>. If no string is given all strings are printed.')

    @safe_cmd
    def do_hex(self, text):
        if not text:
            self.help_text()
            return
        self.__printSectionInHex(text)

    def help_hex(self):
        self.__printHelpText('hex <section>','Prints the section <section> in hex format')

    @safe_cmd
    def do_disassemble(self, text):
        split = text.split(' ')
        length = 1
        if not isHex(split[0]):
            self._cprinter.printError('Number have to be in hex format 0x....')
            return
        if len(split) > 1:
            if split[1][1:].isdigit() or (len(split[1]) >= 3 and split[1][1] == '-' and split[1][2:].isdigit()): # is L\d or L-\d
                length = int(split[1][1:])
            else:
                self._cprinter.printError('Length have to be in the following format L + Number e.g. L3')
                return

        addr = int(split[0], 16)
        self.__disassemble(addr, length)

    def help_disassemble(self):
        self.__printHelpText('disassemble <address> [<length>]', 'Disassembles instruction at address <address>. The count of instructions to disassemble can be specified (0x....:L...)')



    def do_EOF(self, text):
        self.__cprinter.println('')
        self.do_quit(text);


class ConsolePrinter(object):


    def __init__(self, out=stdout):
        super(ConsolePrinter, self).__init__()
        self._out = out

    def puts(self, *args):

        for i, arg in enumerate(args):
            self._out.write(str(arg))
            if i != len(args)-1:
                self._out.write(' ')
        self._out.flush()

    def println(self, *args):

        self.puts(*args)
        self._out.write('\n')

    def printMessage(self, mtype, message):
        self.println(mtype, message)

    def printError(self, message):
        self.printMessage(cstr('[ERROR]', Color.RED), message)

    def printInfo(self, message):
        self.printMessage(cstr('[INFO]', Color.BLUE), message)

    def startProgress(self, message=None):
        if message:
            self.printInfo(message)

    def printProgress(self, message, progress):
        self.puts(cstr('\r') + cstr('[LOAD]', Color.GREEN), message, cstr(int(progress * 100))+cstr('%'))

    def finishProgress(self, message=None):
        self.println('')
        if message:
            self.printInfo(message)
