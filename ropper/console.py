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
from __future__ import print_function
from ropper.loaders.loader import Loader, Type
from ropper.printer.printer import FileDataPrinter
from ropper.rop import Ropper
from ropper.common.error import *
from ropper.gadget import GadgetType
from ropper.gadget import Category
from ropper.semantic import Analyser
from ropper.common.utils import isHex, getFileNameFromPath
from ropper.common.coloredstring import *
from ropper.common.utils import *
from ropper.ropchain.ropchain import *
from ropper.arch import getArchitecture
from ropper.service import RopperService
from binascii import unhexlify
from sys import stdout, stdin, stderr
import ropper
import cmd
import re
import os
import traceback
import time

# Python2 compatibility
try:
    input = raw_input
except:
    pass


def safe_cmd(func):
    def cmd(self, text):
        cp = ConsolePrinter()
        try:
            func(self, text)
        except RopperError as e:
            cp.printError(e)
        except KeyboardInterrupt:
            cp.println()
        except:
            cp.printError('Please report this error on https://github.com/sashs/ropper')
            cp.printError( traceback.format_exc())
    return cmd

class CallbackClass(object):

    def __init__(self, console):
        self.__console = console

    def __gadgetSearchProgress__(self, section, gadgets, progress):
        if gadgets is not None:
            self.__console.cprinter.printProgress('loading...', progress)

            if progress == 1.0:
                self.__console.cprinter.finishProgress()
        else:
            self.__console.cprinter.printInfo(
                'Load gadgets for section: ' + section.name)

    def __deleteDoubleGadgetsProgress__(self, gadget, added, progress):
        self.__console.cprinter.printProgress('removing double gadgets...', progress)
        if progress == 1.0:
            self.__console.cprinter.finishProgress()

    def __filterCfgGadgetsProgress__(self, gadget, added, progress):
        self.__console.cprinter.printProgress('filtering cfg gadgets...', progress)
        if progress == 1.0:
            self.__console.cprinter.finishProgress()

    def __filterBadBytesGadgetsProgress__(self, gadget, added, progress):
        self.__console.cprinter.printProgress('filtering badbytes...', progress)
        if progress == 1.0:
            self.__console.cprinter.finishProgress()

    def __analyseGadgetsProgress__(self, gadget, progress):
        self.__console.cprinter.printProgress('analyse gadgets...', progress)
        if progress == 1.0:
            self.__console.cprinter.finishProgress()


    def __ropchainMessages__(self, message):
        if message.startswith('[*]'):
            self.__console.cprinter.puts('\r' + message)
        else:
            self.__console.cprinter.println()
            self.__console.cprinter.printInfo(message)

    def __message__(self, message):
        self.__console.cprinter.printInfo(message)

class Console(cmd.Cmd):

    def __init__(self, options):
        cmd.Cmd.__init__(self)
        self.__options = options
        if not options.isWindows():
            import readline
            old_delims = readline.get_completer_delims()
            old_delims = old_delims.replace('-', '')
            old_delims = old_delims.replace('/', '')
            readline.set_completer_delims(old_delims)
            #ää Fix completion on mac os
            import rlcompleter
            if 'libedit' in readline.__doc__:
                readline.parse_and_bind("bind ^I rl_complete")
            else:
                readline.parse_and_bind("tab: complete")

        self.__rs = RopperService(self.__options.ropper_options, callbacks=CallbackClass(self))
        self.__currentFileName = ''
        self.__cprinter = ConsolePrinter()
        self.__dataPrinter = {}
        self.__updatePrompt()

    @property
    def cprinter(self):
        return self.__cprinter

    @property
    def currentFileName(self):
        if not self.__currentFileName:
            raise RopperError('No binary loaded')
        return self.__currentFileName

    @property
    def currentFile(self):
        return self.__rs.getFileFor(self.currentFileName)

    def cmdloop(self):
        try:
            cmd.Cmd.cmdloop(self)
        except KeyboardInterrupt:
            print()
            self.cmdloop()

    def emptyline(self):
        pass

    def __getDataPrinter(self, type):
        p = self.__dataPrinter.get(type)
        if not p:
            p = FileDataPrinter.create(type)
            self.__dataPrinter[type] = p

        return p

    def start(self):
        if self.__options.version:
            self.__printVersion()
            return

        if self.__options.clear_cache:
            self.__rs.clearCache()

        if self.__options.file and self.__options.asm is None:
            for file in self.__options.file:
                self.__loadFile(file)
            if len(self.__options.file) > 1:
                self.do_file('1')

        if self.__options.console:
            self.cmdloop()

        self.__handleOptions(self.__options)

    def __updatePrompt(self):
        if self.__currentFileName:
            name = getFileNameFromPath(self.__currentFileName)
            self.prompt = cstr('(%s/%s/%s)> ' % (name, str(self.currentFile.type),self.currentFile.arch), Color.RED)
        else:
            self.prompt = cstr('(ropper)> ', Color.RED)

    def __loadFile(self, file):

        self.__rs.addFile(file, raw=self.__options.raw,
                          arch=self.__options.arch)
        self.__options.arch = None

        self.__currentFileName = file
        self.__updatePrompt()
        if self.__options.I is not None:
            self.__rs.setImageBaseFor(file, self.__options.I)
        if not self.__options.no_load and self.__options.console:
            self.__loadGadgets()

        #self.__binary.printer = FileDataPrinter.create(self.__binary.type)

    def __printGadget(self, gadget, detailed=False):
        if detailed:
            self.__cprinter.println(gadget)
        else:
            self.__cprinter.println(gadget.simpleString())

    def __printData(self, data):
        cf = self.currentFile
        self.__getDataPrinter(cf.type).printData(cf.loader, data)

    def __printVersion(self):
        self.__cprinter.println("Version: Ropper %s" %
                                '.'.join([str(x) for x in ropper.VERSION]))
        self.__cprinter.println("Author: Sascha Schirra")
        self.__cprinter.println("Website: http://scoding.de/ropper\n")

    def __printHelpText(self, cmd, desc):
        self.__cprinter.println('{}  -  {}\n'.format(cmd, desc))

    def __printError(self, error):
        self.__cprinter.printError(error)

    def __printInfo(self, info):
        self.__cprinter.printInfo(cstr(info))

    def __printSeparator(self, before='', behind=''):
        self.__cprinter.println(before + '-' * 40 + behind)

    def __setASLR(self, enable):
        self.currentFile.loader.setASLR(enable)

    def __setNX(self, enable):
        self.currentFile.loader.setNX(enable)

    def __set(self, option, enable):
        if option == 'aslr':
            self.__setASLR(enable)
        elif option == 'nx':
            self.__setNX(enable)
        else:
            raise ArgumentError('Invalid option: {}'.format(option))

    def __asm(self, code, arch, format):
        r = Ropper()
        if format == 'R':
            f = 'raw'
        elif format == 'H':
            f = 'hex'
        elif format == 'S':
            f = 'string'
        else:
            raise RopperError('wrong format: %s' % f)

        self.__cprinter.println(self.__rs.asm(code, arch, f))

    def __disasm(self, code, arch):
        r = Ropper()
        self.__cprinter.println(self.__rs.disasm(code, arch))

    def __searchJmpReg(self, regs):
        regs = regs.split(',')
        gadgets = self.__rs.searchJmpReg(name=self.currentFileName, regs=regs)
        self.__printGadgets([g for g in gadgets.values()][0], header='JMP Instructions')

    def __searchOpcode(self, opcode):
        gadgets = self.__rs.searchOpcode(
            name=self.currentFileName, opcode=opcode)
        self.__printGadgets([g for g in gadgets.values()][0], header='Opcode')

    def __searchInstructions(self, code):
        gadgets = self.__rs.searchInstructions(
            name=self.currentFileName, code=code)
        self.__printGadgets([g for g in gadgets.values()]
                            [0], header='Instructions')

    def __searchPopPopRet(self):
        pprs = self.__rs.searchPopPopRet(self.currentFileName)
        self.__printGadgets([g for g in pprs.values()][0],
                            header='POP;POP;RET Instructions')

    def __loadGadgetsForAllFiles(self):
        self.__rs.loadGadgetsFor()

    def __loadGadgets(self):
        self.__searchGadgetsFor(self.currentFileName)

    def __searchGadgetsFor(self, binary):

        self.__rs.loadGadgetsFor(binary)
        return self.__rs.getFileFor(binary).gadgets

    def __printGadgets(self, gadgets, category=None, header='Gadgets', detailed=False):
        self.__getDataPrinter(self.currentFile.type).printTableHeader(header)

        counter = 0
        for g in gadgets:
            if not category or category == g.category[0]:
                self.__printGadget(g, detailed=detailed)
                counter += 1

        self.__cprinter.println('\n%d gadgets found' % counter)



    def __printProgress(self, gadget, gnr, count):
        if gnr >= 0:
            self.__cprinter.printProgress('clearing up...', float(gnr) / count)
        else:
            self.__cprinter.printProgress('clearing up...', 1)
            self.__cprinter.finishProgress()

    def __loadAllGadgets(self):
        self.__rs.loadGadgetsFor()

    def __printGadgetsFromCurrentFile(self):
        gadgets = self.currentFile.gadgets
        self.__printGadgets(gadgets, detailed=self.__options.detailed)

    def __search(self, filter, quality=None):
        self.__printInfo('Searching for gadgets: ' + filter)
        old = None
        for fc, gadget in self.__rs.search(filter, quality):
            if fc != old:
                old = fc
                self.__cprinter.println()
                self.__printInfo('File: %s' % fc)

            self.__printGadget(gadget, self.__options.detailed)
        self.__cprinter.println()

    def __generateChain(self, command):
        split = command.split(' ')
        try:
            old = self.__rs.options.color
            generator = split[0]
            options = {}
            if len(split) > 1:
                for option in split[1:]:
                    if option.count('=') == 0 or option.count('=') > 1:
                        raise RopperError('Wrong option format. An option has to be set in the following format: option=value')
                    key, value = option.split('=')
                    options[key] = value
            try:

                self.__rs.options.color = False
                chain = self.__rs.createRopChain(generator, str(self.currentFile.arch) ,options)

                #generator = RopChain.get(self.__binaries, self.__gadgets, split[0], self.__ropchainInfoCallback, unhexlify(self.__options.badbytes))

                self.__printInfo('generating rop chain')
                # self.__printSeparator(behind='\n\n')

                self.__cprinter.println(chain)
                # self.__printSeparator(before='\n\n')
                self.__printInfo('rop chain generated!')
            except RopperError as e:
                self.__rs.options.color = old
                self.__printError(e)
        except BaseException as e:
            self.__rs.options.color = old
            print( traceback.format_exc())

            raise e
        self.__rs.options.color = old

    def __ropchainInfoCallback(self, message):
        if message.startswith('[*]'):
            self.__cprinter.puts('\r' + message)
        self.__cprinter.printInfo(message)

    def __setarch(self, arch):
        if self.currentFile:
            self.__rs.setArchitectureFor(self.currentFileName, arch)
            self.__updatePrompt()
        else:
            self.__printError('No file loaded')

    def __printStrings(self, string, sec=None):
        strings = self.__rs.searchString(
            string=string, name=self.currentFileName)
        strings = [s for s in strings.values()][0]
        strings = [(cstr(toHex(addr), Color.RED), cstr(s))
                   for addr, s in strings]
        printTable('Strings', (cstr('Address'), cstr('Value')), strings)

    def __disassembleAddress(self, addr, length):
        ds = self.__rs.disassAddress(self.currentFileName, addr, length)
        if len(ds.split('\n')) < length:
            self.__cprinter.printInfo(
                'Cannot disassemble specified count of instructions')
        self.__getDataPrinter(
            self.currentFile.type).printTableHeader('Instructions')
        self.__cprinter.println(ds)

    def __printSectionInHex(self, section):
        section = self.currentFile.loader.getSection(section)
        if section.bytes:
            printHexFormat(section.bytes, section.virtualAddress,
                       not self.__rs.options.color)
        else:
            self.__printInfo('No bytes to print')

    @safe_cmd
    def __handleOptions(self, options):
        if options.sections:
            self.__printData('sections')
        elif options.analyse:
            self.__loadGadgets()
            #self.do_analyse(options.analyse)
        elif options.semantic:
            self.__loadGadgets()
            self.do_semantic(options.semantic)
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
        elif options.asm is not None:
            format = 'H'
            if options.file is not None:
                with open(options.file[0]) as f:
                    code = f.read()
                if len(options.asm) > 0:
                    format = options.asm[0]
            else:
                code = options.asm[0]
                if len(options.asm) == 2:
                    code = options.asm[0]
                    format = options.asm[1]
            arch = 'x86'
            if options.arch:
                arch = options.arch
            self.__asm(code, arch, format)
        elif options.disasm:
            code = options.disasm
            arch = 'x86'
            if options.arch:
                arch = options.arch
            self.__disasm(code, arch)
        elif options.set:
            self.__set(options.set, True)
        elif options.unset:
            self.__set(options.unset, False)
        elif options.info:
            self.__printData('information')
        elif options.ppr:
            self.__searchPopPopRet()
        elif options.jmp:
            self.__searchJmpReg(options.jmp)
        elif options.stack_pivot:
            self.__loadGadgets()
            self.__printGadgets(self.currentFile.gadgets, Category.STACK_PIVOT)
        elif options.opcode:
            self.__searchOpcode(self.__options.opcode)
        elif options.instructions:
            self.__searchInstructions(self.__options.instructions)
        elif options.string:
            self.__printStrings(options.string, options.section)
        elif options.hex and options.section:
            self.__printSectionInHex(options.section)
        elif options.disassemble_address:
            split = options.disassemble_address.split(':')
            length = 1
            if not isHex(split[0]):
                raise RopperError('Number have to be in hex format 0x....')

            if len(split) > 1:
                if split[1][1:].isdigit() or (len(split[1]) >= 3 and split[1][1] == '-' and split[1][2:].isdigit()):  # is L\d or L-\d
                    length = int(split[1][1:])
                else:
                    raise RopperError(
                        'Length have to be in the following format L + Number e.g. L3')
            self.__disassembleAddress(int(split[0], 16), length)
        # elif options.checksec:
         #   self.__checksec()
        elif options.chain:
            self.__loadGadgetsForAllFiles()
            self.__generateChain(options.chain)
        elif self.__options.file:
            self.__loadGadgets()
            if options.search:
                self.__search(options.search, options.quality)
            else:
                self.__printGadgetsFromCurrentFile()


####### cmd commands ######
    @safe_cmd
    def do_show(self, text):
        if len(text) == 0:
            self.help_show()
            return

        self.__printData(text)

    def help_show(self):
        desc = 'shows informations about the loaded file'
        if self.__getDataPrinter(self.currentFile.type):
            desc += ('Available informations:\n' +
                     ('\n'.join(self.__getDataPrinter(self.currentFile.type).availableInformations)))
        self.__printHelpText(
            'show <info>', desc)

    def complete_show(self, text, line, begidx, endidx):
        if self.__getDataPrinter(self.currentFile.type):
            return [i for i in self.__getDataPrinter(self.currentFile.type).availableInformations if i.startswith(
                    text)]

    @safe_cmd
    def do_close(self, text):

        if text.isdigit():
            idx = int(text)
            if len(self.__rs.files) > idx - 1:
                self.__rs.removeFile(self.__rs.files[idx - 1].loader.fileName)
                if len(self.__rs.files) != 0:
                    self.__currentFileName = self.__rs.files[0].loader.fileName
                else:
                    self.__currentFileName = None
                self.__updatePrompt()
            else:
                self.__cprinter.printError('Index is too small or to large')
        elif text == 'all':
            for file in self.__rs.files:
                self.__rs.removeFile(file.loader.fileName)
            self.__currentFileName = None
            self.__updatePrompt()
        else:
            self.help_close()

    def help_close(self):
        self.__printHelpText(
            'close idx/all', 'closes opened files\nidx - index of file which should be closed\nall - closes all files')

    @safe_cmd
    def do_file(self, text):
        if len(text) == 0:
            data = []
            for index, binary in enumerate(self.__rs.files):
                if self.currentFileName == binary.loader.fileName:
                    data.append(
                        (cstr(index + 1), cstr(binary.loader.fileName + '*'), cstr(binary.arch),cstr(binary.loaded)))
                else:
                    data.append(
                        (cstr(index + 1), cstr(binary.loader.fileName), cstr(binary.arch),cstr(binary.loaded)))

            printTable('Opened Files', (cstr('No.'),
                                        cstr('Name'), cstr('Architecture'),cstr('Loaded')), data)

        elif text.isdigit():
            idx = int(text) - 1
            if idx >= len(self.__rs.files):
                raise RopperError('Index is too small or to large')
            self.__currentFileName = self.__rs.files[idx].loader.fileName
            self.__updatePrompt()
            self.__printInfo('File \'%s\' selected.' % self.currentFileName)
        else:
            self.__loadFile(text)
            self.__printInfo('File loaded.')

    def complete_file(self, text, line, begidx, endidx):
        file = text
        cwd = '.'
        path = ''
        if '/' in file:
            cwd = file[:file.rindex('/') + 1]
            file = file[file.rindex('/') + 1:]
            path = cwd

        return [path + i for i in os.listdir(cwd) if i.startswith(file)]

    def help_file(self):
        self.__printHelpText(
            'file [<file>|<idx>]', '\nno argument shows all opened files\n<file> - loads the file <file>\n<idx> - select the file with number <idx>')

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

        if not self.currentFile.loaded:
            self.__printInfo('Gadgets have to be loaded with load')
            return

        self.__printGadgets(self.currentFile.gadgets, detailed=self.__rs.options.detailed)

    def help_gadgets(self):
        self.__printHelpText('gadgets', 'shows all loaded gadgets')

    @safe_cmd
    def do_load(self, text):
        if text == 'all':
            self.__loadAllGadgets()
        else:
            self.__loadGadgets()
            self.__printInfo('gadgets loaded.')

    def help_load(self):
        self.__printHelpText(
            'load [all]', '\nall - loads gadgets of all opened files\nwithout argument loads gadgets of current file')

    @safe_cmd
    def do_ppr(self, text):
        self.__searchPopPopRet()

    def help_ppr(self):
        self.__printHelpText('ppr', 'shows all pop,pop,ret instructions')

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
        self.__search(text, qual)

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
        desc += 'search mov [%], edx\n\n'
        desc += '0x000067ed: mov dword ptr [esp + 4], edx; mov edx, dword ptr [ebp + 0x14]; mov dword ptr [esp], edx; call eax;\n'
        desc += '0x00006f4e: mov dword ptr [ecx + 0x14], edx; add esp, 0x2c; pop ebx; pop esi; pop edi; pop ebp; ret ;\n'
        desc += '0x000084b8: mov dword ptr [eax], edx; ret ;\n'
        desc += '0x00008d9b: mov dword ptr [eax], edx; add esp, 0x18; pop ebx; ret ;\n\n\n'
        desc += 'search /1/ mov [%], edx\n\n'
        desc += '0x000084b8: mov dword ptr [eax], edx; ret ;\n'

        self.__printHelpText('search [/<quality>/] <string>', desc)

    @safe_cmd
    def do_inst(self, text):
        if len(text) == 0:
            self.help_inst()
            return

        self.__searchInstructions(text)

    def help_inst(self):
        self.__printHelpText(
            'inst <instructions>', 'searchs instructions in executable sections')

    @safe_cmd
    def do_opcode(self, text):
        if len(text) == 0:
            self.help_opcode()
            return

        self.__searchOpcode(text)

    def help_opcode(self):
        self.__printHelpText(
            'opcode <opcode>', 'searchs opcode in executable sections\nExample:\nopcode ffe4\nopcode ff4?\nopcode ff??\n\nNot allowed:\nopcode ff?4')

    @safe_cmd
    def do_imagebase(self, text):
        if len(text) == 0:
            self.__rs.setImageBaseFor(self.currentFileName, None)
            self.__printInfo('Imagebase reseted')
        elif isHex(text):
            self.__rs.setImageBaseFor(self.currentFileName, int(text, 16))
            self.__printInfo('Imagebase set to %s' % text)
        else:
            self.help_imagebase()

    def help_imagebase(self):
        self.__printHelpText(
            'imagebase [<base>]', 'sets a new imagebase. An empty imagebase sets the imagebase to the original value.')

    @safe_cmd
    def do_type(self, text):
        if len(text) == 0:
            self.help_type()
            return

        self.do_settings('type %s' % text)

    def help_type(self):
        self.__printHelpText(
            'type <type>', 'sets the gadget type (rop, jop, sys, all, default:all)')

    @safe_cmd
    def do_jmp(self, text):
        if len(text) == 0:
            self.help_jmp()
            return

        self.__searchJmpReg(text)

    def help_jmp(self):
        self.__printHelpText(
            'jmp <reg[,reg...]>', 'searchs jmp reg instructions')

    @safe_cmd
    def do_detailed(self, text):
        self.do_settings('detailed %s' % text)

    def help_detailed(self):
        self.__printHelpText(
            'detailed [on|off]', 'sets detailed gadget output')

    def complete_detailed(self, text, line, begidx, endidx):
        return [i for i in ['on', 'off'] if i.startswith(text)]

    @safe_cmd
    def do_settings(self, text):
        if len(text):
            try:
                splits = text.strip().split(' ')
                if len(splits) == 1:
                    if splits[0] == 'color':
                        self.__rs.options[splits[0]] = True
                    else:
                        self.__rs.options[splits[0]] = None
                elif len(splits) == 2:
                    if splits[1] in ['on', 'off']:
                        self.__rs.options[splits[0]] = True if splits[1] == 'on' else False
                    elif splits[0] in ('inst_count', 'count_of_findings'):
                        self.__rs.options[splits[0]] = int(splits[1])
                    else:
                        self.__rs.options[splits[0]] = splits[1]

                else:
                    raise RopperError('Invalid setting')
            except TypeError as e:
                raise RopperError(e)
            except AttributeError as e:
                raise RopperError(e)
        else:
            data = []
            desc = {'cfg_only':'if on gadgets are filtered for use in CFG exploits (only PE)',
                    'all':'If on shows all found gadgets including double gadgets',
                    'color':'If on output is colored',
                    'badbytes':'Gadget addresses are not allowed to contain this bytes',
                    'type':'The file is scanned for this type of gadgets. (rop, jop, sys, all)',
                    'detailed':'If on the gadgets will be printed with more detailed information',
                    'inst_count':'The max count of instructions in a gadgets',
                    'count_of_findings':'The max count of findings which will be printed with semantic search (0 = undefined, default: 5'}
            for key, value in self.__rs.options.items():
                if isinstance(value, bool):
                    data.append((cstr(key), cstr('on' if value else 'off'), cstr(desc.get(key,''))))
                else:
                    data.append((cstr(key), cstr(value), cstr(desc[key])))

            printTable('Settings', (cstr('Name'), cstr('Value'), cstr('Description')), data)

    def help_settings(self):
        self.__printHelpText('settings', 'shows the current settings or set the settings\nHow to set:\nsettings badbytes 00 - sets badbytes to 00\nsettings badbytes - sets badbytes to default (empty)')

    @safe_cmd
    def do_badbytes(self, text):
        if len(text) == 0:
            self.__printInfo('badbytes cleared')

        self.do_settings('badbytes %s' % text)

        # for binary in self.__binaries:
        #     if binary.loaded:
        #         self.__gadgets[binary] = ropper.filterBadBytes(binary.gadgets, self.__options.badbytes)

        #         if not self.__options.all:
        #             self.__gadgets[binary] = ropper.deleteDuplicates(self.__gadgets[binary])

        self.__cprinter.printInfo('Filter gadgets')

    def help_badbytes(self):
        self.__printHelpText(
            'badbytes [bytes]', 'sets/clears bad bytes\n\n Example:\nbadbytes 000a0d  -- sets 0x00, 0x0a and 0x0d as badbytes')

    @safe_cmd
    def do_color(self, text):
        if self.__options.isWindows():
            self.__printInfo('No color support for windows')
            return
        self.do_settings('color %s' % text)

    def help_color(self):
        self.__printHelpText('color [on|off]', 'sets colorized output')

    def complete_color(self, text, line, begidx, endidx):
        return [i for i in ['on', 'off'] if i.startswith(text)]

    @safe_cmd
    def do_ropchain(self, text):
        if len(text) == 0:
            self.help_ropchain()
            return
        if not self.currentFile.loaded:
            self.do_load(text)

        gadgets = []
        for binary in self.__rs.files:
            gadgets.append(binary.gadgets)
        self.__generateChain(text)

    def help_ropchain(self):
        self.__printHelpText('ropchain <generator>[ argname=arg[ argname=arg...]]',
                             'uses the given generator and create a ropchain with args\n\nAvailable generators:\nexecve\nargs: cmd (optional)\navailable: x86, x86_64\nOS: linux\n\nmprotect\nargs: address, size\navailable: x86, x86_64\nOS: linux\n\nvirtualprotect\nargs: address (IAT)(optional)\navailable: x86\nOS: Windows\n\nExamples:\nropchain execve\nropchain mprotect address=0xbfff0000 size=0x21000')

    def do_quit(self, text):
        exit(0)

    def help_quit(self):
        self.__printHelpText('quit', 'quits the application')

    @safe_cmd
    def do_arch(self, text):
        if not text:
            self.help_arch()
            return
        self.__setarch(text)

    def help_arch(self):
        self.__printHelpText(
            'arch <arch>', 'sets the architecture <arch> for the loaded file')

    @safe_cmd
    def do_string(self, text):

        self.__printStrings(text)

    def help_string(self):
        self.__printHelpText(
            'string [<string>]', 'Looks for string <string> in section <section>. If no string is given all strings are printed.')

    @safe_cmd
    def do_hex(self, text):
        if not text:
            self.help_hex()
            return
        self.__printSectionInHex(text)

    def help_hex(self):
        self.__printHelpText(
            'hex <section>', 'Prints the section <section> in hex format')

    @safe_cmd
    def do_asm(self, text):
        if not text:
            self.help_asm()
            return

        text = text.strip()
        format = 'H'
        if text[-2:] in (' H', ' R', ' S'):
            format = text[-1:]
            text = text[:-2]

        arch = None
        if text.startswith('-a'):
            text = text[3:]
            index = text.index(' ')
            arch = text[:index]
            text = text[index:]
            arch = arch

        if not arch:
            if self.__currentFileName:
                arch = str(self.currentFile.arch)
            else:
                arch = 'x86'

        self.__asm(text, arch, format)

    def help_asm(self):
        self.__printHelpText('asm [-a <arch>] <code> [<format>]',
                             'assembles the given code. \n Format:\nR - Raw\nS - String\nH - Hex\nDefault: H')

    @safe_cmd
    def do_disasm(self, text):
        if not text:
            self.help_disasm()
            return
        arch = None
        if text.startswith('-a'):
            text = text[3:]
            index = text.index(' ')
            arch = text[:index]
            text = text[index:].strip()
            arch = getArchitecture(arch)
        if not arch:
            if self.__currentFileName:
                arch = str(self.currentFile.arch)
            else:
                arch = 'x86'

        self.__disasm(text, arch)

    def help_disasm(self):
        self.__printHelpText('disasm <bytes>', 'disassembles the given bytes.\nExample:\ndisasm ffe4')

    @safe_cmd
    def do_disasm_address(self, text):
        split = text.split(' ')
        length = 1
        if not isHex(split[0]):
            self.__cprinter.printError(
                'Number have to be in hex format 0x....')
            return
        if len(split) > 1:
            if split[1][1:].isdigit() or (len(split[1]) >= 3 and split[1][1] == '-' and split[1][2:].isdigit()):  # is L\d or L-\d
                length = int(split[1][1:])
            else:
                self.__cprinter.printError(
                    'Length have to be in the following format L + Number e.g. L3')
                return

        addr = int(split[0], 16)
        self.__disassembleAddress(addr, length)

    def help_disasm_address(self):
        self.__printHelpText(
            'disassembleAddress <address> [<length>]', 'Disassembles instruction at address <address>. The count of instructions to disassemble can be specified (0x....:L...)\nExample:\ndisasm_address 0x8048cd8\ndisasm_address 0x8048cd8 L2\ndisasm_address 0x8048cd8 L-2')

    @safe_cmd
    def do_stack_pivot(self, text):
        if self.currentFile.loaded:
            self.__printGadgets(self.currentFile.gadgets, Category.STACK_PIVOT)
        else:
            self.__printInfo('No gadgets loaded. Please load gadgets with \'load\'')

    def help_stack_pivot(self):
        self.__printHelpText('stack_pivot','Prints all stack pivot gadgets')

    def do_EOF(self, text):
        self.__cprinter.println('')
        self.do_quit(text)

    @safe_cmd
    def do_clearcache(self, text):
        self.__rs.clearCache()

    def help_clearcache(self):
        self.__printHelpText('clearcache','Clears the cache')

    @safe_cmd
    def do_semantic(self, text):
        if not text:
            self.help_semantic()
            return
        if not self.currentFile.analysed:
            self.__rs.analyseGadgets(self.currentFile)
        constraint = None
        constraints = text.split(';')

        split = constraints[-1].split(' ')
        stableRegs = []
        for s in split:
            if s.startswith('!'):
                stableRegs.append(s[1:])
            else:
                constraint = s.strip()
        constraints[-1] = constraint
        for c in range(len(constraints)):
            constraints[c] = constraints[c].strip()

        self.__printInfo('Searching for gadgets: ' + text)
        old = None
        found = False
        analysedCount = None
        count = 0
        for fc, gadget in self.__rs.semanticSearch(constraints, stableRegs=stableRegs):
            if fc != old:
                old = fc
                self.__cprinter.println()
                self.__printInfo('File: %s' % fc)
            found = True
            self.__printGadget(gadget, self.__options.detailed)
            count += 1

        self.__cprinter.printInfo('%d gadgets found' % count)

        self.__cprinter.println()

    def help_semantic(self):
        self.__printHelpText('semantic', 'Searchs gadgets\nsemantic <constraint>[; <constraint>][ !<stable reg>*]\n\nExample:\nsemantc eax==ebx; ecx==1 !edx !esi\n\nValid constraints:\nreg==reg\nreg==number\nreg==[reg]\nreg<+|-|*|/>=<reg|number|[reg]>')

    # @safe_cmd
    # def do_analyse(self, text):
    #     import z3
    #     from ropper.slicing import Slicer
    #     slicer = Slicer()
    #     if text and isHex(text):
    #         addr = int(text, 16)
    #         for g in self.currentFile.gadgets:
    #             if g.address == addr:
    #                 print(bytes(g.bytes).encode('hex'))
    #                 print(g.info.regs)
    #                 g.info.irsb.pp()
    #                 print(g.info.expressions)
    #                 set_reg = self.currentFile.arch.searcher.extractValues(["rsp=rbx"], g.info)[0][0]
    #                # print(self.currentFile.arch.searcher._createConstraint("eax=1",g.info))
    #                 slice = slicer.slicing(g.info.irsb, set_reg)
    #                 print(slice.instructions)
    #                 solver = z3.Solver()
    #                 expr_len = len(g.info.expressions)
    #                 for inst in slice.instructions[::-1]:
    #                     expr = g.info.expressions[expr_len-inst]
    #                     if expr == False:
    #                         continue
    #                     solver.add(expr)


    #                 c = None
    #                 c2 = None
    #                 constraint = self.currentFile.arch.searcher._createConstraint(["rsp=rbx"], g.info)
    #                 print(constraint)
    #                 if constraint is not None:
    #                     solver.add(constraint)

    #                 print(solver.assertions())
    #                 print(solver.check())
    #                 print(g.info.clobberedRegs)
    #                 print(g.simpleString())

    #     else:
    #         self.__printInfo('No such gadget')



    # @safe_cmd
    # def do_edit(self, text):
    #     cmd = None
    #     if self.binary.type == Type.ELF:
    #         cmd = ELFConsole(self.binary, self.__cprinter)
    #     elif self.binary.type == Type.PE:
    #         cmd = PEConsole(self.binary, self.__cprinter)
    #     elif self.binary.type == Type.MACH_O:
    #         cmd = MachOConsole(self.binary, self.__cprinter)
    #     else:
    #         self.printError(
    #             'This type is currently not supported: %s' % self.binary.type)
    #         return
    #     if cmd:
    #         cmd.cmdloop()

    # def help_edit(self):
    #     self.__printHelpText('edit', 'edits a file ***experimental***')


class ConsolePrinter(object):

    def __init__(self, out=stdout, err=stderr):
        super(ConsolePrinter, self).__init__()
        self._out = out
        self._err = err

    def putsErr(self, *args):
        for i, arg in enumerate(args):
            self._err.write(str(arg))
            if i != len(args) - 1:
                self._err.write(' ')
        self._err.flush()

    def puts(self, *args):

        for i, arg in enumerate(args):
            self._out.write(str(arg))
            if i != len(args) - 1:
                self._out.write(' ')
        self._out.flush()

    def println(self, *args):

        self.puts(*args)
        self._out.write('\n')

    def printlnErr(self, *args):

        self.putsErr(*args)
        self._err.write('\n')

    def printHelpText(self, cmd, desc):
        self.println('{}  -  {}\n'.format(cmd, desc))

    def printMessage(self, mtype, message):
        self.printlnErr(mtype, message)

    def printError(self, message):
        self.printMessage(cstr('[ERROR]', Color.RED), message)

    def printInfo(self, message):
        self.printMessage(cstr('[INFO]', Color.GREEN), message)

    def startProgress(self, message=None):
        if message:
            self.printInfo(message)

    def printProgress(self, message, progress):
        self.putsErr(cstr('\r') + cstr('[LOAD]', Color.GREEN),
                     message, cstr(int(progress * 100)) + cstr('%'))

    def finishProgress(self, message=None):
        self.printlnErr('')
        if message:
            self.printInfo(message)


class EditConsoleMixin(object):

    def __init__(self, binary, printer):
        cmd.Cmd.__init__(self)
        self._binary = binary
        self._printer = printer
        self.prompt = cstr('(edit:%s) ' % str(binary.type).lower(), Color.RED)
        self.intro = cstr('***EXPERIMENTAL***')

    @property
    def binary(self):
        return self._binary

    @property
    def printer(self):
        return self._printer

    @safe_cmd
    def do_save(self, text):
        self.binary.save()

    def help_save(self):
        self.printer.printHelpText(
            'save', 'Saves the changes in the opened file.')

    def do_exit(self, text):
        self.printer.println()
        return True

    do_EOF = do_exit


class ELFConsole(EditConsoleMixin, cmd.Cmd):

    def __init__(self, binary, printer):
        EditConsoleMixin.__init__(self, binary, printer)
        cmd.Cmd.__init__(self)

    @safe_cmd
    def do_ehdr(self, text):
        if not text:
            ehdr = self._binary.ehdr

            self._printer.println('ehdr')

            for field in ehdr._fields_:
                self._printer.println(
                    '    %s' % field[0], '=', (bytes(ehdr.__getattribute__(field[0]))))

    @safe_cmd
    def do_phdr(self, text):
        if not text:
            phdrs = self._binary.phdrs

            for i in range(len(phdrs)):
                self._printer.println('phdr [%d]' % i)
                phdr = phdrs[i].struct
                for field in phdr._fields_:
                    self._printer.println('    %s' % field[0], '=', hex(
                        phdr.__getattribute__(field[0]))[:-1])

    @safe_cmd
    def do_shdr(self, text):
        shdrs = self._binary.shdrs
        if not text:

            for i in range(len(shdrs)):
                self._printer.println('shdr [%d]' % i)
                shdr = shdrs[i].struct
                for field in shdr._fields_:
                    self._printer.println('    %s' % field[0], '=', hex(
                        shdr.__getattribute__(field[0]))[:-1])
        else:
            if ' ' in text:
                number, field = text.split()
                number = int(number)
                if '=' in field:
                    shdr = shdrs[number].struct
                    field, value = field.split('=')
                    shdr.__setattr__(field, int(value))
            elif text.isdigit():
                index = int(text)
                self.printer.println('shdr [%d]' % index)
                shdr = shdrs[index].struct
                for field in shdr._fields_:
                    self._printer.println('    %s' % field[0], '=', hex(
                        shdr.__getattribute__(field[0]))[:-1])


class PEConsole(EditConsoleMixin, cmd.Cmd):

    def __init__(self, binary, printer):
        EditConsoleMixin.__init__(self, binary, printer)
        cmd.Cmd.__init__(self)


class MachOConsole(EditConsoleMixin, cmd.Cmd):

    def __init__(self, binary, printer):
        EditConsoleMixin.__init__(self, binary, printer)
        cmd.Cmd.__init__(self)
