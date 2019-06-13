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
from filebytes.pe import ImageDirectoryEntry
from ropper.common.utils import isWindows, isHex, toHex, getFileNameFromPath
from ropper.common.coloredstring import cstr, Color
from ropper.common.error import RopperError
from ropper.loaders.loader import Loader, Type
from ropper.ropchain.ropchain import RopChain
from ropper.arch import getArchitecture
from ropper.rop import Ropper, Format
from ropper.gadget import Gadget, GadgetType
from binascii import unhexlify
from codecs import encode, decode
from ropper.semantic import Analyser, SemanticInformation
import tempfile
import re
import os
import multiprocessing
import sys

def deleteDuplicates(gadgets, callback=None):
    toReturn = []
    inst = set()
    count = 0
    added = False
    len_gadgets = len(gadgets)
    for i,gadget in enumerate(gadgets):
        inst.add(gadget._gadget)
        if len(inst) > count:
            count = len(inst)
            toReturn.append(gadget)
            added = True
        if callback:
            callback(gadget, added, float(i+1)/(len_gadgets))
            added = False
    return toReturn


def filterBadBytes(gadgets, badbytes, callback=None):

    def formatBadBytes(badbytes):
        if len(badbytes) % 2 > 0:
            raise RopperError('The length of badbytes has to be a multiple of two')

        try:
            badbytes = unhexlify(badbytes)
        except:
            raise RopperError('Invalid characters in badbytes string')
        return badbytes

    if not badbytes:
        return gadgets
    added = False
    badbytes = formatBadBytes(badbytes)
    if isinstance(gadgets, dict):
        toReturn = {}

        gadget_count = 0
        for file, gadget in gadgets.items():
            gadget_count += len(gadget)
        for file, gadget in gadgets.items():
            t = []
            for i,g in enumerate(gadget):
                if not badbytes or not g.addressesContainsBytes(badbytes):
                    t.append(g)
                    added = True
                if callback:
                    callback(gadget, added, float(i)/(gadget_count-1))
                    added = False
            toReturn[file] = t
    elif isinstance(gadgets, list):
        toReturn = []
        for i, gadget in enumerate(gadgets):
            if not badbytes or not gadget.addressesContainsBytes(badbytes):
                toReturn.append(gadget)
                added = True
            if callback:
                callback(gadget, added, float(i)/(len(gadgets)-1))
                added = False

    return toReturn


def cfgFilterGadgets(binary, gadgets, callback=None):

    def intern(gadgets, callback=None,current=0, length=0):
        result = []
        added = False
        for gadget in gadgets:
            loadConfig = binary._binary.dataDirectory[ImageDirectoryEntry.LOAD_CONFIG]
            if not loadConfig:
                return gadgets

            # calculate relative address of the gadget when loaded to memory
            gadgetRVA = gadget.address - binary.imageBase

            # consider Microsoft CFG implementation imprecision - chop off 3 lsbits
            gadgetRVA8ByteAligend = gadgetRVA - (gadgetRVA % 8)

            inList = gadgetRVA8ByteAligend in loadConfig.cfGuardedFunctions

            if inList:
                # this is a gadget which passes CFG checks
                result.append(gadget)
                added = True

            if callback:
                # occasional progress reporting
                callback(gadget, added, float(current)/gadgetLen)
                added = False
            current += 1
        return result

    if isinstance(gadgets,  list):
        gadgetLen = len(gadgets)-1
        return intern(gadgets, callback, length=gadgetLen)
    elif isinstance(gadgets, dict):
        result = {}
        i = 0
        glen = 0
        for file, glist in gadgets.items():
            glen += len(glist)-1
        for file, glist in gadgets.items():
            result[file] = intern(glist, callback, i, glen)
            i += len(result[file])

        return result


class Options(object):

    def __init__(self, options={}, option_changed=None):
        super(Options, self).__init__()
        self.__checkOptions(options)
        self.__options_dict = options
        self.__option_changed = option_changed

    def __checkOptions(self, options):
        if not isinstance(options, dict):
            raise TypeError('options has to be an instance of dict')

        inst_count = options.get('inst_count')
        if inst_count and not isinstance(inst_count, (int)):
            raise TypeError('inst_count has to be an instance of int')
        elif not inst_count:
            options['inst_count'] = 6
        elif inst_count < 1:
            raise AttributeError('inst_count has to be bigger than 0')

        color = options.get('color')
        if color != None and not isinstance(color, bool):
            raise TypeError('color has to be an instance of bool')
        elif color == None:
            options['color'] = False

        badbytes = options.get('badbytes')
        if badbytes and not isinstance(badbytes, str):
            raise TypeError('badbytes has to be an instance of str')
        elif badbytes and len(badbytes) % 2 == 1:
            raise AttributeError('length of badbytes has to be even')
        elif badbytes and not isHex('0x'+badbytes):
            raise AttributeError('badbytes has to consist of 0-9 a-f A-F')
        elif not badbytes:
            options['badbytes'] = ''

        all = options.get('all')
        if all != None and not isinstance(all, bool):
            raise TypeError('all has to be an instance of bool')
        elif all == None:
            options['all'] = False

        gtype = options.get('type')
        if gtype and not isinstance(gtype, str):
            raise TypeError('type has to be an instance of str')
        elif gtype and gtype not in ['rop', 'jop', 'sys', 'all']:
            raise AttributeError('type has to be a "rop", "jop", "sys" or "all"')
        elif not gtype:
            options['type'] = 'all'

        detailed = options.get('detailed')
        if detailed != None and not isinstance(detailed, bool):
            raise TypeError('detailed has to be an instance of bool')
        elif detailed == None:
            options['detailed'] = False

        cfg_only = options.get('cfg_only')
        if cfg_only != None and not isinstance(cfg_only, bool):
            raise TypeError('cfg_only has to be an instance of bool')
        elif cfg_only == None:
            options['cfg_only'] = False

        count_of_findings = options.get('count_of_findings')
        if count_of_findings != None and not isinstance(count_of_findings, int):
            raise TypeError('cfg_only has to be an instance of bool')
        elif count_of_findings == None:
            options['count_of_findings'] = 5

    def items(self):
        for key, value in self.__options_dict.items():
            yield key, value

    def __getattr__(self, key):
        if key.startswith('_'):
            return super(Options, self).__getattr__(key)
        else:
            return self.__options_dict[key]

    def __setattr__(self, key, value):
        if key.startswith('_'):
            super(Options, self).__setattr__(key, value)
        else:
            old = self.__options_dict[key]
            self.__checkOptions({key:value})
            self.__options_dict[key] = value
            self.__checkOptions(self.__options_dict)
            if self.__option_changed:
                self.__option_changed(key, old, value)

    def __setitem__(self, key, value):
        self.__setattr__(key, value)

    def __getitem__(self, key):
        return self.__getattr__(key)


class RopperService(object):

    ROPPER_FOLDER = os.path.expanduser('~') + os.path.sep + ".ropper/"
    CACHE_FOLDER = os.path.expanduser('~') + os.path.sep + ".ropper/cache/"
    CACHE_FILE_COUNT = 16

    def __init__(self, options={}, callbacks=None):
        super(RopperService, self).__init__()
        self.__options = Options(options, self.__optionChanged)
        if callbacks and hasattr(callbacks, '__gadgetSearchProgress__'):
            self.__ropper = Ropper(callback=callbacks.__gadgetSearchProgress__)
        else:
            self.__ropper = Ropper()
        self.__files = []
        self.__callbacks = callbacks
        if self.__options.color:
            cstr.COLOR = self.__options.color
        Gadget.DETAILED = self.__options.detailed

    @property
    def ropper(self):
        return self.__ropper

    @property
    def options(self):
        return self.__options

    @property
    def files(self):
        return list(self.__files)

    def __optionChanged(self, option, oldvalue, newvalue):
        if hasattr(self, '_%s_changed' % option):
            func = getattr(self, '_%s_changed' % option)
            func(newvalue)

    def __prepareGadgets(self, file, gadgets, type=None):

        gadgets = self.__filterBadBytes(gadgets)
        gadgets = self.__filterCfg(file, gadgets, type)
        if not self.__options.all:
            callback = None
            if self.__callbacks and hasattr(self.__callbacks, '__deleteDoubleGadgetsProgress__'):
                callback = self.__callbacks.__deleteDoubleGadgetsProgress__
            gadgets = deleteDuplicates(gadgets, callback)
        return gadgets

    def __filterBadBytes(self, gadgets):
        if self.__options.badbytes:
            callback = None
            if self.__callbacks and hasattr(self.__callbacks, '__filterBadBytesGadgetsProgress__'):
                callback = self.__callbacks.__filterBadBytesGadgetsProgress__
            gadgets = filterBadBytes(gadgets, self.options.badbytes, callback)
        return gadgets

    def __filterCfg(self, file, gadgets, type):
        if self.__options.cfg_only and type==Type.PE:
            callback = None
            if self.__callbacks and hasattr(self.__callbacks, '__filterCfgGadgetsProgress__'):
                callback = self.__callbacks.__filterCfgGadgetsProgress__
            gadgets = cfgFilterGadgets(file.loader, gadgets, callback)
        return gadgets

    def __getCacheFileName(self, file):
        return "%s_%s_%d_%s_%d" % (file.loader.checksum, str(file.arch), self.options.inst_count,str(self.options.type), sys.version_info.major)

    def __saveCache(self, file):
        cache_file = None
        try:
            temp = RopperService.CACHE_FOLDER
            if not os.path.exists(temp):
                os.makedirs(temp)

            cache_file = temp + os.path.sep + self.__getCacheFileName(file)
            count = RopperService.CACHE_FILE_COUNT
            if not isWindows() and len(file.allGadgets) > 1000:
                if os.path.exists(cache_file):
                    os.remove(cache_file)

                length = len(file.allGadgets)

                step = int(length / count)
                for i in range(count-1):
                    gadgets = file.allGadgets[i*step: (i+1)*step]
                    with open(cache_file+'_%d' % (i+1),'wb') as f:
                        f.write(encode(repr(gadgets).encode('ascii'),'zip'))

                gadgets = file.allGadgets[(count-1)*step:]
                with open(cache_file+'_%d' % (count),'wb') as f:
                    f.write(encode(repr(gadgets).encode('ascii'),'zip'))
                return

            with open(cache_file,'wb') as f:
                f.write(encode(repr(file.allGadgets).encode('ascii'),'zip'))
        except BaseException as e:
            print(e)
            if cache_file:
                for i in range(1, RopperService.CACHE_FILE_COUNT+1):
                    if os.path.exists(cache_file+'_%d' % i):
                        os.remove(cache_file+'_%d' % i)


    def __loadCachePerProcess(self, fqueue, gqueue):
        nan=0
        while True:
            cacheFileName = fqueue.get()
            if cacheFileName is None:
                fqueue.task_done()
                break
            if os.path.exists(cacheFileName):
                with open(cacheFileName,'rb') as f:
                    data = f.read()
                    gqueue.put(eval(decode(data,'zip')))
            else:
                gqueue.put([])
            fqueue.task_done()


    def __loadCache(self, file):
        mp = False
        nan= 0
        processes = []
        single = False
        cache_file = None
        try:
            temp = RopperService.CACHE_FOLDER
            cache_file = temp + os.path.sep + self.__getCacheFileName(file)

            if not os.path.exists(cache_file):
                if not os.path.exists(cache_file+'_%d' % 1):
                    return
                else:
                    if isWindows():
                        raise RopperError('Cache has to be cleared.')
                    mp = True and multiprocessing.cpu_count()>1
            else:
                single = True
            if self.__callbacks and hasattr(self.__callbacks, '__message__'):
                self.__callbacks.__message__('Load gadgets from cache')
            if self.__callbacks and hasattr(self.__callbacks, '__gadgetSearchProgress__'):
                        self.__callbacks.__gadgetSearchProgress__(None, [], 0)
            if not mp:
                all_gadgets = []
                if single:
                    with open(cache_file,'rb') as f:
                        data = f.read()
                        all_gadgets.extend(eval(decode(data,'zip')))
                        if self.__callbacks and hasattr(self.__callbacks, '__gadgetSearchProgress__'):
                            self.__callbacks.__gadgetSearchProgress__(None, all_gadgets, 1.0)
                else:
                    for i in range(1,RopperService.CACHE_FILE_COUNT+1):
                        if os.path.exists(cache_file+'_%d' % i):
                            with open(cache_file+'_%d' % i,'rb') as f:
                                data = f.read()
                                all_gadgets.extend(eval(decode(data,'zip')))
                                if self.__callbacks and hasattr(self.__callbacks, '__gadgetSearchProgress__'):
                                    self.__callbacks.__gadgetSearchProgress__(None, all_gadgets, float(i)/RopperService.CACHE_FILE_COUNT)
                return all_gadgets

            else:
                count = min(multiprocessing.cpu_count(),RopperService.CACHE_FILE_COUNT)

                gqueue = multiprocessing.Queue()
                fqueue = multiprocessing.JoinableQueue()
                for i in range(1,RopperService.CACHE_FILE_COUNT+1):
                    fqueue.put(cache_file+'_%d' % i)
                all_gadgets = []
                for i in range(count):
                    p=multiprocessing.Process(target=self.__loadCachePerProcess, args=(fqueue, gqueue))
                    p.start()
                    processes.append(p)

                for i in range(count):
                    fqueue.put(None)

                for i in range(RopperService.CACHE_FILE_COUNT):
                    gadgets = gqueue.get()
                    all_gadgets.extend(gadgets)
                    if self.__callbacks and hasattr(self.__callbacks, '__gadgetSearchProgress__'):
                        self.__callbacks.__gadgetSearchProgress__(None, all_gadgets, float(i+1)/RopperService.CACHE_FILE_COUNT)

                return sorted(all_gadgets, key=Gadget.simpleInstructionString)
        except KeyboardInterrupt:
            if mp:
                for p in processes:
                    if p and p.is_alive():
                        p.terminate()
        except BaseException as e:
            if mp:
                for p in processes:
                    if p and p.is_alive():
                        p.terminate()
            if cache_file:
                for i in range(1,RopperService.CACHE_FILE_COUNT+1):
                    if os.path.exists(cache_file+'_%d' % i):
                        os.remove(cache_file+'_%d' % i)


    def _badbytes_changed(self, value):
        for f in self.__files:
            if f.loaded:
                f.gadgets = self.__prepareGadgets(f, f.allGadgets, f.type)

    def _all_changed(self, value):
        for f in self.__files:
            if f.loaded:
                f.gadgets = self.__prepareGadgets(f, f.allGadgets, f.type)

    def _color_changed(self, value):
        cstr.COLOR = value

    def _detailed_changed(self, value):
        Gadget.DETAILED = value

    def _cfg_only_changed(self, value):
        for f in self.__files:
            if f.loaded and f.type == Type.PE:
                f.gadgets = self.__prepareGadgets(f, f.allGadgets, f.type)

    def _type_changed(self, value):
        for f in self.__files:
            if f.loaded:
                self.loadGadgetsFor(f.name)

    def _inst_count_changed(self, value):
        for f in self.__files:
            if f.loaded:
                self.loadGadgetsFor(f.name)

    def _getFileFor(self, name):
        for file in self.__files:
            if file.loader.fileName == name:
                return file

        return None

    def clearCache(self):
        temp = RopperService.CACHE_FOLDER
        if os.path.exists(temp):
            import shutil
            shutil.rmtree(temp)


    def getFileFor(self, name):
        return self._getFileFor(name)

    def addFile(self, name, bytes=None, arch=None, raw=False):
        if self._getFileFor(name):
            raise RopperError('file is already added: %s' % name)

        if arch:
            arch=getArchitecture(arch)

        loader = Loader.open(name, bytes=bytes, raw=raw, arch=arch)
        file = FileContainer(loader)
        self.__files.append(file)

    def removeFile(self, name):
        for idx, fc in enumerate(self.__files):
            if fc.loader.fileName == name:
                del self.__files[idx]

    def asm(self, code, arch='x86', format='hex'):
        if format not in ('hex', 'string', 'raw'):
            raise RopperError('Invalid format: %s\n Valid formats are: hex, string, raw' % format)
        format = Format.HEX if format=='hex' else Format.STRING if format=='string' else Format.RAW
        return self.ropper.assemble(code, arch=getArchitecture(arch), format=format)

    def disasm(self, opcode, arch='x86'):
        return self.ropper.disassemble(opcode, arch=getArchitecture(arch))

    def searchPopPopRet(self, name=None):
        to_return = {}

        if not name:
            for file in self.__files:
                to_return[file.loader.fileName] = self.__ropper.searchPopPopRet(file.loader)
        else:
            fc = self._getFileFor(name)
            if not fc:
                raise RopperError('No such file opened: %s' % name)

            to_return[name] = self.__ropper.searchPopPopRet(fc.loader)

        return self.__filterBadBytes(to_return)

    def searchJmpReg(self, regs=['esp'],name=None):
        to_return = {}

        if not name:
            for file in self.__files:
                to_return[file.loader.fileName] = self.__ropper.searchJmpReg(file.loader, regs)
        else:
            fc = self._getFileFor(name)
            if not fc:
                raise RopperError('No such file opened: %s' % name)

            to_return[name] = self.__ropper.searchJmpReg(fc.loader, regs)

        return self.__filterBadBytes(to_return)

    def searchOpcode(self, opcode, name=None):
        to_return = {}

        if not name:
            for file in self.__files:
                to_return[file.loader.fileName] = self.__ropper.searchOpcode(file.loader, opcode)
        else:
            fc = self.getFileFor(name)
            if not fc:
                raise RopperError('No such file opened: %s' % name)

            to_return[name] = self.__ropper.searchOpcode(fc.loader, opcode)

        return self.__filterBadBytes(to_return)

    def searchInstructions(self, code, name=None):
        to_return = {}

        if not name:
            for file in self.__files:
                to_return[file.loader.fileName] = self.__ropper.searchInstructions(file.loader, code)
        else:
            fc = self.getFileFor(name)
            if not fc:
                raise RopperError('No such file opened: %s' % name)

            to_return[name] = self.__ropper.searchInstructions(fc.loader, code)

        return self.__filterBadBytes(to_return)

    def analyseGadgets(self, fileObject):
        gadgets = fileObject.gadgets
        analyser = Analyser()
        cb = None
        lg = len(gadgets)
        if self.__callbacks and hasattr(self.__callbacks, '__analyseGadgetsProgress__'):
            cb = self.__callbacks.__analyseGadgetsProgress__
        for i,g in enumerate(gadgets):
            g.info = analyser.analyse(g)
            if cb:
                cb(g, float(i)/lg)
        if cb:
             cb(None, 1.0)
        self.__saveCache(fileObject)
        fileObject.analysed = True

    def loadGadgetsFor(self, name=None):

        def load_gadgets(f):
            gtype = None
            cache = False
            Gadget.IMAGE_BASES[f.loader.checksum] = f.loader.imageBase
            if self.options.type == 'rop':
                gtype = GadgetType.ROP
            elif self.options.type == 'jop':
                gtype = GadgetType.JOP
            elif self.options.type == 'sys':
                gtype = GadgetType.SYS
            elif self.options.type == 'all':
                gtype = GadgetType.ALL
            f.allGadgets = self.__loadCache(f)
            if f.allGadgets == None:
                cache = True
                f.allGadgets = self.__ropper.searchGadgets(f.loader, instructionCount=self.options.inst_count, gtype=gtype)

            if cache:
                self.__saveCache(f)
            f.gadgets = self.__prepareGadgets(f, f.allGadgets, f.type)
            f.analysed = f.gadgets[0].info is not None if len(f.gadgets) > 0 else False
            #self._analyseGadgets(f.gadgets)


        if name is None:
            for fc in self.__files:
                load_gadgets(fc)
        else:
            for fc in self.__files:
                if fc.loader.fileName == name:
                    load_gadgets(fc)

    def printGadgetsFor(self, name=None):
        def print_gadgets(f):
            print(f.loader.fileName)
            for g in f.gadgets:
                if self.options.detailed:
                    print(g)
                else:
                    print(g.simpleString())

        if name is None:
            for f in self.__files:
                print_gadgets(f)
        else:
            for f in self.__files:
                if f.loader.fileName == name:
                    print_gadgets(f)

    def searchString(self, string='', name=None):

        def search(f, string):
            data = []
            if not string or string == '[ -~]{2}[ -~]*':
                string = '[ -~]{2}[ -~]*'
            else:
                string = f.arch.searcher.prepareFilter(string)
            sections = list(f.dataSections)
            string = string.encode('ascii') # python 3 compatibility
            for section in sections:
                b = bytes(bytearray(section.bytes))
                for match in re.finditer(string, b):
                    vaddr = f.imageBase + section.offset if f.imageBase != None else section.virtualAddress
                    data.append( (match.start() + vaddr , match.group()))
            return data

        to_return = {}
        if not name:
            for file in self.__files:
                to_return[file.loader.fileName] = search(file.loader, string)
        else:
            fc = self._getFileFor(name)
            if not fc:
                raise RopperError('No such file opened: %s' % name)
            to_return[name] = search(fc.loader, string)

        return to_return

    def search(self, search, quality=None, name=None):
        if name:
            fc = self._getFileFor(name)
            if not fc:
                raise RopperError('No such file opened: %s' % name)

            s = fc.loader.arch.searcher
            for gadget in s.search(fc.gadgets, search, quality):
                    yield(fc.name, gadget)
        else:
            for fc in self.__files:
                s = fc.loader.arch.searcher
                for gadget in s.search(fc.gadgets, search, quality):
                    yield(fc.name, gadget)

    def semanticSearch(self, search, stableRegs=[], name=None):
        count = 0
        if name:
            fc = self._getFileFor(name)
            if not fc:
                raise RopperError('No such file opened: %s' % name)

            s = fc.loader.arch.searcher
            for gadget in s.semanticSearch(fc.gadgets, search, self.options.inst_count, stableRegs):
                if self.options.count_of_findings == 0 or self.options.count_of_findings > count:
                    yield(fc.name, gadget)
                else:
                    break
                count += 1
            self.__saveCache(fc)
        else:
            for fc in self.__files:
                s = fc.loader.arch.searcher
                for gadget in s.semanticSearch(fc.gadgets, search, self.options.inst_count, stableRegs):
                    if self.options.count_of_findings == 0 or self.options.count_of_findings > count:
                        yield(fc.name, gadget)
                    else:
                        break
                    count += 1
                self.__saveCache(fc)

    def searchdict(self, search, quality=None, name=None):
        to_return = {}
        for file, gadget in self.search(search, quality, name):
            l = to_return.get(file)
            if not l:
                l = []
                to_return[file] = l
            l.append(gadget)
        return to_return

    def disassAddress(self, name, address, length):
        fc = self.getFileFor(name)
        if not fc:
            raise RopperError('No such file opened: %s' % name)
        eSections = fc.loader.executableSections

        for section in  eSections:
            if section.virtualAddress <= address and section.virtualAddress + section.size > address:
                ropper = Ropper()


                g = ropper.disassembleAddress(section, fc.loader, address, address - (fc.loader.imageBase+section.offset), length)
                if not g:
                    raise RopperError('Cannot disassemble address: %s' % toHex(address))

                if length < 0:
                    length = length * -1
                return g.disassemblyString()
        return ''

    def createRopChain(self, chain, arch, options={}):
        callback = None
        if self.__callbacks and hasattr(self.__callbacks, '__ropchainMessages__'):
            callback = self.__callbacks.__ropchainMessages__

        b = []
        gadgets = {}
        for binary in self.__files:
            if str(binary.arch) == arch:
                gadgets[binary.loader] = binary.gadgets
                b.append(binary.loader)
        generator = RopChain.get(b, gadgets, chain, callback, unhexlify(self.options.badbytes))

        if not generator:
            raise RopperError('%s does not have support for %s chain generation at the moment. Its a future feature.' % (self.files[0].loader.arch.__class__.__name__, chain))

        return generator.create(options)

    def setImageBaseFor(self, name, imagebase):
        file = self._getFileFor(name)
        if not file:
            raise RopperError('No such file opened: %s' % name)
        file.loader.imageBase = imagebase
        Gadget.IMAGE_BASES[file.loader.checksum] = file.loader.imageBase
        if file.loaded and (self.options.badbytes or self.options.cfg_only and file.type == Type.PE):
            file.gadgets = self.__prepareGadgets(file, file.allGadgets, file.type)

    def setArchitectureFor(self, name, arch):
        file = self.getFileFor(name)
        if not file:
            raise RopperError('No such file opened: %s' % name)
        file.loader.arch = getArchitecture(arch)
        if file.loaded:
            self.loadGadgetsFor(name)

    def _setGadgets(self, name, gadgets):
        fc = self.getFileFor(name)
        if not fc:
            raise RopperError('No such file opened: %s' % name)
        fc.allGadgets = gadgets
        fc.gadgets = self.__prepareGadgets(fc, fc.allGadgets, fc.type)



class FileContainer(object):

    def __init__(self, loader):
        super(FileContainer, self).__init__()

        self.__loader = loader
        self.__all_gadgets = None
        self.__gadgets = None
        self.__loaded = False

    @property
    def name(self):
        return self.loader.fileName

    @property
    def arch(self):
        return self.loader.arch

    @property
    def type(self):
        return self.loader.type

    @property
    def loaded(self):
        return self.__loaded

    @property
    def loader(self):
        return self.__loader

    @property
    def gadgets(self):
        return self.__gadgets

    @gadgets.setter
    def gadgets(self, gadgets):
        self.__gadgets = gadgets

    @property
    def allGadgets(self):
        return self.__all_gadgets

    @allGadgets.setter
    def allGadgets(self, gadgets):
        self.__loaded = True if gadgets is not None else False
        self.__all_gadgets = gadgets
