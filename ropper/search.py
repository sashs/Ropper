# coding=utf-8
#
# Copyright 2016 Sascha Schirra
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
import re
try: 
    import z3
except:
    pass
from ropper.common.error import RopperError
from ropper.common.utils import isHex
from ropper.gadget import Category
import time
import sys


class Searcher(object):

    CONSTRAINT_REGEX = '(\[?[a-zA-Z0-9]+\]?)([\+\*\-/])?=(\[?[a-zA-Z0-9]+\]?)$'

    def prepareFilter(self, filter):
        filter = filter.replace('\\','\\\\')
        filter = filter.replace('(','\\(')
        filter = filter.replace(')','\\(')
        filter = filter.replace('[','\\[')
        filter = filter.replace(']','\\]')
        filter = filter.replace('+','\\+')
        filter = filter.replace('.',r'\.')
        filter = filter.replace('*',r'\*')
        filter = filter.replace('?','[ -~]')
        filter = filter.replace('%', '[ -~]*')
        return filter

    def __getRealRegName(self, reg, arch):
        info = arch.registers.get(reg)
        if not info:
            return reg
        return arch.translate_register_name(info[0], info[1]*8)


    def _create(self, adjust, left, right, right2=None):
        if adjust is not None:
            return '%s == %s %s %s' % (left, right, adjust, right2)
        else:
            return '%s == %s' % (left, right)

    def _createConstraint(self, constraints, analysis):
        # TODO complex constraints have to be build by this method
        # The current implementation is just for testing
        if not constraints:
            return []

        constraint_list = []
        for constraintString in constraints:
            m = re.match(Searcher.CONSTRAINT_REGEX, constraintString)
            if not m:
                raise RopperError('Not a valid constraint')

            reg1 = m.group(1)
            reg2 = m.group(3)
            adjust = m.group(2)

            if isHex(reg2):
                reg2 = int(reg2, 16)
            elif reg2.isdigit():
                reg2 = int(reg2)

            if reg1.startswith('['):
                raise RopperError("not implemented")
                reg1 = reg1[1:-1]
                reg1 = self.__getRealRegName(reg1.strip(), analysis.arch)
                z3_reg1_0 = analysis.readRegister(reg1,analysis.arch.registers[reg1][1]*8,0)
                reg2 = self.__getRealRegName(reg2.strip(), analysis.arch)
                z3_reg2 = analysis.readRegister(reg2,analysis.arch.registers[reg2][1]*8,0)
                size = analysis.arch.registers[reg2][1]
                mem_new = z3.Array('memory_1' , z3.BitVecSort(analysis.arch.bits), z3.BitVecSort(8))
                mem_old = z3.Array('memory_%d' % 0, z3.BitVecSort(analysis.arch.bits), z3.BitVecSort(8))
                for i in range(size):
                    mem_old = z3.Store(mem_old, z3_reg1_0+i, z3.Extract((i+1)*8-1,i*8,z3_reg2))
    
                constraint_list.append(mem_old == mem_new)

            elif isinstance(reg2, int):
                reg1 = self.__getRealRegName(reg1.strip(), analysis.arch)
                z3_reg1 = analysis.readRegister(reg1,analysis.arch.registers[reg1][1]*8)
                z3_reg2 = z3.BitVecVal(reg2, analysis.arch.registers[reg1][1]*8)

                if adjust:
                    z3_reg1_0 = analysis.readRegister(reg1,analysis.arch.registers[reg1][1]*8,0)
                    constraint_list.append(self._create(adjust, z3_reg1, z3_reg1_0, z3_reg2))
                else:
                    constraint_list.append(self._create(adjust, z3_reg1, z3_reg2))
                #constraint_list.append(z3_reg1 == z3_reg1_0 + reg2)
            elif reg2.startswith('['):
                reg1 = self.__getRealRegName(reg1.strip(), analysis.arch)
                z3_reg1 = analysis.readRegister(reg1,analysis.arch.registers[reg1][1]*8)
                reg2 = self.__getRealRegName(reg2[1:-1], analysis.arch)
                regs = analysis.regs.get((reg2))
                if regs:
                    c = None
                    for reg in regs:
                        reg = z3.Extract(analysis.arch.registers[reg2][1]*8-1, 0, reg)
                        mem = analysis.readMemory(reg, analysis.arch.registers[reg2][1]*8, analyse=False)
                        cnst = None
                        if adjust:
                            z3_reg1_0 = analysis.readRegister(reg1,analysis.arch.registers[reg1][1]*8,0)
                            cnst = self._create(adjust, z3_reg1, z3_reg1_0, mem)
                        else:
                            cnst = self._create(adjust, z3_reg1, mem)
                        if c is not None:
                            c = z3.Or(c, cnst)
                        else:
                            c = cnst
                    if c is not None:

                        constraint_list.append(c)
            else:
                reg1 = self.__getRealRegName(reg1.strip(), analysis.arch)
                z3_reg1 = analysis.readRegister(reg1,analysis.arch.registers[reg1][1]*8)
                reg2 = self.__getRealRegName(reg2.strip(), analysis.arch)
                z3_reg2 = analysis.readRegister(reg2,analysis.arch.registers[reg2][1]*8,0)
                if adjust:
                    z3_reg1_0 = analysis.readRegister(reg1,analysis.arch.registers[reg1][1]*8,0)
                    constraint_list.append(self._create(adjust, z3_reg1, z3_reg1_0, z3_reg2))
                else:
                    constraint_list.append(self._create(adjust, z3_reg1, z3_reg2))
            #print([reg1 == reg2])

        to_return = None
        for constraint in constraint_list:
            if to_return is not None:
                to_return = 'z3.And(%s, %s)' % (constraint,to_return)
            else:
                to_return = constraint

        if to_return is None:
            return None

        return to_return

    def extractValues(self, constraints, analysis):
        if not constraints:
            return []

        to_return = []

        for constraintString in constraints:
            m = re.match(Searcher.CONSTRAINT_REGEX, constraintString)
            if not m:
                raise RopperError('Not a valid constraint')

            reg1 = m.group(1)
            reg2 = m.group(3) 
            reg1 = reg1.replace('[','')
            reg1 = reg1.replace(']','')
            reg1 = self.__getRealRegName(reg1, analysis.arch)
            reg2 = reg2.replace('[','')
            reg2 = reg2.replace(']','')

            if reg2.isdigit() or isHex(reg2):
                reg2 = None
            reg2 = self.__getRealRegName(reg2, analysis.arch)
            to_return.append((reg1,reg2))
        return to_return

    def semanticSearch(self, gadgets, constraints, maxLen ,stableRegs=[]):
        if sys.version_info.major > 2:
            raise RopperError('Semantic Search is only available for python2.')

        if 'z3' not in globals():
            raise RopperError('z3 has to be installed in order to use semantic search')

        from ropper.semantic import ExpressionBuilder, Analyser, Slicer
        
        to_return = []
        count = 0
        max_count = len(gadgets)
        count = 0
        found = False
        found_gadgets = []
        slicer = Slicer()

        for glen in range(1,maxLen+1):
            for gadget in gadgets:
                if len(gadget) != glen:
                    continue
                
                anal = gadget.info#analyser.analyse(gadget)

                if not anal:
                    continue

                no_candidate = False
                for fg in found_gadgets:
                    #print(fg)
                    #print(gadget)
                    #print('fg',bytes(fg.bytes).encode('hex'), len(bytes(fg.bytes)))
                    #print('new',bytes(gadget.bytes)[0-len(fg.bytes):].encode('hex'), len(bytes(gadget.bytes)[0-len(fg.bytes):]), len(bytes(gadget.bytes)))
                    if bytes(gadget.bytes).endswith(bytes(fg.bytes)):
                    #    print('continue')
                        no_candidate = True
                        break

                if no_candidate:
                    continue

                no_candidate = False
                for reg in self.extractValues(constraints, anal):
                    if reg[0] not in anal.clobberedRegs or (reg[1] is not None and reg[1] not in anal.usedRegs):
                        no_candidate = True

                if no_candidate:
                    continue

                clobber_reg = False
                for reg in anal.clobberedRegs:
                    if reg in stableRegs:
                        clobber_reg = True
                if clobber_reg:
                    continue

                constraint_values = self.extractValues(constraints, anal)
                set_reg = constraint_values[0][0]
                slice_instructions = []
                
                slice = slicer.slice(anal.expressions, [set_reg for set_reg, get_reg in constraint_values ])
                
                count += 1
                solver = z3.Solver()

                expr_len = len(anal.expressions)
                expr = None
                tmp = None
                
                for inst in slice.expressions:
                    
                    tmp = inst
                   
                    if tmp == False:
                        continue
                    
                    if expr is None:
                        expr = tmp
                    else:
    
                        expr = 'And(%s, %s)' % (expr, tmp)
                 
                expr = ExpressionBuilder().build(anal.regs, anal.mems, expr, self._createConstraint(constraints, anal))
                

                
                solver.add(expr)
                
                if solver.check() == z3.unsat:
                    found = True
                    found_gadgets.append(gadget)
                    yield (gadget,count)
    
    def search(self, gadgets, filter, quality = None, pprinter=None):
        filter = self.prepareFilter(filter)
        filtered = {}
        count = 0
        max_count = len(gadgets)
        fg = []

        for g in gadgets:
            if g.match(filter):
                if quality:
                    if len(g) <= quality+1:
                        fg.append(g)
                else:
                    fg.append(g)
            count += 1
            if pprinter:
                pprinter.printProgress('searching gadgets...', float(count) / max_count)
            
        if pprinter:
            pprinter.finishProgress();
        return fg

    def filter(self, gadgets, filter, quality = None, pprinter=None):
        filter = self.prepareFilter(filter)
        filtered = {}
        count = 0
        max_count = len(gadgets)
        
        fg = []
        for g in gadgets:
            if not g.match(filter):
                if quality:
                    if len(g) <= quality+1:
                        yield g
                else:
                    yield g
            count += 1
            if pprinter:
                pprinter.printProgress('filtering gadgets...', float(count) / max_count)
            
        if pprinter:
            pprinter.finishProgress();


class Searcherx86(Searcher):

    def prepareFilter(self, filter):
        filter = super(Searcherx86,self).prepareFilter(filter)
        if not re.search('. ptr \\[', filter,  re.IGNORECASE):
            filter = filter.replace('\\[', '.{4,6} ptr \\[')
        return filter

class SearcherARM(Searcher):

    def prepareFilter(self, filter):
        filter = super(SearcherARM,self).prepareFilter(filter)
        filter = filter.replace('r9','sb')
        filter = filter.replace('r10','sl')
        filter = filter.replace('r11','fp')
        filter = filter.replace('r12','ip')
        filter = filter.replace('r13','sp')
        filter = filter.replace('r14','lr')
        filter = filter.replace('r15','pc')

        return filter

    def search(self, gadgets, filter, quality = None, pprinter=None):
        if pprinter:
            pprinter.printInfo('r9=sb r10=sl r11=fp r12=ip r13=sp r14=lr r15=pc')
        for x in super(SearcherARM, self).search(gadgets, filter, quality, pprinter):
            yield x
