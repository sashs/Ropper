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

from ropper.common.error import RopperError
from ropper.semantic import Analyser
from ropper.common.utils import isHex
from ropper.gadget import Category
from ropper.slicing import Slicer
import time
import sys
try:
    if sys.version_info.major < 3:
        import z3
except:
    pass

class Searcher(object):

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

    def _createConstraint(self, constraints, analysis):
        # TODO complex constraints have to be build by this method
        # The current implementation is just for testing
        if not constraints:
            return []

        to_return = []
        for constraintString in constraints:
            if '=' not in constraintString:
                raise RopperError('Not a valid constraint')
            
            reg1, reg2 = constraintString.split('=')
            if isHex(reg2):
                reg2 = int(reg2, 16)
            elif reg2.isdigit():
                reg2 = int(reg2)

            reg1 = self.__getRealRegName(reg1.strip(), analysis.arch)

            z3_reg1 = analysis.readRegister(reg1,analysis.arch.registers[reg1][1]*8)
            z3_reg1_0 = analysis.readRegister(reg1,analysis.arch.registers[reg1][1]*8,0)
            if isinstance(reg2, int):
                reg2 = z3.BitVecVal(reg2, analysis.arch.registers[reg1][1]*8)
                to_return.append(z3_reg1 == reg2)
            elif reg2.startswith('['):
                reg2 = self.__getRealRegName(reg2[1:-1], analysis.arch)
                regs = analysis.regs.get((reg2))
                if regs:
                    c = None
                    for reg in regs:
                        reg = z3.Extract(analysis.arch.registers[reg2][1]*8-1, 0, reg)
                        if c is not None:
                            c = z3.Or(c, z3_reg1 == analysis.readMemory(reg, analysis.arch.registers[reg2][1]*8, analyse=False))
                        else:
                            c = z3_reg1 == analysis.readMemory(reg, analysis.arch.registers[reg2][1]*8, analyse=False)
                    if c is not None:

                        to_return.append(c)
                
            else:
                reg2 = self.__getRealRegName(reg2.strip(), analysis.arch)
                reg2 = analysis.readRegister(reg2,analysis.arch.registers[reg2][1]*8,0)
                to_return.append(z3_reg1 == reg2)
            
            
            #print([reg1 == reg2])
            
        return to_return

    def getCategory(self, constraints):
        if not constraints:
            return []

        to_return = []
        for constraintString in constraints:
            if '=' not in constraintString:
                raise RopperError('Not a valid constraint')
            
            reg1, reg2 = constraintString.split('=')
            if isHex(reg2):
                reg2 = int(reg2, 16)
            elif reg2.isdigit():
                reg2 = int(reg2)

            if isinstance(reg2, int):
                return Category.WRITE_REG_FROM_REG
            elif reg2.startswith('['):
                return Category.WRITE_REG_FROM_MEM
            else:
                return Category.WRITE_REG_FROM_REG

    def extractValues(self, constraints, analysis):
        if not constraints:
            return []

        to_return = []

        for constraintString in constraints:
            if '=' not in constraintString:
                raise RopperError('Not a valid constraint')

            reg1, reg2 = constraintString.split('=')
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

    def chainGadgets(self, gadgets, constraints, maxLen, stableRegs=[]):
        pass


    def semanticSearch(self, gadgets, constraints, maxLen ,stableRegs=[]):
        if 'z3' not in globals():
            raise RopperError('z3py is needed') 

        to_return = []
        count = 0
        max_count = len(gadgets)
        count = 0
        found = False
        slicer = Slicer()
        for glen in range(1,maxLen+1):
            for gadget in gadgets:
                if len(gadget) != glen:
                    continue
                    
                anal = gadget.info#analyser.analyse(gadget)

                if not anal:
                    continue

                constraint_values = self.extractValues(constraints, anal)
                set_reg = constraint_values[0][0]

                no_possible_gadget = False
                for reg in self.extractValues(constraints, anal):
                    if reg[0] not in anal.clobberedRegs:
                        no_possible_gadget = True
                if no_possible_gadget:
                    continue

                clobber_reg = False
                for reg in anal.clobberedRegs:
                    if reg in stableRegs:
                        clobber_reg = True
                if clobber_reg:
                    continue

                slice = slicer.slicing(anal.irsb, set_reg)
                count += 1
                solver = z3.Solver()

                expr_len = len(anal.expressions)
                for inst in slice.instructions[::-1]:
                    expr = anal.expressions[expr_len-inst]
                    if expr == False:
                        continue
                    solver.add(expr)

                c = None
                c2 = None
                for constraint in self._createConstraint(constraints, anal):
                    
                    c = constraint
                    if c2 is not None:
                        c2 = z3.And(c,c2)
                    else:
                        c2 = c
                if c2 is not None:
                    solver.add(z3.Not(c2))
                
                if solver.check() == z3.unsat:
                    found = True
                    yield gadget
    
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
