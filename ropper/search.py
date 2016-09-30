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
import re

from ropper.common.error import RopperError
from ropper.semantic import Analyser
from ropper.common.utils import isHex
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

    def _createConstraint(self, constraintString, analysis):
        # TODO complex constraints have to be build by this method
        # The current implementation is just for testing
        if not constraintString:
            return []

        if '=' not in constraintString:
            raise RopperError('Not a valid constraint')
        
        reg1, reg2 = constraintString.split('=')
        if isHex(reg2):
            reg2 = int(reg2, 16)
        elif reg2.isdigit():
            reg2 = int(reg2)

        if isinstance(reg2, int):
            reg2 = z3.BitVecVal(reg2, analysis.arch.registers[reg1][1]*8)
        else:
            reg2 = analysis.readRegister(reg2.strip(),analysis.arch.registers[reg2][1]*8,0)
        reg1 = analysis.readRegister(reg1.strip(),analysis.arch.registers[reg1][1]*8)
        
        
        #print([reg1 == reg2])
        return [reg1 == reg2] 

    def semanticSearch(self, gadgets, constraintString, maxLen ,stableRegs=[], pprinter=None):
        if 'z3' not in globals():
            raise RopperError('z3py is needed') 

        
        to_return = []
        count = 0
        max_count = len(gadgets)
        for i in range(1,maxLen):
            for gadget in gadgets:
                if len(gadget) == i:

                    
                    if pprinter:
                        pprinter.printProgress('searching gadgets...', float(count) / max_count)
                    anal = gadget.info#analyser.analyse(gadget)
                    count += 1
                    if not anal:
                        continue
                    solver = z3.Solver()
                    for expr in anal.expressions:
                        if expr == False:
                            continue
                        solver.add(expr)
                    for constraint in self._createConstraint(constraintString, anal):
                        
                        solver.add(z3.Not(constraint))
                    
                    if solver.check() == z3.unsat:
                        for reg in stableRegs:
                            if reg in anal.clobberedRegs:
                                continue
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
