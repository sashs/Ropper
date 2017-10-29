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
    import archinfo
    import pyvex
except:
    pass
from ropper.common.error import RopperError
from ropper.common.utils import isHex
from ropper.gadget import Category
from ropper.semantic import ExpressionBuilder, Analyser, Slicer, create_register_expression, create_number_expression
import time
import sys


class Searcher(object):

    CONSTRAINT_REGEX = '(\[?[a-zA-Z0-9]+\]?)([\+\*\-=/])?=(\[?[a-zA-Z0-9]+\]?)$'

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

    def _create(self, adjust, left, right, right2=None):
        if adjust is not None:
            return '%s == %s %s %s' % (left, right, adjust, right2)
        else:
            return '%s == %s' % (left, right)

    def extractValues(self, constraints, analysis, arch):
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
            reg1 = arch.getRegisterName(reg1)
            reg2 = reg2.replace('[','')
            reg2 = reg2.replace(']','')

            if reg2.isdigit() or isHex(reg2):
                reg2 = None
            reg2 = arch.getRegisterName(reg2)
            to_return.append((reg1,reg2))
        return to_return

    def __isSimilarGadget(self, gadget, found_gadgets):
        for fg in found_gadgets:
            if bytes(gadget.bytes).endswith(bytes(fg.bytes)):
                return True
        return False

    def __areRegistersNotUsed(self, constraint_values, semantic_info):
        
        for reg in constraint_values:
            if reg[0] not in semantic_info.clobberedRegisters or (reg[1] is not None and reg[1] not in semantic_info.usedRegs):
                return True
        return False

    def __areStableRegistersClobbered(self, stable_registers, clobbered_registers):
        clobber_reg = False
        for reg in clobbered_registers:
            if reg in stable_registers:
                return True
        return False

    def semanticSearch(self, gadgets, constraints, maxLen ,stableRegs=[]):
        if sys.version_info.major > 2:
            raise RopperError('Semantic Search is only available for python2.')

        if 'z3' not in globals():
            raise RopperError('z3 has to be installed in order to use semantic search')

        if 'archinfo' not in globals():
            raise RopperError('archinfo has to be installed in order to use semantic search')
        if 'pyvex' not in globals():
            raise RopperError('pyvex has to be installed in order to use semantic search')
        to_return = []
        count = 0
        max_count = len(gadgets)
        count = 0
        found = False
        found_gadgets = []
        slicer = Slicer()
        constraint_key = " ".join(list(set(constraints)))
        import z3helper
        for glen in range(1, maxLen+1):
            for gadget in gadgets:
                if len(gadget) != glen:
                    continue
                semantic_info = gadget.info
                if not semantic_info:
                    continue
                
                #constraint_values = self.extractValues(constraints, semantic_info, gadget.arch)
                cc = z3helper.ConstraintCompiler(gadget.arch, semantic_info)
                constraint_values = cc.getSymbols(constraints)      
                          
                if self.__isSimilarGadget(gadget, found_gadgets) \
                or self.__areRegistersNotUsed(constraint_values, semantic_info) \
                or self.__areStableRegistersClobbered(stableRegs, semantic_info.clobberedRegisters):
                    continue
                constraint_string = cc.compile(';'.join(constraints))
                if constraint_key not in semantic_info.checkedConstraints:
                    set_reg = constraint_values[0][0]
                    slice_instructions = []
                    slice = slicer.slice(semantic_info.expressions, [set_reg for set_reg, get_reg in constraint_values])
                    count += 1
                    solver = z3.Solver()

                    expr_len = len(semantic_info.expressions)
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

                    expr = ExpressionBuilder().build(semantic_info.regs, semantic_info.mems, expr, constraint_string)
                    solver.add(expr)
                    if solver.check() == z3.unsat:
                        found = True
                        found_gadgets.append(gadget)
                        semantic_info.checkedConstraints[constraint_key] = True
                        yield gadget
                    else:
                        semantic_info.checkedConstraints[constraint_key] = False
                elif semantic_info.checkedConstraints[constraint_key]:
                    count += 1
                    found_gadgets.append(gadget)
                    yield gadget
                else:
                    count += 1
                
    
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
