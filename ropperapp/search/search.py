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
                        fg.append(g)
                else:
                    fg.append(g)
            count += 1
            if pprinter:
                pprinter.printProgress('filtering gadgets...', float(count) / max_count)
            
        if pprinter:
            pprinter.finishProgress();
        return fg


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
        return super(SearcherARM, self).search(gadgets, filter, quality, pprinter)
