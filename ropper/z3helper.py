# coding=utf-8
#
# Copyright 2017 Sascha Schirra
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

class ConstraintCompiler(object):
    """
    Compile a user given constraints to z3 expressions

    constraint := assignment | pop_reg
    assignment := reg, adjust, reg | number
    pop_reg := "pop", reg
    adjust := "==" | "+=" | "-=" | "*=" | "/="
    reg := a register of the current architecture
    number := int
    """

    NUMBER_REGEX = '(-?[0-9]+)'
    REG_REGEX = '([a-zA-Z0-9]+)'
    ADJUST_REGEX = '([\\+\-\*/=]=)'
    ASSIGNMENT_REGEX = '('+REG_REGEX + ' *' + ADJUST_REGEX + ' *('+NUMBER_REGEX+'|'+REG_REGEX+'|(\[)'+REG_REGEX+'(\])))'
    POP_REGEX = '((pop) +([a-zA-Z0-9]+))'
    CONSTRAINT_REGEX = '(' + ASSIGNMENT_REGEX + '|' + POP_REGEX + ')'

    def parse(self, constraints):
        """
        parse a line of semantic expressions
        """
        tokens = self._tokenize(constraints)
        print(tokens)

    def _tokenize(self, constraints):
        """
        return a list of tokens
        """
        tokens = []
        for constraint in constraints.split(';'):
            constraint = constraint.strip()
            if not constraint:
                continue
            match = re.match(ConstraintCompiler.CONSTRAINT_REGEX, constraint)
            if match is None:
                raise ConstraintError('Invalid Syntax: %s' % constraint)
            last_valid_index = -1
            for index in range(1, len(match.regs)):
                start = match.regs[index][0]
                if start == -1:
                    continue
                if last_valid_index == -1:
                    last_valid_index = index
                    continue
                if match.regs[last_valid_index][0] != start:
                    tokens.append(match.group(last_valid_index))
                last_valid_index = index
            tokens.append(match.group(last_valid_index))
            tokens.append(';')
        return tokens


class ConstraintError(RopperError):
    """
    ConstraintError
    """
    pass
