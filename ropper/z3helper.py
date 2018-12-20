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
    REG_REGEX = '(?P<{}>[a-zA-Z0-9]+)'
    ADJUST_REGEX = '([\\+\-\*/=]=)'
    ASSIGNMENT_REGEX = '('+REG_REGEX.format('reg_dst_1') + ' *' + ADJUST_REGEX + ' *('+NUMBER_REGEX+'|'+REG_REGEX.format('reg_src_1')+'|(\[)'+REG_REGEX.format('reg_src_2')+'(\])))'
    POP_REGEX = '((pop) +'+REG_REGEX.format('reg_dst_2')+')'
    CONSTRAINT_REGEX = '(' + ASSIGNMENT_REGEX + '|' + POP_REGEX + ')'

    def __init__(self, architecture, semantic_info):
        self.__architecture = architecture
        self.__semantic_info = semantic_info

    def getSymbols(self, constraints):
        symbols = []
        for constraint in constraints:
            match = re.match(ConstraintCompiler.CONSTRAINT_REGEX, constraint)
            if match is None:
                raise Exception('Invalid syntax: %s' % constraint)
            reg_dst = match.group('reg_dst_1')
            if reg_dst is not None:
                reg_src = match.group('reg_src_1')
                reg_src = match.group('reg_src_2') if reg_src is None else reg_src
                symbols.append((reg_dst, reg_src))
            else:
                symbols.append((match.group('reg_dst_2'), None))

        return symbols


    def compile(self, constraints):
        """
        compile a line of semantic expressions
        """
        tokens = self._tokenize(constraints)[::-1]
        to_return = None
        constraint = None
        while True:
            if not tokens:
                break

            token = tokens.pop()
            if token in self.__architecture.info.registers:
                constraint = self._assignment(token, tokens)
            elif token == 'pop':
                constraint = self._popReg(token, tokens)
            elif token == ';':
                if to_return is None:
                    to_return = constraint
                else:
                    to_return = 'And(%s, %s)' % (to_return, constraint)
            else:
                raise ConstraintError('Invalid token: %s' % token)

        return to_return

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

    def _assignment(self, register, tokens):
        register = self.__architecture.getRegisterName(register)
        reg1_last = self.__semantic_info.regs[register][-1]
        reg1_init = self.__semantic_info.regs[register][0]
        op = tokens.pop()
        if not re.match(ConstraintCompiler.ADJUST_REGEX, op):
            raise ConstraintError('Invalid syntax: %s' % op)
        value = tokens.pop()
        if value == '[':
            r1 = register
            register = tokens.pop()

            register_name = self.__architecture.getRegisterName(register)
            if not register_name:
                raise ConstraintError('Invalid register: %s' & register)
            value = self._readMemory(register_name)
            tokens.pop()
        elif re.match(ConstraintCompiler.NUMBER_REGEX, value):
            value = create_number_expression(int(value), int(reg1_last.split('_')[-1]))

        elif value in self.__architecture.info.registers:
            value = self.__architecture.getRegisterName(value)
            value = self.__semantic_info.regs[value][0]
            value = create_register_expression(value, int(value.split('_')[-1]))
        else:
            print(re.match(ConstraintCompiler.NUMBER_REGEX, value))
            raise ConstraintError('Invalid Assignment: %s%s%s' % (register, op, value))
        reg1_last = create_register_expression(reg1_last, int(reg1_last.split('_')[-1]))
        reg1_init = create_register_expression(reg1_init, int(reg1_init.split('_')[-1]))
        return self._create(reg1_last, reg1_init, value, op[0])

    def _create(self, left_last, left_init, right, adjust):
        if adjust != '=':
            return '%s == %s %s %s' % (left_last, left_init, adjust, right)
        else:
            return '%s == %s' % (left_last, right)

    def _readMemory(self, register):
        register_init = self.__semantic_info.regs[register][0]
        if self.__semantic_info.mems:
            memory = self.__semantic_info.mems[-1]
        else:
            memory = 'memory%d_%d_%d' % (0, self.__architecture.info.bits, 8)
            self.__semantic_info.mems.append(memory)
        size = int(register_init.split('_')[-1])
        register_expr = create_register_expression(register_init, size)
        mem_expr = create_read_memory_expression(memory, register_expr, size)
        return mem_expr

    def _popReg(self, pop, tokens):
        reg_name = tokens.pop()
        self.symbols.append((reg_name,None))
        reg = self.__semantic_info.regs[reg_name][-1]
        if self.__semantic_info.mems:
            memory = self.__semantic_info.mems[0]
        else:
            memory = 'memory%d_%d_%d' % (0, self.__architecture.info.bits, 8)
            self.__semantic_info.mems.append(memory)
        size = int(reg.split('_')[-1])
        register_expr = create_register_expression(reg, size)
        mem_expr = create_read_memory_expression(memory, register_expr, size)
        return mem_expr


class ConstraintError(RopperError):
    """
    ConstraintError
    """
    pass


def create_register_expression(register_accessor, size, high=False):
    register_size = int(register_accessor.split('_')[2])
    if size < register_size:
        if high:
            return 'Extract(%d, 8, %s)' % (size+8-1, register_accessor)
        else:
            return 'Extract(%d, 0, %s)' % (size-1, register_accessor)
    else:
        return '%s' % register_accessor

def create_number_expression(number, size):
    return "BitVecVal(%d, %d)" % (number, size)

def create_read_memory_expression(memory, addr, size):
    to_return = '%s[%s]' % (memory, addr)
    for i in range(1, int(size/8)):
        value = '%s[%s]' % (memory, '%s + %d' % (addr, i))
        to_return = 'Concat(%s, %s)' % (value, to_return)

    return to_return
