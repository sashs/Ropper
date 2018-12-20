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
from ropper.common.abstract import *
from ropper.common.error import *

class RopChain(Abstract):

    def __init__(self, binaries, gadgets, callback, badbytes=''):

        self._binaries = binaries
        self._usedBinaries = []
        self.__callback = callback
        self._gadgets = gadgets
        self.__badbytes = badbytes


    @property
    def badbytes(self):
        return self.__badbytes

    @abstractmethod
    def create(self, options):
        pass

    def _updateUsedBinaries(self,gadget):
        if (gadget.fileName, gadget._section) not in self._usedBinaries:
            self._usedBinaries.append((gadget.fileName, gadget._section))

    @classmethod
    def name(cls):
        return None

    @classmethod
    def availableGenerators(cls):
        return []

    @classmethod
    def archs(self):
        return []


    @classmethod
    def usableTypes(self):
        return ()

    @classmethod
    def getUsableBinaries(cls, binaries):
        to_return = []
        for binary in binaries:
            if isinstance(binary, cls.usableTypes()):
                to_return.append(binary)

        return to_return

    @classmethod
    def get(cls, binaries, gadgets, name, callback, badbytes=''):
        for subclass in cls.__subclasses__():
            if binaries[0].arch in subclass.archs():
                gens = subclass.availableGenerators()
                for gen in gens:
                    if gen.name() == name:
                        ub = gen.getUsableBinaries(binaries)
                        if ub:
                            return gen(ub, gadgets, callback, badbytes)
                        else:
                            filetypes = set([str(b.type) for b in binaries])
                            raise RopperError('The generator {} is not useable for the filetypes: {}'.format(name, ', '.join(filetypes)))


    def containsBadbytes(self, value, bytecount=4):
        for b in self.badbytes:
            tmp = value


            if type(b) == str:
                b = ord(b)

            for i in range(bytecount):
                if (tmp & 0xff) == b:
                    return True

                tmp >>= 8
        return False

    def _printMessage(self, message):
        if self.__callback:
            self.__callback(message)
