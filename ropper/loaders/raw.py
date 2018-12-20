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

from ropper.loaders.loader import *
from ropper.common.error import LoaderError
from ropper.arch import x86
from filebytes.binary import Binary

class Raw(Loader):

    def __init__(self, filename, bytes=None, arch=x86):
        super(Raw, self).__init__(filename, bytes, arch)
        self.__codeSection = Section('bytes', self._binary._bytes, 0x0, 0x0)

    @property
    def entryPoint(self):
        return 0x0

    def _getImageBase(self):
        return 0x0

    @property
    def type(self):
        return Type.RAW

    @property
    def executableSections(self):
        return [self.__codeSection]

    @property
    def dataSections(self):
        return []

    def getSection(self, name):
        raise RopperError('No such secion: %s' % name)

    def _loadDefaultArch(self):
        return None

    def _loadFile(self, fileName, bytes=None):
        return RawBinary(fileName, bytes)

    def setNX(self, enable):
        raise LoaderError('Not available for raw files')


    def setASLR(self, enable):
        raise LoaderError('Not available for raw files')


    def checksec(self):
        raise LoaderError('Not available for raw files')


    @classmethod
    def isSupportedFile(cls, fileName, bytes=None):
        return True


class RawBinary(Binary):

    @classmethod
    def isSupportedContent(cls, fileContent):
        return True
