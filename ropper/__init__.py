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
from filebytes.pe import ImageDirectoryEntry
from .console import Console
from .options import Options
from .common.error import *
from binascii import unhexlify
from ropper.rop import Ropper
from ropper.loaders import elf
from ropper.loaders import pe
from ropper.loaders import mach_o
from ropper.loaders import raw
from ropper.loaders.loader import Loader, Type
from ropper.gadget import Gadget, GadgetType
from ropper.service import RopperService, filterBadBytes
from ropper.service import deleteDuplicates, cfgFilterGadgets
from ropper.arch import ARM,ARM64, ARMTHUMB,  x86, x86_64, PPC, PPC64, MIPS, MIPS64, MIPSBE, MIPS64BE, ARMBE
import traceback
app_options = None
VERSION=[1,11,13]


def start(args):
    try:
        global app_options
        app_options = Options(args)
        Console(app_options).start()
    except RopperError as e:
        print('Please report this error on https://github.com/sashs/ropper')
        print('Stacktrace:')
        print(traceback.format_exc())
