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
VERSION=[1,11,10]

def start(args):
    try:
        global app_options
        app_options = Options(args)
        Console(app_options).start()
    except RopperError as e:
        print('Please report this error on https://github.com/sashs/ropper')
        print('Stacktrace:')
        print(traceback.format_exc())

