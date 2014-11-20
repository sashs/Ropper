#!/usr/bin/env python2
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
from ropperapp.common.enum import Enum
from sys import version_info
import ropperapp


class Color(Enum):
	RED = '0;31'
	CYAN = '0;36'
	BLUE = '0;34'
	GREEN = '0;32'
	PURPLE = '0;35'
	LIGHT_RED = '1;31'
	LIGHT_CYAN = '1;36'
	LIGHT_BLUE = '1;34'
	LIGHT_GREEN = '1;32'
	LIGHT_PURPLE = '1;35'
	LIGHT_YELLOW = '1;33'
	YELLOW = '0;33'
	LIGHT_GRAY = '0;37'
	WHITE = '1;37'

class cstr(str):

	def __new__(cls, data='', color=Color.LIGHT_GRAY):
		if isinstance(data, cstr):
			return data
		if version_info.major > 2 and type(data) is bytes:
			data = data.decode('utf-8')
		new = str.__new__(cls, data)
		new._color = color
		return new

	@property
	def color(self):
		return self._color

	def __add__(self, arg):
		return str.__add__(str(self),str(arg))

	def __iadd__(self, arg):
		return str.__iadd__(str(self),str(arg))

	def __len__(self):
		return str.__len__(str(self))

	def rawlength(self):
		return str.__len__(self)

	def __repr__(self):
		return str.__repr__(self)

	def __str__(self):
		data = str.__str__(self)
		if ropperapp.app_options.nocolor or not self._color:
			return data
		return '\x1b[%sm%s\x1b[0m' % (self._color.value, data)


	def colorize(self, color):
		self._color = color
