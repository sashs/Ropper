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
from ropper.common.enum import Enum
from sys import version_info

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

	COLOR = False

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
		return cstr(str.__add__(str(self),str(arg)))

	def __iadd__(self, arg):
		return cstr(str.__add__(str(self),str(arg)))

	def __len__(self):
		return str.__len__(str(self))

	def rawlength(self):
		return str.__len__(self)

	def __repr__(self):
		return str.__repr__(self)

	def __str__(self):
		data = str.__str__(self)
		if not cstr.COLOR or not self._color:
			return data
		return '\x1b[%sm%s\x1b[0m' % (self._color.value, data)

	def __eq__(self, other):
		data = str.__str__(self)
		other = str.__str__(other)
		return data.__eq__(other)

	def __ne__(self, other):
		data = str.__str__(self)
		other = str.__str__(other)
		return data.__ne__(other)

	def __lt__(self, other):
		data = str.__str__(self)
		other = str.__str__(other)
		return data.__lt__(other)

	def __le__(self, other):
		data = str.__str__(self)
		other = str.__str__(other)
		return data.__le__(other)

	def __gt__(self, other):
		data = str.__str__(self)
		other = str.__str__(other)
		return data.__gt__(other)

	def __ge__(self, other):
		data = str.__str__(self)
		other = str.__str__(other)
		return data.__ge__(other)

	def colorize(self, color):
		self._color = color
