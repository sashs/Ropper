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

from re import match
from sys import version_info
import types

if version_info.major > 2:
    long = int

class EnumError(BaseException):

    def __init__(self, msg):
        super(EnumError, self).__init__(msg)



class EnumElement(object):

    def __init__(self, name, value, enum):
        super(EnumElement, self).__init__()

        self.__name = name
        self.__value = value
        self.__enum = enum

    @property
    def name(self):
        return self.__name

    @property
    def value(self):
        return self.__value

    @property
    def _enum(self):
        return self.__enum

    def __str__(self):
        return self.__name

    def __index__(self):
        return self.__value

    def __hash__(self):
        return hash((self,))

    @property
    def value(self):
        return self.__value

    @property
    def name(self):
        return self.__name

    def __repr__(self):
        return str(self)

class IntEnumElement(EnumElement):


    def __hash__(self):
        return hash(self.value)

    def __cmp__(self, other):
        if isinstance(other, EnumElement):
            return self.value - other.value
        else:
            return self.value - other

    def __lt__(self, other):
        return self.__cmp__(other) < 0

    def __le__(self, other):
        return self.__cmp__(other) <= 0

    def __eq__(self, other):
        return self.__cmp__(other) == 0

    def __ge__(self, other):
        return self.__cmp__(other) >= 0

    def __gt__(self, other):
        return self.__cmp__(other) > 0

    def __and__(self, other):
        if isinstance(other, int) or isinstance(other, long):
            return self.value & other
        elif isinstance(other, EnumElement):
            return self.value & other.value
        raise TypeError('This operation is not supported for type ' % type(other))

    def __rand__(self, other):
        if isinstance(other, int) or isinstance(other, long):
            return self.value & other
        elif isinstance(other, EnumElement):
            return self.value & other.value
        raise TypeError('This operation is not supported for type ' % type(other))

    def __or__(self, other):
        if isinstance(other, int) or isinstance(other, long):
            return self.value | other
        elif isinstance(other, EnumElement) :
            return self.value | other.value
        raise TypeError('This operation is not supported for type ' % type(other))

    def __ror__(self, other):
        if isinstance(other, int) or isinstance(other, long):
            return self.value | other
        elif isinstance(other, EnumElement):
            return self.value | other.value
        raise TypeError('This operation is not supported for type ' % type(other))


    def __invert__(self):
        return ~self.value

    def __int__(self):
        return self.value




class EnumIterator(object):

    def __init__(self, enumData):
        self.__enumData = enumData
        self.__index = 0

    def next(self):
        if self.__index < len(self.__enumData):
            data = self.__enumData[self.__index]
            self.__index += 1
            return data
        raise StopIteration



class EnumMeta(type):

    def __new__(cls, name, bases, dct):

        def update(key, value):
            if value in values:
                raise EnumError('No aliases allowed: '+key+' and '+str(revData[value]))
            if isinstance(value, types.FunctionType):
                dct[key] = classmethod(value)
                return
            values.append(value)
            if isinstance(value, int) or isinstance(value, long):
                element = IntEnumElement(key, value, name)
            else:
                element = EnumElement(key, value, name)
            revData[value] = element
            valueData.append(element)
            dct[key] = element

        revData = {}
        valueData = []
        values = []
        for key, value in dct.items():
            if not key.startswith('_'):
                update(key, value)

        count = 0
        if '_enum_' in dct:
            enuminit = None
            if isinstance(dct['_enum_'], str):
                enuminit = dct['_enum_'].split(' ')
            elif isinstance(dct['_enum_'], tuple) or isinstance(dct['_enum_'], list):
                enuminit = dct['_enum_']
            for key in enuminit:
                if count in revData:
                    raise EnumError('The predefined elements have to have bigger value numbers')
                update(key, count)
                count += 1

        dct['_revData'] = revData
        dct['_enumData'] = sorted(valueData, key=lambda x: x.value)

        return super(EnumMeta, cls).__new__(cls, name, bases, dct)



    def __call__(cls, name, args):
        if isinstance(args, list):
            args = ' '.join(args)
        return type(name, (cls,), {'_enum_':args})

    def __iter__(cls):
        return EnumIterator(cls._enumData)

    def __str__(cls):
        toReturn = '<'
        for elem in cls._enumData:
            toReturn += str(elem) + '|'
        toReturn = toReturn[:-1] + '>'
        return cls.__name__ + '='+toReturn

    def __contains__(cls, item):
        return item in cls._revData

    def __getitem__(cls, key):
        if isinstance(key, str):
            return cls.__search(key)
        elif isinstance(key, EnumElement):
            return cls.__search(str(key))
        elif isinstance(key, int) or isinstance(key, long):
            if key in cls._revData:
                return cls._revData[key]
            return 'Unkown'
        raise TypeError('key has to be an instance of int/long or str:' + key.__class__.__name__)

    def __search(self, key):
        for elem in self._enumData:
            if str(elem) == key:
                return elem;

    def __instancecheck__(self, instance):
        return isinstance(instance, EnumElement) and instance._enum == self.__name__

# For compatibility reason (python2 & python3)
Enum = EnumMeta('Enum', (), {})
