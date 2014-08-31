from re import match
import types

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

    def __cmp__(self, other):
        if isinstance(other, EnumElement):
            return self.__value - other.__value
        else:
            return self.__value - other

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

    def __index__(self):
        return self.__value

    def __and__(self, other):
        if isinstance(other, int) or isinstance(other, long):
            return self.__value & other
        elif isinstance(other, EnumElement):
            return self.__value & other.__value
        raise TypeError('This operation is not supported for type ' % type(other))

    def __rand__(self, other):
        if isinstance(other, int) or isinstance(other, long):
            return self.__value & other
        elif isinstance(other, EnumElement):
            return self.__value & other.__value
        raise TypeError('This operation is not supported for type ' % type(other))

    def __or__(self, other):
        if isinstance(other, int) or isinstance(other, long):
            return self.__value | other
        elif isinstance(other, EnumElement) :
            return self.__value | other.__value
        raise TypeError('This operation is not supported for type ' % type(other))

    def __ror__(self, other):
        if isinstance(other, int) or isinstance(other, long):
            return self.__value | other
        elif isinstance(other, EnumElement):
            return self.__value | other.__value
        raise TypeError('This operation is not supported for type ' % type(other))


    def __invert__(self):        return ~self.__value

    def __int__(self):
        return self.__value


    @property
    def value(self):
        return self.__value

    @property
    def name(self):
        return self.__name

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
                raise EnumError('Duplicate element')
            if isinstance(value, types.FunctionType):
                dct[key] = classmethod(value)
                return
            values.append(value)
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
        dct['_enumData'] = sorted(valueData)

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

    def __getitem__(cls, key):
        if isinstance(key, str):
            return cls.__search(key)
        elif isinstance(key, EnumElement):
            return cls.__search(str(key))
        elif isinstance(key, int) or isinstance(key, long):
            return cls._revData[key]
        raise TypeError('key has to be an instance of int/long or str:' + key.__class__)

    def __search(self, key):
        for elem in self._enumData:
            if str(elem) == key:
                return elem;

    def __instancecheck__(self, instance):
        return isinstance(instance, EnumElement) and instance._enum == self.__name__

# For compatibility reason (python2 & python3)
Enum = EnumMeta('Enum', (), {})
