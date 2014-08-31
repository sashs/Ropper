from abc import *


class AbstractSingletonMeta(ABCMeta):

    def __init__(self, name, bases, namespace):
        super(AbstractSingletonMeta, self).__init__(name, bases, namespace)

        self._instance = None

    def __call__(self):
        if not self._instance:
            self._instance = super(AbstractSingletonMeta, self).__call__()

        return self._instance

Abstract = ABCMeta('Abstract', (), {})
AbstractSingleton = AbstractSingletonMeta('AbstractSingelton', (), {})
