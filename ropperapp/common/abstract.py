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
