#!/usr/bin/env python
# coding=utf-8
import re


def isHex(num):
    return re.match('^0x[0-9A-Fa-f]+$', num) != None


def toHex(number, length=4):
    return ('0x%.' + str(length * 2) + 'x') % number
