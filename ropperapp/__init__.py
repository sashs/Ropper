from console import Console
from options import Options
from common.error import RopperError

VERSION='1.0'

def start(args):
    try:
        Console(Options(args)).start()
    except RopperError as e:
        print(e)
