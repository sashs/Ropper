import argparse
from common.error import *
from common.utils import isHex


class Options(object):

    def __init__(self, argv):
        super(Options, self).__init__()

        self.__argv = argv
        self.__args = None
        self.__parser = self._createArgParser()
        self._analyseArguments()

    def _createArgParser(self):
        parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
description="""With ropper you can show informations about files in different file formats
and you can search gadgets to build rop chains for different architectures.

supported filetypes:
  ELF
  PE

supported architectures:
  x86
  x86_64
  MIPS
""",
epilog="""example uses:
  [Generic]
  ropper.py
  ropper.py --file /bin/ls --console

  [Informations]
  ropper.py --file /bin/ls --info
  ropper.py --file /bin/ls --imports
  ropper.py --file /bin/ls --sections
  ropper.py --file /bin/ls --segments
  ropper.py --file /bin/ls --set nx
  ropper.py --file /bin/ls --unset nx

  [Gadgets]
  ropper.py --file /bin/ls --depth 5
  ropper.py --file /bin/ls --search "sub eax"
  ropper.py --file /bin/ls --filter "sub eax"
  ropper.py --file /bin/ls --opcode ffe4
  ropper.py --file /bin/ls --type jop
  ropper.py --file /bin/ls --ppr
  ropper.py --file /bin/ls --jmp esp,eax
  ropper.py --file /bin/ls --type jop
  \n""")


        parser.add_argument(
            '-v', '--version', help="Print version", action='store_true')
        parser.add_argument(
            '--console', help='Starts interactive commandline', action='store_true')
        parser.add_argument(
            '-f', '--file', metavar="<file>", help='The file to load')
        parser.add_argument(
            '-i', '--info', help='Shows file header [ELF/PE]', action='store_true')
        parser.add_argument('-e', help='Shows EntryPoint', action='store_true')
        parser.add_argument('--imagebase', help='Shows ImageBase [ELF/PE]', action='store_true')
        parser.add_argument(
            '-c', '--dllcharacteristics',help='Shows DllCharacteristics [PE]', action='store_true')
        parser.add_argument(
            '-s', '--sections', help='Shows file sections [ELF/PE]', action='store_true')
        parser.add_argument(
            '-S', '--segments', help='Shows file segments [ELF]', action='store_true')
        parser.add_argument(
            '--imports', help='Shows imports [ELF/PE]', action='store_true')
        parser.add_argument(
            '--symbols', help='Shows symbols [ELF]', action='store_true')
        parser.add_argument(
            '--set', help='Sets options. Available options: aslr nx', metavar='<option>')
        parser.add_argument(
            '--unset', help='Unsets options. Available options: aslr nx', metavar='<option>')
        parser.add_argument('-I', metavar='<imagebase>', help='Uses this imagebase for gadgets')
        parser.add_argument(
            '-p', '--ppr', help='Searchs \'pop reg; pop reg; ret\' instructions [only x86/x86_64]', action='store_true')
        parser.add_argument(
            '-j', '--jmp', help='Searchs \'jmp reg\' instructions (-j reg[,reg...]) [only x86/x86_64]', metavar='<reg>')
        parser.add_argument(
            '--depth', help='Specify the depth of search (default: 10)', metavar='<n bytes>', type=int)
        parser.add_argument(
            '--search', help='Searchs for gadgets', metavar='<regex>')
        parser.add_argument(
            '--filter', help='Filters gadgets', metavar='<regex>')
        parser.add_argument(
            '--opcode', help='Searchs opcodes', metavar='<opcode>')
        parser.add_argument(
            '--type', help='Sets the type of gadgets [rop, jop, all] (default: all)', metavar='<type>')
        return parser

    def _analyseArguments(self):
        if len(self.__argv) == 0:
            self.__argv.append('--console')
        self.__args = self.__parser.parse_args(self.__argv)

        if not self.__args.console and not self.__args.file and not self.__args.version:
            self.__missingArgument('[-f|--file]')

        if not self.__args.depth:
            self.__args.depth = 10

        if not self.__args.type:
            self.__args.type = 'all'

        if self.__args.I:
            if not isHex(self.__args.I):
                raise ArgumentError('Imagebase should be in hex (0x.....)')
            else:
                self.__args.I = int(self.__args.I, 16)


    def __missingArgument(self, arg):
        raise ArgumentError('Missing argument: %s' % arg)

    def __getattr__(self, key):
        if key.startswith('_'):
            return super(Options, self).__getattr__(key)
        else:
            return vars(self.__args)[key]

    def __setattr__(self, key, value):
        if key.startswith('_'):
            super(Options, self).__setattr__(key, value)
        else:
            vars(self.__args)[key] = value
