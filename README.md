Ropper
================

With ropper you can show informations about files in different file formats
and you can search gadgets to build rop chains for different architectures. For disassembly ropper uses the
awesome Capstone Framework.

Install
-------

Install Capstone

    $ pip install capstone

Install and execute Ropper

    $ python setup.py install
    $ ropper

If you want, you can use Ropper without installation

    $ ./ropper.py


Usage
-----

    usage: ropper.py [-h] [-v] [--console] [-f <file>] [-i] [-e] [--imagebase]
                 [-c] [-s] [-S] [--imports] [--symbols] [--set <option>]
                 [--unset <option>] [-I <imagebase>] [-p] [-j <reg>]
                 [--depth <n bytes>] [--search <regex>] [--filter <regex>]
                 [--opcode <opcode>] [--type <type>]

    With ropper you can show informations about files in different file formats
    and you can search gadgets to build rop chains for different architectures.

    supported filetypes:
      ELF
      PE

    supported architectures:
      x86
      x86_64
      MIPS

    optional arguments:
      -h, --help            show this help message and exit
      -v, --version         Print version
      --console             Starts interactive commandline
      -f <file>, --file <file>
                            The file to load
      -i, --info            Shows file header [ELF/PE]
      -e                    Shows EntryPoint
      --imagebase           Shows ImageBase [ELF/PE]
      -c, --dllcharacteristics
                            Shows DllCharacteristics [PE]
      -s, --sections        Shows file sections [ELF/PE]
      -S, --segments        Shows file segments [ELF]
      --imports             Shows imports [ELF/PE]
      --symbols             Shows symbols [ELF]
      --set <option>        Sets options. Available options: aslr nx
      --unset <option>      Unsets options. Available options: aslr nx
      -I <imagebase>        Uses this imagebase for gadgets
      -p, --ppr             Searchs 'pop reg; pop reg; ret' instructions [only
                            x86/x86_64]
      -j <reg>, --jmp <reg>
                            Searchs 'jmp reg' instructions (-j reg[,reg...]) [only
                            x86/x86_64]
      --depth <n bytes>     Specify the depth of search (default: 10)
      --search <regex>      Searchs for gadgets
      --filter <regex>      Filters gadgets
      --opcode <opcode>     Searchs opcodes
      --type <type>         Sets the type of gadgets [rop, jop, all] (default:
                            all)

    example uses:
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


Planned features for future versions
------------------------------------
  Architectures:
  * ARM-Support
  * PowerPC-Support

  File formats
  * Mach-O

  ropchain generator

Project page
------------------------------------
http://scoding.de/ropper