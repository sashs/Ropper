Ropper
================

With ropper you can show information about files in different file formats
and you can search for gadgets to build rop chains for different architectures. For disassembly ropper uses the
awesome Capstone Framework.

Install
-------

Download and Install Capstone

    $ wget http://capstone-engine.org/download/3.0/capstone-3.0.tgz
    $ tar xf capstone-3.0.tgz
    $ cd capstone-3.0
    $ ./make.sh
    $ sudo ./make.sh install
    $ cd ./bindings/python
    $ sudo make install

Install and execute Ropper

    $ python setup.py install
    $ ropper

You can also install Ropper with pip

    $ pip install ropper

If you want, you can use Ropper without installation

    $ ./ropper.py


Usage
-----

    usage: ropper.py [-h] [-v] [--console] [-f <file>] [-a <arch>] [-i] [-e]
                 [--imagebase] [-c] [-s] [-S] [--checksec] [--imports]
                 [--symbols] [--set <option>] [--unset <option>]
                 [-I <imagebase>] [-p] [-j <reg>] [--depth <n bytes>]
                 [--search <regex>] [--filter <regex>] [--opcode <opcode>]
                 [--type <type>] [--detail] [--chain <generator>]
                 [-b <badbytes>] [--nocolor]

    With ropper you can show information about files in different file formats
    and you can find gadgets to build rop chains for different architectures.

    supported filetypes:
      ELF
      PE
      Mach-O

    supported architectures:
      x86 [x86]
      x86_64 [x86_64]
      MIPS [MIPS, MIPS64]
      ARM/Thumb [ARM, ARMTHUMB]
      ARM64 [ARM64]
      PowerPC [PPC, PPC64]

    available rop chain generators:
      execve (execve[=<cmd>], default /bin/sh) [Linux x86]
      mprotect  (mprotect=<address>:<size>) [Linux x86]

    optional arguments:
      -h, --help            show this help message and exit
      -v, --version         Print version
      --console             Starts interactive commandline
      -f <file>, --file <file>
                            The file to load
      -a <arch>, --arch <arch>
                            The architecture of the loaded file
      -i, --info            Shows file header [ELF/PE/Mach-O]
      -e                    Shows EntryPoint
      --imagebase           Shows ImageBase [ELF/PE/Mach-O]
      -c, --dllcharacteristics
                            Shows DllCharacteristics [PE]
      -s, --sections        Shows file sections [ELF/PE/Mach-O]
      -S, --segments        Shows file segments [ELF/Mach-O]
      --checksec            Shows the security mechanisms used in the file
                            [ELF/PE/Mach-O]
      --imports             Shows imports [ELF/PE]
      --symbols             Shows symbols [ELF]
      --set <option>        Sets options. Available options: aslr nx
      --unset <option>      Unsets options. Available options: aslr nx
      -I <imagebase>        Uses this imagebase for gadgets
      -p, --ppr             Searches for 'pop reg; pop reg; ret' instructions
                            [only x86/x86_64]
      -j <reg>, --jmp <reg>
                            Searches for 'jmp reg' instructions (-j reg[,reg...])
                            [only x86/x86_64]
      --depth <n bytes>     Specifies the depth of search (default: 10)
      --search <regex>      Searches for gadgets
      --filter <regex>      Filters gadgets
      --opcode <opcode>     Searches for opcodes
      --type <type>         Sets the type of gadgets [rop, jop, all] (default:
                            all)
      --detail              Prints gadgets more detailed
      --chain <generator>   Generates a ropchain [generator=parameter]
      -b <badbytes>, --badbytes <badbytes>
                            Set bytes which should not contains in gadgets
      --nocolor             Disables colored output

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
      ropper.py --file /bin/ls --search "sub eax" --badbytes 000a0d
      ropper.py --file /bin/ls --search "sub eax" --detail
      ropper.py --file /bin/ls --filter "sub eax"
      ropper.py --file /bin/ls --depth 5 --filter "sub eax"
      ropper.py --file /bin/ls --opcode ffe4
      ropper.py --file /bin/ls --detail
      ropper.py --file /bin/ls --ppr --nocolor
      ropper.py --file /bin/ls --jmp esp,eax
      ropper.py --file /bin/ls --type jop
      ropper.py --file /bin/ls --arch x86_64
      ropper.py --file /bin/ls --chain execve=/bin/sh
      ropper.py --file /bin/ls --chain execve=/bin/sh --badbytes 000a0d
      ropper.py --file /bin/ls --chain mprotect=0xbfdff000:0x21000






Planned features for future versions
------------------------------------
  File formats:
    - Raw

  Edit header fields
  Print more informations

  For any other ideas please contact me



Project page
------------------------------------
http://scoding.de/ropper
