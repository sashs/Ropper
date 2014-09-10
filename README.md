Ropper
================

With ropper you can show information about files in different file formats
and you can search for gadgets to build rop chains for different architectures. For disassembly ropper uses the
awesome Capstone Framework.

Install
-------

Download and Install Capstone

    $ wget http://www.capstone-engine.org/download/2.1.2/capstone-2.1.2.tgz
    $ tar xf capstone-2.1.2.tgz
    $ cd capstone-2.1.2
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

    usage: ropper.py [-h] [-v] [--console] [-f <file>] [-i] [-e] [--imagebase]
                       [-c] [-s] [-S] [--imports] [--symbols] [--set <option>]
                       [--unset <option>] [-I <imagebase>] [-p] [-j <reg>]
                       [--depth <n bytes>] [--search <regex>] [--filter <regex>]
                       [--opcode <opcode>] [--type <type>] [--detail]

          With ropper you can show information about files in different file formats
          and you can find gadgets to build rop chains for different architectures.

          supported filetypes:
            ELF
            PE
            Mach-O

          supported architectures:
            x86
            x86_64
            MIPS
            ARM
            ARM64

          optional arguments:
            -h, --help            show this help message and exit
            -v, --version         Print version
            --console             Starts interactive commandline
            -f <file>, --file <file>
                                  The file to load
            -i, --info            Shows file header [ELF/PE/Mach-O]
            -e                    Shows EntryPoint
            --imagebase           Shows ImageBase [ELF/PE/Mach-O]
            -c, --dllcharacteristics
                                  Shows DllCharacteristics [PE]
            -s, --sections        Shows file sections [ELF/PE/Mach-O]
            -S, --segments        Shows file segments [ELF/Mach-O]
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



Planned features for future versions
------------------------------------
  Architectures:
- PowerPC-Support
- ARM Thumb Support

  File formats:
- Raw


  ropchain generator

Project page
------------------------------------
http://scoding.de/ropper
