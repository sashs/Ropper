Ropper
================

You can use ropper to display information about binary files in different file formats
and you can search for gadgets to build rop chains for different architectures (x86/X86_64, ARM/ARM64, MIPS/MIPS64, PowerPC). 
For disassembly ropper uses the awesome [Capstone Framework](http://www.capstone-engine.org).

NOTE: I recommend to use the dev version of ropper, because bugfixes are earlier available in dev branch.

Install
-------

Install [Capstone](http://www.capstone-engine.org) with PyPi:

    $ sudo pip install capstone
    
Install and execute Ropper

    $ python setup.py install
    $ ropper

You can also install Ropper with pip

    $ pip install ropper

If you want, you can use Ropper without installation

    $ ./Ropper.py


Usage
-----

    usage: ropper.py [-h] [-v] [--console] [-f <file>] [--db <dbfile>] [-a <arch>]
                     [--section <section>] [--string [<string>]] [--hex]
                     [--disassemble <address:length>] [-i] [-e] [--imagebase] [-c]
                     [-s] [-S] [--imports] [--symbols] [--set <option>]
                     [--unset <option>] [-I <imagebase>] [-p] [-j <reg>]
                     [--depth <n bytes>] [--search <regex>] [--quality <quality>]
                     [--filter <regex>] [--opcode <opcode>] [--type <type>]
                     [--detail] [--chain <generator>] [-b <badbytes>] [--nocolor]

    You can use ropper to display information about binary files in different file formats
        and you can search for gadgets to build rop chains for different architectures

    supported filetypes:
      ELF
      PE
      Mach-O
      Raw

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
      virtualprotect (virtualprotect=<address iat vp>:<size>) [Windows x86]

    optional arguments:
      -h, --help            show this help message and exit
      -v, --version         Print version
      --console             Starts interactive commandline
      -f <file>, --file <file>
                            The file to load
      --db <dbfile>         The dbfile to load
      -a <arch>, --arch <arch>
                            The architecture of the loaded file
      --section <section>   The data of the this section should be printed
      --string [<string>]   Looks for the string <string> in all data sections
      --hex                 Prints the selected sections in a hex format
      --disassemble <address:length>
                            Disassembles instruction at address <address>
                            (0x12345678:L3). The count of instructions to
                            disassemble can be specified (0x....:L...)
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
      --quality <quality>   The quality for gadgets which are found by search (1 =
                            best)
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
      ropper.py --file /bin/ls --chain execve=/bin/sh
      ropper.py --file /bin/ls --chain execve=/bin/sh --badbytes 000a0d
      ropper.py --file /bin/ls --chain mprotect=0xbfdff000:0x21000

      [Search]
      ?   any character
      %   any string

      Example:

      ropper.py --file /bin/ls --search "mov e?x"
      0x000067f1: mov edx, dword ptr [ebp + 0x14]; mov dword ptr [esp], edx; call eax
      0x00006d03: mov eax, esi; pop ebx; pop esi; pop edi; pop ebp; ret ;
      0x00006d6f: mov ebx, esi; mov esi, dword ptr [esp + 0x18]; add esp, 0x1c; ret ;
      0x000076f8: mov eax, dword ptr [eax]; mov byte ptr [eax + edx], 0; add esp, 0x18; pop ebx; ret ;

      ropper.py --file /bin/ls --search "mov [%], edx"
      0x000067ed: mov dword ptr [esp + 4], edx; mov edx, dword ptr [ebp + 0x14]; mov dword ptr [esp], edx; call eax;
      0x00006f4e: mov dword ptr [ecx + 0x14], edx; add esp, 0x2c; pop ebx; pop esi; pop edi; pop ebp; ret ;
      0x000084b8: mov dword ptr [eax], edx; ret ;
      0x00008d9b: mov dword ptr [eax], edx; add esp, 0x18; pop ebx; ret ;

      ropper.py --file /bin/ls --search "mov [%], edx" --quality 1
      0x000084b8: mov dword ptr [eax], edx; ret ;




Planned features for future versions
------------------------------------

- Edit header fields;
- Print more informations;

For any other ideas please contact me



Project page
------------------------------------
http://scoding.de/ropper


Screenshots
------------------------------------

<img src="https://scoding.de/uploads/load.jpg" alt="load"></img>

<img src="https://scoding.de/uploads/x86.jpg" alt="x86"></img>

<img src="https://scoding.de/uploads/arm.jpg" alt="arm"></img>

<img src="https://scoding.de/uploads/mips.jpg" alt="mips"></img>

<img src="https://scoding.de/uploads/ppc.jpg" alt="ppc"></img>

<img src="https://scoding.de/uploads/ropchain.jpg" alt="ropchain"></img>

<img src="https://scoding.de/uploads/header.jpg" alt="header"></img>

<img src="https://scoding.de/uploads/disass.jpg" alt="disassembler"></img>

<img src="https://scoding.de/uploads/hex.jpg" alt="hex"></img>



