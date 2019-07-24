#!/usr/bin/env python
from ropper import RopperService

# not all options need to be given
options = {'color' : False,     # if gadgets are printed, use colored output: default: False
            'badbytes': '00',   # bad bytes which should not be in addresses or ropchains; default: ''
            'all' : False,      # Show all gadgets, this means to not remove double gadgets; default: False
            'inst_count' : 6,   # Number of instructions in a gadget; default: 6
            'type' : 'all',     # rop, jop, sys, all; default: all
            'detailed' : False} # if gadgets are printed, use detailed output; default: False

rs = RopperService(options)

##### change options ######
rs.options.color = True
rs.options.badbytes = '00'
rs.options.badbytes = ''
rs.options.all = True


##### open binaries ######
# it is possible to open multiple files
rs.addFile('test-binaries/ls-x86')
rs.addFile('ls', bytes=open('test-binaries/ls-x86','rb').read()) # other possiblity
rs.addFile('ls_raw', bytes=open('test-binaries/ls-x86','rb').read(), raw=True, arch='x86')

##### close binaries ######
rs.removeFile('ls')
rs.removeFile('ls_raw')


# Set architecture of a binary, so it is possible to look for gadgets for a different architecture
# It is useful for ARM if you want to look for ARM gadgets or Thumb gadgets
# Or if you opened a raw file
ls = 'test-binaries/ls-x86'
rs.setArchitectureFor(name=ls, arch='x86')
rs.setArchitectureFor(name=ls, arch='x86_64')
rs.setArchitectureFor(name=ls, arch='ARM')
rs.setArchitectureFor(name=ls, arch='ARMTHUMB')
rs.setArchitectureFor(name=ls, arch='ARM64')
rs.setArchitectureFor(name=ls, arch='MIPS')
rs.setArchitectureFor(name=ls, arch='MIPS64')
rs.setArchitectureFor(name=ls, arch='PPC')
rs.setArchitectureFor(name=ls, arch='PPC64')
rs.setArchitectureFor(name=ls, arch='SPARC64')
rs.setArchitectureFor(name=ls, arch='x86')


##### load gadgets ######

# load gadgets for all opened files
rs.loadGadgetsFor() 

# load gadgets for only one opened file
ls = 'test-binaries/ls-x86'
rs.loadGadgetsFor(name=ls)

# change gadget type
rs.options.type = 'jop'
rs.loadGadgetsFor() 

rs.options.type = 'rop'
rs.loadGadgetsFor() 

# change instruction count
rs.options.inst_count = 10
rs.loadGadgetsFor() 

##### print gadgets #######
rs.printGadgetsFor() # print all gadgets
rs.printGadgetsFor(name=ls)

##### Get gadgets ######
gadgets = rs.getFileFor(name=ls).gadgets


##### search pop pop ret ######
pprs = rs.searchPopPopRet(name=ls) # looks for ppr only in 'test-binaries/ls-x86'
pprs = rs.searchPopPopRet()        # looks for ppr in all opened files
for file, ppr in pprs.items():
    for p in ppr:
        print(p)

##### load jmp reg ######
jmp_regs = rs.searchJmpReg(name=ls, regs=['esp', 'eax']) # looks for jmp reg only in 'test-binaries/ls-x86'
jmp_regs = rs.searchJmpReg(regs=['esp', 'eax'])
jmp_regs = rs.searchJmpReg()                             # looks for jmp esp in all opened files
for file, jmp_reg in jmp_regs.items():
    for j in jmp_reg:
        print(j)


##### search opcode ######
ls = 'test-binaries/ls-x86'
gadgets_dict = rs.searchOpcode(opcode='ffe4', name=ls)
gadgets_dict = rs.searchOpcode(opcode='ffe?')
gadgets_dict = rs.searchOpcode(opcode='??e4')

for file, gadgets in gadgets_dict.items():
    for g in gadgets:
        print(g)

##### search instructions ######
ls = 'test-binaries/ls-x86'
for file, gadget in rs.search(search='mov e?x', name=ls):
    print(file, gadget)

for file, gadget in rs.search(search='mov [e?x%]'):
    print(file, gadget)

result_dict = rs.searchdict(search='mov eax')
for file, gadgets in result_dict.items():
    print(file)
    for gadget in gadgets:
        print(gadget)

##### assemble instructions ######
hex_string = rs.asm('jmp esp')
print('"jmp esp" assembled to hex string =', hex_string)
raw_bytes = rs.asm('jmp esp', format='raw')
print('"jmp esp" assembled to raw bytes =', raw_bytes)
string = rs.asm('jmp esp', format='string')
print('"jmp esp" assembled to string =', string)
arm_bytes = rs.asm('bx sp', arch='ARM')
print('"bx sp" assembled to hex string =', arm_bytes)

##### disassemble bytes #######
arm_instructions = rs.disasm(arm_bytes, arch='ARM')
print(arm_bytes, 'disassembled to "%s"' % arm_instructions)

# Change the imagebase, this also change the imagebase for all loaded gadgets of this binary
rs.setImageBaseFor(name=ls, imagebase=0x0)

# reset image base
rs.setImageBaseFor(name=ls, imagebase=None)

gadgets = rs.getFileFor(name=ls).gadgets

# gadget address
print(hex(gadgets[0].address))

# get instruction bytes of gadget
print(bytes(gadgets[0].bytes).encode('hex'))

# remove all gadgets containing bad bytes in address
rs.options.badbytes = '000a0d'  # gadgets are filtered automatically
