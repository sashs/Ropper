#!/usr/bin/env python

from ropper import *

##### open a binary ######

binary_elf = Loader.open('test-binaries/ls-x86')
# binary_elf = elf.ELF('test-binaries/ls-x86')
binary_pe = Loader.open('test-binaries/cmd-x86.exe')
# binary_pe = pe.PE('test-binaries/cmd-x86.exe')
binary_macho = Loader.open('test-binaries/ls-macho-x86_64')
# binary_macho = mach_o.MachO('test-binaries/ls-macho-x86_64')
binary_raw = Loader.open('test-binaries/ls-x86', raw=True, arch=x86) # x86, x86_64, ARM, ARMTHUMB, ARM64, PPC, PPC64, MIPS, MIPS64


print binary_elf.type == Type.ELF
print binary_pe.type == Type.PE
print binary_macho.type == Type.MACH_O
print binary_raw.type == Type.RAW

# Set architecture of a binary, so it is possible to look for gadgets for a different architecture
# It is useful for ARM if you want to look for ARM gadgets or Thumb gadgets
# Or if you opened a raw file
binary_elf.arch = x86
binary_elf.arch = x86_64
binary_elf.arch = ARM
binary_elf.arch = ARMTHUMB
binary_elf.arch = ARM64
binary_elf.arch = MIPS
binary_elf.arch = MIPS64
binary_elf.arch = PPC
binary_elf.arch = PPC64
binary_elf.arch = x86


##### load gadgets ######

rop = Ropper()
gadgets = rop.searchGadgets(binary_elf)
gadgets = rop.searchGadgets(binary_elf, gtype=GadgetType.JOP)
gadgets = rop.searchGadgets(binary_pe, gtype=GadgetType.ROP)
gadgets = rop.searchGadgets(binary_elf, instructionCount=5)


##### search pop pop ret ######
pprs = rop.searchPopPopRet(binary_elf)

##### load jmp reg ######
jmp_regs = rop.searchJmpReg(binary_pe, ['esp', 'eax'])

##### search opcode ######
opcode_gadgets = rop.searchOpcode(binary_elf, 'ffe4')
opcode_gadgets = rop.searchOpcode(binary_elf, 'ffe?')
opcode_gadgets = rop.searchOpcode(binary_elf, '??e4')

##### search instructions ######
opcode_gadgets = rop.searchInstructions(binary_elf, 'jmp esp')
opcode_gadgets = rop.searchInstructions(binary_elf, 'pop eax; ret')

##### assemble instructions ######
hex_string = rop.assemble('jmp esp')
print '"jmp esp" assembled to hex string =', hex_string
raw_bytes = rop.assemble('jmp esp', format=FORMAT.RAW)
print '"jmp esp" assembled to raw bytes =', raw_bytes
string = rop.assemble('jmp esp', format=FORMAT.STRING)
print '"jmp esp" assembled to string =',string
arm_bytes = rop.assemble('bx sp', arch=ARM)
print '"bx sp" assembled to hex string =', arm_bytes

##### disassemble bytes #######
arm_instructions = rop.disassemble(arm_bytes, arch=ARM)
print arm_bytes, 'disassembled to "%s"' % arm_instructions

# Change the imagebase, this also change the imagebase for all loaded gadgets of this binary
binary_elf.imageBase = 0x0

# reset image base
binary_elf.imageBase = None

# print a gadget
print gadgets[0]

# print simple
print gadgets[0].simpleString()

# gadget address
print hex(gadgets[0].address)

# get instruction bytes of gadget
print bytes(gadgets[0].bytes).encode('hex')

# search gadgets
found = search(gadgets, 'mov e?x')

# remove all gadgets containing bad bytes in address
withouthBadBytes = filterBadBytes(gadgets, '000a0d')

# delete duplicates
withoutDuplicates = deleteDuplicates(gadgets)

strings = binary_elf.searchDataString('bin%')
for address, string in strings:

    print "0x%x: %s" % (address, string)
