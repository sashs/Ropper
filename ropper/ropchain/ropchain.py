# coding=utf-8
# Copyright 2018 Sascha Schirra
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" A ND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
from ropper.common.abstract import *
from ropper.common.error import *
from ropper.common.utils import *

class RopChain(Abstract):

    def __init__(self, binaries, gadgets, callback, badbytes=''):

        self._binaries = binaries
        self._usedBinaries = []
        self.__callback = callback
        self._gadgets = gadgets
        self.__badbytes = badbytes


    @property
    def badbytes(self):
        return self.__badbytes

    @abstractmethod
    def create(self, options):
        pass

    def _updateUsedBinaries(self,gadget):
        if (gadget.fileName, gadget._section) not in self._usedBinaries:
            self._usedBinaries.append((gadget.fileName, gadget._section))

    @classmethod
    def name(cls):
        return None

    @classmethod
    def availableGenerators(cls):
        return []

    @classmethod
    def archs(self):
        return []


    @classmethod
    def usableTypes(self):
        return ()

    @classmethod
    def getUsableBinaries(cls, binaries):
        to_return = []
        for binary in binaries:
            if isinstance(binary, cls.usableTypes()):
                to_return.append(binary)

        return to_return

    @classmethod
    def get(cls, binaries, gadgets, name, callback, badbytes=''):
        for subclass in cls.__subclasses__():
            if binaries[0].arch in subclass.archs():
                gens = subclass.availableGenerators()
                for gen in gens:
                    if gen.name() == name:
                        ub = gen.getUsableBinaries(binaries)
                        if ub:
                            return gen(ub, gadgets, callback, badbytes)
                        else:
                            filetypes = set([str(b.type) for b in binaries])
                            raise RopperError('The generator {} is not useable for the filetypes: {}'.format(name, ', '.join(filetypes)))


    def containsBadbytes(self, value, bytecount=4):
        for b in self.badbytes:
            tmp = value


            if type(b) == str:
                b = ord(b)

            for i in range(bytecount):
                if (tmp & 0xff) == b:
                    return True

                tmp >>= 8
        return False

    def _printMessage(self, message):
        if self.__callback:
            self.__callback(message)

    # ------------------------------------------------------------------
    # Shared symbol / string resolution helpers.
    #
    # These are best-effort and defensive: they only work for ELF binaries
    # whose inner filebytes object exposes sections/symbols/relocations, and
    # they degrade to ``None`` for every other file type rather than raising.
    # ret2libc generators (spawn_shell) use them to auto-resolve the address
    # of ``system`` and a ``"/bin/sh"`` pointer where the binary makes that
    # possible, falling back to clearly-labelled placeholders otherwise.
    # ------------------------------------------------------------------
    def _findSymbolAddress(self, name):
        """Return the virtual address of a *defined* symbol ``name`` from the
        primary binary's ``.symtab``/``.dynsym``, or ``None``.

        Only symbols that are actually defined inside this file are returned
        (``st_value`` set and ``st_shndx`` not ``SHN_UNDEF``); imported
        (undefined) symbols are reported via :meth:`_findImportGotSlot`
        instead.  This resolves e.g. libc ``system`` for statically linked or
        non-stripped binaries."""
        binary = self._binaries[0]
        inner = getattr(binary, '_binary', None)
        sections = getattr(inner, 'sections', None)
        if not sections:
            return None
        try:
            for section in sections:
                if getattr(section, 'name', '') in ('.symtab', '.dynsym'):
                    for sym in section.symbols:
                        if sym.name == name and sym.header.st_value and sym.header.st_shndx:
                            return sym.header.st_value
        except BaseException:
            return None
        return None

    def _findImportGotSlot(self, name):
        """Return the GOT slot virtual address for an imported symbol ``name``
        (the ``r_offset`` of its PLT/GOT relocation), or ``None``.

        This does not resolve the runtime address of the function (that lives
        in a shared library), but the slot address is a useful hint and proves
        the symbol is imported through the PLT."""
        binary = self._binaries[0]
        inner = getattr(binary, '_binary', None)
        sections = getattr(inner, 'sections', None)
        if not sections:
            return None
        try:
            for section in sections:
                relocs = getattr(section, 'relocations', None)
                if not relocs:
                    continue
                for reloc in relocs:
                    sym = getattr(reloc, 'symbol', None)
                    if sym is not None and sym.name == name:
                        return reloc.header.r_offset
        except BaseException:
            return None
        return None

    def _findPltStub(self, name):
        """Return the virtual address of the PLT stub for the imported symbol
        ``name`` (i.e. ``name@plt`` -- the address a ret2plt chain jumps to), or
        ``None``.

        The stub is found by disassembling the binary's PLT sections and
        locating the entry whose indirect jump *provably* dereferences
        ``name``'s GOT slot.  Because the match is verified against the actual
        relocation target, this never returns a silently-wrong address: if the
        layout cannot be parsed (stripped PLT, x86 PIE ``jmp [ebx+off]`` whose
        GOT base is unknown at rest, unsupported arch) it returns ``None`` and
        the caller falls back to a hint + placeholder."""
        got = self._findImportGotSlot(name)
        if got is None:
            return None
        binary = self._binaries[0]
        arch = getattr(binary, 'arch', None)
        try:
            from capstone import Cs, CS_OP_MEM, CS_OP_IMM, CS_ARCH_ARM
            md = Cs(arch._arch, arch._mode)
            md.detail = True
        except BaseException:
            return None

        sections = []
        for sname in ('.plt.sec', '.plt', '.plt.got'):
            try:
                sections.append(binary.getSection(sname))
            except BaseException:
                pass
        if not sections:
            return None

        is_arm = (arch._arch == CS_ARCH_ARM)
        for section in sections:
            try:
                code = bytes(bytearray(section.bytes))
                if is_arm:
                    stub = self._scanPltArm(md, code, section.virtualAddress, got, CS_OP_MEM, CS_OP_IMM)
                else:
                    stub = self._scanPltX86(md, code, section.virtualAddress, got, CS_OP_MEM)
            except BaseException:
                stub = None
            if stub is not None:
                return stub
        return None

    def _scanPltX86(self, md, code, base, got, CS_OP_MEM):
        """Find an x86/x86_64 PLT entry whose ``jmp [mem]`` targets ``got``.
        Returns the entry's virtual address (preferring the ``endbr`` landing
        pad of a ``.plt.sec`` entry when present)."""
        prev = None
        for insn in md.disasm(code, base):
            if 'jmp' in insn.mnemonic and insn.operands:
                op = insn.operands[0]
                if op.type == CS_OP_MEM:
                    base_name = md.reg_name(op.mem.base) if op.mem.base else None
                    target = None
                    if base_name == 'rip':            # x86_64 RIP-relative
                        target = insn.address + insn.size + op.mem.disp
                    elif base_name is None:           # x86 absolute (non-PIE)
                        target = op.mem.disp & 0xffffffff
                    # base_name == 'ebx'/'rbx' (PIE) -> GOT base unknown, skip
                    if target is not None and target == got:
                        if (prev is not None and prev.mnemonic in ('endbr64', 'endbr32')
                                and prev.address + prev.size == insn.address):
                            return prev.address
                        return insn.address
            prev = insn
        return None

    def _armAddImmediate(self, ops, CS_OP_IMM):
        """Value added by an ARM ``add`` immediate form.  GAS/capstone render a
        rotated modified-immediate as two operands ``#imm, #rot`` (value =
        ``imm`` rotated right by ``rot``, as the PLT's ``add ip, pc, #0, #12``);
        a plain ``add ip, ip, #8`` has a single immediate operand."""
        imms = [o.imm & 0xffffffff for o in ops[2:] if o.type == CS_OP_IMM]
        if not imms:
            return None
        if len(imms) == 1:
            return imms[0]
        value, rot = imms[0], imms[1] & 31
        if rot == 0:
            return value
        return ((value >> rot) | (value << (32 - rot))) & 0xffffffff

    def _scanPltArm(self, md, code, base, got, CS_OP_MEM, CS_OP_IMM):
        """Find an ARM PLT entry of the form
        ``add ip, pc, #imm ; [add ip, ip, #imm ;] ldr pc, [ip, #imm]!`` whose
        effective GOT dereference equals ``got``.  Returns the address of the
        leading ``add ip, pc`` (the stub entry point)."""
        IP = ('ip', 'r12')
        PC = ('pc', 'r15')
        ip = None
        entry_start = None
        for insn in md.disasm(code, base):
            m = insn.mnemonic
            ops = insn.operands
            if (m.startswith('add') and len(ops) >= 3
                    and md.reg_name(ops[0].reg) in IP):
                src = md.reg_name(ops[1].reg)
                val = self._armAddImmediate(ops, CS_OP_IMM)
                if val is None:
                    ip, entry_start = None, None
                elif src in PC:                       # ARM PC reads as addr + 8
                    ip = insn.address + 8 + val
                    entry_start = insn.address
                elif src in IP and ip is not None:
                    ip += val
                else:
                    ip, entry_start = None, None
            elif m.startswith('ldr') and ip is not None and ops:
                if (md.reg_name(ops[0].reg) in PC and len(ops) > 1
                        and ops[1].type == CS_OP_MEM and md.reg_name(ops[1].mem.base) in IP):
                    if ((ip + ops[1].mem.disp) & 0xffffffff) == got and entry_start is not None:
                        return entry_start
                ip, entry_start = None, None
        return None

    def _findExistingString(self, text):
        """Return the virtual address of an existing occurrence of ``text`` in
        the primary binary, or ``None``."""
        binary = self._binaries[0]
        try:
            results = binary.searchString(text)
        except BaseException:
            return None
        if results:
            return results[0][0]
        return None

    def _useBinaryForRebase(self, binary=None):
        """Ensure ``binary`` (default: the primary binary) is registered in
        ``_usedBinaries`` and return its ``rebase_N`` index.

        Gadget selection normally registers a binary as a side effect, but a
        ret2libc chain may need to rebase an address (a resolved symbol, a
        ``.data`` buffer) without having selected any gadget from that binary
        yet.  Rebasing only depends on the file (image base), not the section,
        so an existing entry for the same file is reused when present."""
        binary = binary or self._binaries[0]
        for idx, (fileName, _section) in enumerate(self._usedBinaries):
            if fileName == binary.checksum:
                return idx
        section = binary.executableSections[0]
        self._usedBinaries.append((binary.checksum, section))
        return len(self._usedBinaries) - 1

    # ------------------------------------------------------------------
    # ret2libc (spawn_shell) building blocks shared by every architecture.
    #
    # Architectures differ only in address width and in how a string is
    # written into ``.data`` (the gadget primitives differ), so those two
    # pieces are exposed as overridable hooks and everything else is generic.
    # ------------------------------------------------------------------
    def _addressWidth(self):
        """Address width in bytes for hex formatting (4 = 32-bit default)."""
        return 4

    def _writeCmdToData(self, cmd, dataaddr):
        """Return a chain fragment that writes the NUL-terminated ``cmd`` into
        the binary at ``dataaddr``.  Architecture bases override this; the
        default signals that no write strategy is available."""
        raise RopChainError('No .data-write strategy for this architecture')

    def _rebaseLine(self, vaddr, comment):
        """Emit a ``rop += rebase_N(offset) # comment`` line for an address
        that lives *inside* the analysed binary (so it follows ASLR via the
        existing ``rebase_N`` lambdas)."""
        idx = self._useBinaryForRebase()
        off = vaddr - self._binaries[0].imageBase
        return 'rop += rebase_%d(%s) # %s\n' % (idx, toHex(off, self._addressWidth()), comment)

    def _resolveBinshPointer(self, cmd, string):
        """Resolve a pointer to the command string for a ret2libc chain.

        Returns ``(chain_line, definitions, write_fragment)`` where
        ``chain_line`` is the ``rop += ...`` line that yields the pointer,
        ``definitions`` is any ``NAME = 0x..`` preamble it references, and
        ``write_fragment`` is chain text that must run earlier to populate the
        buffer (empty unless the string is written into ``.data``).

        Precedence: explicit ``string=`` address > write ``cmd`` into ``.data``
        > an existing copy already present in the binary > placeholder."""
        width = self._addressWidth()
        if string is not None:
            value = int(string, 16) if isinstance(string, str) else string
            defs = 'BINSH_ADDR = %s # address of "%s" (supplied)\n' % (toHex(value, width), cmd)
            return ('rop += p(BINSH_ADDR)\n', defs, '')

        try:
            section = self._binaries[0].getSection('.data')
            dataaddr = section.offset
            write_text = self._writeCmdToData(cmd, dataaddr)
            self._printMessage('Writing "%s" into .data at %s' % (cmd, toHex(section.virtualAddress, width)))
            # Address the buffer with the SAME rebase convention the write uses
            # (rebase_N(section.offset)), so the pointer and the written bytes
            # always coincide -- including under a manually overridden image
            # base.  Do NOT route through _rebaseLine(), which expects an
            # absolute virtual address and would subtract the image base a
            # second time from this already-relative offset.
            idx = self._useBinaryForRebase()
            line = 'rop += rebase_%d(%s) # "%s" (written to .data)\n' % (idx, toHex(dataaddr, width), cmd)
            return (line, '', write_text)
        except RopChainError as e:
            self._printMessage('Cannot write command into .data: %s' % e)

        found = self._findExistingString(cmd)
        if found is not None:
            self._printMessage('Found existing "%s" at %s' % (cmd, toHex(found, width)))
            return (self._rebaseLine(found, '"%s" (found in binary)' % cmd), '', '')

        self._printMessage('Could not resolve a pointer to "%s"; using placeholder BINSH_ADDR.' % cmd)
        defs = 'BINSH_ADDR = 0x41414141 # TODO: set address of "%s"\n' % cmd
        return ('rop += p(BINSH_ADDR)\n', defs, '')

    def _resolveSystemAddress(self, address):
        """Resolve the address of libc ``system()`` for a ret2libc chain.

        Returns ``(chain_line, definitions)``.  Precedence: explicit
        ``address=`` (absolute, not rebased) > a ``system`` symbol defined in
        this binary (rebased) > an import hint plus placeholder > placeholder."""
        width = self._addressWidth()
        if address is not None:
            value = int(address, 16) if isinstance(address, str) else address
            defs = 'SYSTEM_ADDR = %s # libc system() (supplied)\n' % toHex(value, width)
            return ('rop += p(SYSTEM_ADDR)\n', defs)

        sym = self._findSymbolAddress('system')
        if sym is not None:
            self._printMessage('Resolved system() from symbol table at %s' % toHex(sym, width))
            return (self._rebaseLine(sym, 'system()'), '')

        plt = self._findPltStub('system')
        if plt is not None:
            self._printMessage('Resolved system@plt at %s (verified against its GOT slot).'
                               % toHex(plt, width))
            return (self._rebaseLine(plt, 'system@plt'), '')

        got = self._findImportGotSlot('system')
        if got is not None:
            self._printMessage('system() is imported via PLT (GOT slot at %s) but its stub '
                               'could not be auto-resolved.' % toHex(got, width))
            self._printMessage('Pass address=<runtime libc system() or system@plt>.')
            defs = ('SYSTEM_ADDR = 0xdeadbeef # TODO: libc system() '
                    '(imported via PLT; GOT slot at %s)\n' % toHex(got, width))
            return ('rop += p(SYSTEM_ADDR)\n', defs)

        self._printMessage('Could not resolve system(); using placeholder SYSTEM_ADDR.')
        defs = 'SYSTEM_ADDR = 0xdeadbeef # TODO: set libc system() address\n'
        return ('rop += p(SYSTEM_ADDR)\n', defs)
