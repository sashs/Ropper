# coding=utf-8
# Tests for the ARM execve ropchain generator.
import unittest

from ropper.service import RopperService
from ropper.common.error import RopperError


_ARM_BINARY = 'test-binaries/ls-arm'


def _generate(arch='ARM', options=None):
    rs = RopperService(options={'all': False, 'type': 'all', 'inst_count': 6})
    rs.addFile(_ARM_BINARY, arch=arch)
    rs.loadGadgetsFor(_ARM_BINARY)
    return rs.createRopChain('execve', arch, options=options or {})


class ARMExecveChain(unittest.TestCase):

    def test_arch_is_supported(self):
        # Before this change, calling --chain execve on ARM raised
        # "ArchitectureArm does not have support for execve chain generation".
        # Confirm createRopChain no longer raises that for ARM.
        try:
            chain = _generate('ARM', {'cmd': '/bin/sh'})
        except RopperError as e:
            self.fail('ARM execve chain raised RopperError: %s' % e)
        self.assertIn('rop = ', chain)

    def test_chain_emits_header_and_rebase(self):
        chain = _generate('ARM', {'cmd': '/bin/sh'})
        self.assertIn("p = lambda x : pack('<I', x)", chain)
        self.assertIn('IMAGE_BASE_0', chain)
        self.assertIn('print(rop)', chain)

    def test_chain_uses_explicit_address(self):
        # When `address=` is given, the chain must not attempt to write the
        # command into .data (that path is the fallback when no address is
        # supplied).
        chain = _generate('ARM',
                          {'cmd': '/bin/sh', 'address': '0xdeadbeef'})
        self.assertNotIn('rop += \'/bin/sh', chain)

    def test_chain_emits_partial_with_todos_when_gadgets_missing(self):
        # /bin/ls (ARM) genuinely lacks an r0-popping gadget and an svc 0
        # gadget.  The generator must emit a partial chain with TODO comments
        # rather than raising.
        chain = _generate('ARM', {'cmd': '/bin/sh', 'address': '0xdeadbeef'})
        self.assertIn('# INSERT SVC 0 GADGET HERE', chain)
        # r1, r2, r7 are loadable from one pop gadget in ls-arm.
        self.assertIn('0x0000000b', chain)  # r7 = 11 (execve syscall number)


if __name__ == '__main__':
    unittest.main()
