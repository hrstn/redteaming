"""Unit tests for chain orchestrator and decryption stub generators."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.chain import parse_chain_spec, apply_chain, build_single_stage
from modules.chain import decryption_stubs_ps1, decryption_stubs_cs, decryption_stubs_vba
from modules import crypto


PLAINTEXT = b'SHELLCODE_PLACEHOLDER_BYTES\x90\x90\x90\xcc' * 8


class TestParseChainSpec(unittest.TestCase):
    def test_single_xor(self):
        stages = parse_chain_spec('xor:KEY=0xAA')
        self.assertEqual(len(stages), 1)
        self.assertEqual(stages[0]['algo'], 'xor')
        self.assertEqual(stages[0]['params']['KEY'], '0xAA')

    def test_multi_stage(self):
        stages = parse_chain_spec('xor:KEY=0xAA,rc4:KEY=secret,rot:N=13')
        self.assertEqual(len(stages), 3)
        self.assertEqual(stages[0]['algo'], 'xor')
        self.assertEqual(stages[1]['algo'], 'rc4')
        self.assertEqual(stages[2]['algo'], 'rot')

    def test_aes_with_iv(self):
        stages = parse_chain_spec('aes256:KEY=mykey;IV=1234567890abcdef')
        self.assertEqual(stages[0]['algo'], 'aes256')
        self.assertEqual(stages[0]['params']['KEY'], 'mykey')
        self.assertEqual(stages[0]['params']['IV'], '1234567890abcdef')

    def test_no_params(self):
        stages = parse_chain_spec('xor')
        self.assertEqual(stages[0]['algo'], 'xor')
        self.assertEqual(stages[0]['params'], {})


class TestApplyChainRoundtrip(unittest.TestCase):
    def test_xor_roundtrip(self):
        stages = [build_single_stage('xor', key=b'\xde\xad\xbe\xef')]
        ct, meta = apply_chain(PLAINTEXT, stages)
        self.assertNotEqual(ct, PLAINTEXT)
        # Decrypt manually
        pt = crypto.xor_decrypt(ct, meta[0]['key'])
        self.assertEqual(pt, PLAINTEXT)

    def test_rc4_roundtrip(self):
        stages = [build_single_stage('rc4', key=b'TestKey')]
        ct, meta = apply_chain(PLAINTEXT, stages)
        pt = crypto.rc4_decrypt(ct, meta[0]['key'])
        self.assertEqual(pt, PLAINTEXT)

    def test_rot_roundtrip(self):
        stages = [build_single_stage('rot', rot_n=42)]
        ct, meta = apply_chain(PLAINTEXT, stages)
        pt = crypto.rot_decrypt(ct, meta[0]['n'])
        self.assertEqual(pt, PLAINTEXT)

    def test_xor_rot_chain(self):
        stages = parse_chain_spec('xor:KEY=0xBB,rot:N=7')
        ct, meta = apply_chain(PLAINTEXT, stages)
        # Decrypt in reverse
        mid = crypto.rot_decrypt(ct, meta[1]['n'])
        pt  = crypto.xor_decrypt(mid, meta[0]['key'])
        self.assertEqual(pt, PLAINTEXT)

    def test_rc4_xor_chain(self):
        stages = parse_chain_spec('rc4:KEY=hello,xor:KEY=0xDE')
        ct, meta = apply_chain(PLAINTEXT, stages)
        mid = crypto.xor_decrypt(ct, meta[1]['key'])
        pt  = crypto.rc4_decrypt(mid, meta[0]['key'])
        self.assertEqual(pt, PLAINTEXT)

    def test_unknown_algo_raises(self):
        with self.assertRaises(ValueError):
            apply_chain(PLAINTEXT, [{'algo': 'blowfish', 'params': {}}])

    def test_random_key_generated_when_absent(self):
        stages = [{'algo': 'xor', 'params': {}}]
        ct1, meta1 = apply_chain(PLAINTEXT, stages)
        ct2, meta2 = apply_chain(PLAINTEXT, stages)
        # Keys should differ (random)
        self.assertNotEqual(meta1[0]['key'], meta2[0]['key'])


class TestAES256Chain(unittest.TestCase):
    def setUp(self):
        try:
            from Crypto.Cipher import AES
            self.ok = True
        except ImportError:
            self.ok = False

    def test_aes_roundtrip(self):
        if not self.ok:
            self.skipTest("pycryptodome not installed")
        stages = [build_single_stage('aes256', key=b'MyAESKey', iv=os.urandom(16))]
        ct, meta = apply_chain(PLAINTEXT, stages)
        pt = crypto.aes256_cbc_decrypt(ct, meta[0]['key'], meta[0]['iv'])
        self.assertEqual(pt, PLAINTEXT)

    def test_aes_xor_chain(self):
        if not self.ok:
            self.skipTest("pycryptodome not installed")
        stages = parse_chain_spec('aes256:KEY=s3cr3t,xor:KEY=0xCC')
        ct, meta = apply_chain(PLAINTEXT, stages)
        mid = crypto.xor_decrypt(ct, meta[1]['key'])
        pt  = crypto.aes256_cbc_decrypt(mid, meta[0]['key'], meta[0]['iv'])
        self.assertEqual(pt, PLAINTEXT)


class TestDecryptionStubs(unittest.TestCase):
    def _check_ps1_output(self, meta):
        helpers, exec_code = decryption_stubs_ps1(meta)
        self.assertIsInstance(helpers, list)
        self.assertIsInstance(exec_code, str)
        self.assertIn('$encrypted', exec_code)

    def _check_cs_output(self, meta):
        methods, calls = decryption_stubs_cs(meta)
        self.assertIsInstance(methods, str)
        self.assertIsInstance(calls, str)

    def _check_vba_output(self, meta):
        helpers, calls = decryption_stubs_vba(meta)
        self.assertIsInstance(helpers, str)
        self.assertIsInstance(calls, str)

    def test_ps1_xor_stub(self):
        _, meta = apply_chain(PLAINTEXT, [build_single_stage('xor', key=b'\xaa')])
        self._check_ps1_output(meta)

    def test_ps1_rc4_stub(self):
        _, meta = apply_chain(PLAINTEXT, [build_single_stage('rc4', key=b'key')])
        self._check_ps1_output(meta)

    def test_ps1_rot_stub(self):
        _, meta = apply_chain(PLAINTEXT, [build_single_stage('rot', rot_n=13)])
        self._check_ps1_output(meta)

    def test_cs_xor_stub(self):
        _, meta = apply_chain(PLAINTEXT, [build_single_stage('xor', key=b'\xbb')])
        self._check_cs_output(meta)

    def test_cs_rot_stub(self):
        _, meta = apply_chain(PLAINTEXT, [build_single_stage('rot', rot_n=7)])
        self._check_cs_output(meta)

    def test_vba_xor_stub(self):
        _, meta = apply_chain(PLAINTEXT, [build_single_stage('xor', key=b'\xcc')])
        self._check_vba_output(meta)

    def test_vba_rc4_stub(self):
        _, meta = apply_chain(PLAINTEXT, [build_single_stage('rc4', key=b'vbakey')])
        self._check_vba_output(meta)

    def test_vba_aes_raises(self):
        meta = [{'algo': 'aes256', 'key': b'\x00'*32, 'iv': b'\x00'*16}]
        with self.assertRaises(ValueError):
            decryption_stubs_vba(meta)


if __name__ == '__main__':
    unittest.main()
