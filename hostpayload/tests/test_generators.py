"""Unit tests verifying generator output structure for all formats."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.chain import apply_chain, build_single_stage
from modules.generators import ps1, vba, cs, aspx, raw

SHELLCODE = b'\x90' * 64 + b'\xcc' * 16   # NOP sled + INT3 (safe for testing)


def _xor_meta():
    _, meta = apply_chain(SHELLCODE, [build_single_stage('xor', key=b'\xaa')])
    ct, meta = apply_chain(SHELLCODE, [build_single_stage('xor', key=b'\xaa')])
    return ct, meta


def _rc4_meta():
    ct, meta = apply_chain(SHELLCODE, [build_single_stage('rc4', key=b'TestRC4Key')])
    return ct, meta


def _rot_meta():
    ct, meta = apply_chain(SHELLCODE, [build_single_stage('rot', rot_n=13)])
    return ct, meta


class TestPS1Generator(unittest.TestCase):
    def test_xor_output_contains_amsi(self):
        ct, meta = _xor_meta()
        out = ps1.generate(ct, meta, enable_obfuscation=False)
        self.assertIn('Amsi', out)

    def test_output_is_string(self):
        ct, meta = _xor_meta()
        out = ps1.generate(ct, meta, enable_obfuscation=False)
        self.assertIsInstance(out, str)

    def test_contains_shellcode_bytes(self):
        ct, meta = _xor_meta()
        out = ps1.generate(ct, meta, enable_obfuscation=False)
        # Encrypted bytes should appear as 0xNN hex literals
        self.assertRegex(out, r'0x[0-9A-Fa-f]{2}')

    def test_contains_virtualalloc(self):
        ct, meta = _xor_meta()
        out = ps1.generate(ct, meta, enable_obfuscation=False)
        self.assertIn('VirtualAlloc', out)

    def test_rc4_contains_rc4_function(self):
        ct, meta = _rc4_meta()
        out = ps1.generate(ct, meta, enable_obfuscation=False)
        # RC4 decryption stub should contain PRGA pattern
        self.assertIn('-bxor', out)

    def test_debug_output(self):
        ct, meta = _xor_meta()
        out = ps1.generate(ct, meta, enable_obfuscation=False, enable_debug=True)
        self.assertIn('DEBUG', out)

    def test_obfuscated_output_larger(self):
        ct, meta = _xor_meta()
        clean = ps1.generate(ct, meta, enable_obfuscation=False)
        obfusc = ps1.generate(ct, meta, enable_obfuscation=True, obfuscation_level=2)
        self.assertGreater(len(obfusc), len(clean))


class TestVBAGenerator(unittest.TestCase):
    def test_xor_output(self):
        ct, meta = _xor_meta()
        out = vba.generate(ct, meta)
        self.assertIn('VirtualAlloc', out)
        self.assertIn('CreateThread', out)
        self.assertIn('AutoOpen', out)

    def test_rc4_output(self):
        ct, meta = _rc4_meta()
        out = vba.generate(ct, meta)
        # RC4 VBA stub contains the PRGA XOR pattern
        self.assertIn('XOR S(', out.upper())

    def test_win64_ptrSafe(self):
        ct, meta = _xor_meta()
        out = vba.generate(ct, meta)
        self.assertIn('PtrSafe', out)

    def test_aes_raises(self):
        meta = [{'algo': 'aes256', 'key': b'\x00'*32, 'iv': b'\x00'*16}]
        ct = b'\x00' * 32
        with self.assertRaises(ValueError):
            vba.generate(ct, meta)

    def test_contains_byte_array(self):
        ct, meta = _xor_meta()
        out = vba.generate(ct, meta)
        # Should contain numeric byte values
        self.assertRegex(out, r'\d+,\s*\d+')


class TestCSGenerator(unittest.TestCase):
    def test_valloc_output(self):
        ct, meta = _xor_meta()
        out = cs.generate(ct, meta, injection_method='valloc')
        self.assertIn('VirtualAlloc', out)
        self.assertIn('CreateThread', out)
        self.assertIn('static void Main', out)

    def test_pinject_output(self):
        ct, meta = _xor_meta()
        out = cs.generate(ct, meta, injection_method='pinject')
        self.assertIn('OpenProcess', out)
        self.assertIn('CreateRemoteThread', out)

    def test_ntinject_output(self):
        ct, meta = _rot_meta()
        out = cs.generate(ct, meta, injection_method='ntinject')
        self.assertIn('NtCreateSection', out)
        self.assertIn('RtlCreateUserThread', out)

    def test_hollow_output(self):
        ct, meta = _xor_meta()
        out = cs.generate(ct, meta, injection_method='hollow')
        self.assertIn('CreateProcess', out)
        self.assertIn('ResumeThread', out)

    def test_unknown_method_raises(self):
        ct, meta = _xor_meta()
        with self.assertRaises(ValueError):
            cs.generate(ct, meta, injection_method='magic')

    def test_cs_compiles_structure(self):
        ct, meta = _xor_meta()
        out = cs.generate(ct, meta)
        self.assertIn('using System;', out)
        self.assertIn('static void Main', out)
        self.assertIn('namespace', out)

    def test_target_process_appears_in_pinject(self):
        ct, meta = _xor_meta()
        out = cs.generate(ct, meta, injection_method='pinject', target_process='notepad')
        self.assertIn('notepad', out)


class TestASPXGenerator(unittest.TestCase):
    def test_xor_output(self):
        ct, meta = _xor_meta()
        out = aspx.generate(ct, meta)
        self.assertIn('Page_Load', out)
        self.assertIn('VirtualAlloc', out)

    def test_rot_output(self):
        ct, meta = _rot_meta()
        out = aspx.generate(ct, meta)
        self.assertIn('Page_Load', out)

    def test_rc4_raises(self):
        ct, meta = _rc4_meta()
        with self.assertRaises(ValueError):
            aspx.generate(ct, meta)

    def test_aes_raises(self):
        meta = [{'algo': 'aes256', 'key': b'\x00'*32, 'iv': b'\x00'*16}]
        ct = b'\x00' * 48
        with self.assertRaises(ValueError):
            aspx.generate(ct, meta)

    def test_aspx_header(self):
        ct, meta = _xor_meta()
        out = aspx.generate(ct, meta)
        self.assertIn('<%@ Page', out)


class TestRawGenerator(unittest.TestCase):
    def test_passthrough(self):
        ct, _ = _xor_meta()
        result = raw.generate(ct)
        self.assertEqual(result, ct)

    def test_returns_bytes(self):
        ct, _ = _xor_meta()
        result = raw.generate(ct)
        self.assertIsInstance(result, bytes)


if __name__ == '__main__':
    unittest.main()
