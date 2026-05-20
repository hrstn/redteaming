"""Unit tests for all encryption primitives."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules import crypto


SAMPLE = b'\x00\x01\x02Hello, shellcode!\xff\xfe\xfd' * 4


class TestXOR(unittest.TestCase):
    def test_single_byte_key(self):
        key = b'\xaa'
        ct = crypto.xor_encrypt(SAMPLE, key)
        self.assertNotEqual(ct, SAMPLE)
        self.assertEqual(crypto.xor_decrypt(ct, key), SAMPLE)

    def test_multi_byte_key(self):
        key = b'\xde\xad\xbe\xef'
        ct = crypto.xor_encrypt(SAMPLE, key)
        self.assertEqual(crypto.xor_decrypt(ct, key), SAMPLE)

    def test_symmetric(self):
        key = os.urandom(16)
        self.assertEqual(crypto.xor_crypt(crypto.xor_crypt(SAMPLE, key), key), SAMPLE)

    def test_empty_key_raises(self):
        with self.assertRaises(ValueError):
            crypto.xor_encrypt(SAMPLE, b'')

    def test_all_zero_key(self):
        key = bytes(16)
        self.assertEqual(crypto.xor_encrypt(SAMPLE, key), SAMPLE)


class TestRC4(unittest.TestCase):
    def test_roundtrip(self):
        key = b'SecretKey'
        ct = crypto.rc4_encrypt(SAMPLE, key)
        self.assertNotEqual(ct, SAMPLE)
        self.assertEqual(crypto.rc4_decrypt(ct, key), SAMPLE)

    def test_random_key(self):
        key = os.urandom(16)
        ct = crypto.rc4_encrypt(SAMPLE, key)
        self.assertEqual(crypto.rc4_decrypt(ct, key), SAMPLE)

    def test_empty_key_raises(self):
        with self.assertRaises(ValueError):
            crypto.rc4_encrypt(SAMPLE, b'')

    def test_known_vector(self):
        # RFC 6229-style: Key "Key", plaintext "Plaintext"
        key = b'Key'
        pt = b'Plaintext'
        ct = crypto.rc4_encrypt(pt, key)
        self.assertEqual(crypto.rc4_decrypt(ct, key), pt)


class TestROT(unittest.TestCase):
    def test_rot13_roundtrip(self):
        ct = crypto.rot_encrypt(SAMPLE, 13)
        self.assertEqual(crypto.rot_decrypt(ct, 13), SAMPLE)

    def test_rot255_roundtrip(self):
        ct = crypto.rot_encrypt(SAMPLE, 255)
        self.assertEqual(crypto.rot_decrypt(ct, 255), SAMPLE)

    def test_rot0_identity(self):
        self.assertEqual(crypto.rot_encrypt(SAMPLE, 0), SAMPLE)

    def test_byte_wraparound(self):
        data = bytes([200, 250, 10])
        ct = crypto.rot_encrypt(data, 100)
        self.assertEqual(crypto.rot_decrypt(ct, 100), data)

    def test_inverse_is_decrypt(self):
        n = 42
        ct = crypto.rot_encrypt(SAMPLE, n)
        # Inverse ROT: n_inv = (256 - n) % 256
        n_inv = (256 - n) % 256
        self.assertEqual(crypto.rot_encrypt(ct, n_inv), SAMPLE)


class TestAES256(unittest.TestCase):
    def setUp(self):
        try:
            from Crypto.Cipher import AES
            self.aes_available = True
        except ImportError:
            self.aes_available = False

    def test_roundtrip(self):
        if not self.aes_available:
            self.skipTest("pycryptodome not installed")
        key = os.urandom(32)
        iv = os.urandom(16)
        ct = crypto.aes256_cbc_encrypt(SAMPLE, key, iv)
        self.assertNotEqual(ct, SAMPLE)
        self.assertEqual(crypto.aes256_cbc_decrypt(ct, key, iv), SAMPLE)

    def test_short_key_stretched(self):
        if not self.aes_available:
            self.skipTest("pycryptodome not installed")
        key = b'short'
        iv = os.urandom(16)
        ct = crypto.aes256_cbc_encrypt(SAMPLE, key, iv)
        self.assertEqual(crypto.aes256_cbc_decrypt(ct, key, iv), SAMPLE)

    def test_wrong_key_fails(self):
        if not self.aes_available:
            self.skipTest("pycryptodome not installed")
        key = os.urandom(32)
        iv = os.urandom(16)
        ct = crypto.aes256_cbc_encrypt(SAMPLE, key, iv)
        wrong_key = os.urandom(32)
        with self.assertRaises(Exception):
            crypto.aes256_cbc_decrypt(ct, wrong_key, iv)


class TestParseKey(unittest.TestCase):
    def test_hex_single_byte(self):
        self.assertEqual(crypto.parse_key('0xAA'), b'\xaa')

    def test_hex_multi_byte(self):
        self.assertEqual(crypto.parse_key('0xDEADBEEF'), b'\xde\xad\xbe\xef')

    def test_plaintext(self):
        self.assertEqual(crypto.parse_key('hello'), b'hello')

    def test_odd_hex_length(self):
        # 0xA -> 0x0A
        self.assertEqual(crypto.parse_key('0xA'), b'\x0a')


if __name__ == '__main__':
    unittest.main()
