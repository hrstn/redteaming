"""
Encryption primitives: XOR, AES-256-CBC, RC4, ROT-N.
All functions take/return bytes.  XOR and RC4 are symmetric (encrypt == decrypt).
"""

import hashlib
import os


# ---------------------------------------------------------------------------
# XOR
# ---------------------------------------------------------------------------

def xor_crypt(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("XOR key cannot be empty")
    result = bytearray(len(data))
    key_len = len(key)
    for i, byte in enumerate(data):
        result[i] = byte ^ key[i % key_len]
    return bytes(result)


xor_encrypt = xor_crypt   # symmetric
xor_decrypt = xor_crypt


# ---------------------------------------------------------------------------
# RC4
# ---------------------------------------------------------------------------

def rc4_crypt(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("RC4 key cannot be empty")
    # KSA
    S = list(range(256))
    j = 0
    key_bytes = list(key)
    klen = len(key_bytes)
    for i in range(256):
        j = (j + S[i] + key_bytes[i % klen]) % 256
        S[i], S[j] = S[j], S[i]
    # PRGA
    result = bytearray(len(data))
    i = j = 0
    for n, byte in enumerate(data):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        result[n] = byte ^ K
    return bytes(result)


rc4_encrypt = rc4_crypt   # symmetric
rc4_decrypt = rc4_crypt


# ---------------------------------------------------------------------------
# ROT-N  (byte-level Caesar, N in 1..255)
# ---------------------------------------------------------------------------

def rot_encrypt(data: bytes, n: int) -> bytes:
    n = n % 256
    return bytes((b + n) % 256 for b in data)


def rot_decrypt(data: bytes, n: int) -> bytes:
    n = n % 256
    return bytes((b - n + 256) % 256 for b in data)


# ---------------------------------------------------------------------------
# AES-256-CBC  (requires pycryptodome)
# ---------------------------------------------------------------------------

def _aes_import():
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad, unpad
        return AES, pad, unpad
    except ImportError:
        raise ImportError(
            "pycryptodome is required for AES-256-CBC encryption.\n"
            "Install it with:  pip install pycryptodome"
        )


def aes256_cbc_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    AES, pad, _ = _aes_import()
    key32 = _derive_key(key, 32)
    iv16 = _pad_iv(iv)
    cipher = AES.new(key32, AES.MODE_CBC, iv16)
    return cipher.encrypt(pad(data, AES.block_size))


def aes256_cbc_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    AES, _, unpad = _aes_import()
    key32 = _derive_key(key, 32)
    iv16 = _pad_iv(iv)
    cipher = AES.new(key32, AES.MODE_CBC, iv16)
    return unpad(cipher.decrypt(data), AES.block_size)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _derive_key(key: bytes, length: int) -> bytes:
    """Return exactly `length` bytes from key, stretching with SHA-256 if needed."""
    if len(key) >= length:
        return key[:length]
    return hashlib.sha256(key).digest()[:length]


def _pad_iv(iv: bytes) -> bytes:
    if len(iv) >= 16:
        return iv[:16]
    return iv.ljust(16, b'\x00')


def parse_key(key_str: str) -> bytes:
    """Convert CLI key string to bytes.

    Supports:
      0xAA           -> single byte 0xAA
      0xDEADBEEF     -> multi-byte hex
      plain text     -> UTF-8 encoded
    """
    s = key_str.strip()
    if s.lower().startswith('0x'):
        hex_part = s[2:]
        if len(hex_part) % 2 != 0:
            hex_part = '0' + hex_part
        return bytes.fromhex(hex_part)
    return s.encode('utf-8')
