#!/usr/bin/env python3
"""
Unit tests for the hostpayload_v2 ChaCha20 + HMAC-SHA256 crypto logic.

Verifies that the Python packer produces a blob the dropper can verify and
decrypt. The dropper uses IETF ChaCha20 (96-bit nonce, 32-bit counter starting
at zero) and HMAC-SHA256 over the ciphertext.
"""

import hashlib
import hmac
import os
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from Crypto.Cipher import ChaCha20
from pack import encrypt_payload


def chacha20_ietf_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Pure-Python IETF ChaCha20 (96-bit nonce) for cross-check."""
    assert len(key) == 32 and len(nonce) == 12
    state_const = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    k = list(struct.unpack("<8I", key))
    n = list(struct.unpack("<3I", nonce))
    counter = 0
    out = bytearray()

    def qr(x, a, b, c, d):
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF
        x[d] ^= x[a]
        x[d] = ((x[d] << 16) | (x[d] >> 16)) & 0xFFFFFFFF
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF
        x[b] ^= x[c]
        x[b] = ((x[b] << 12) | (x[b] >> 20)) & 0xFFFFFFFF
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF
        x[d] ^= x[a]
        x[d] = ((x[d] << 8) | (x[d] >> 24)) & 0xFFFFFFFF
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF
        x[b] ^= x[c]
        x[b] = ((x[b] << 7) | (x[b] >> 25)) & 0xFFFFFFFF

    for pos in range(0, len(ciphertext), 64):
        block_counter = struct.pack("<I", counter)
        state = state_const + k + list(struct.unpack("<4I", block_counter + nonce))
        x = state[:]
        for _ in range(10):
            qr(x, 0, 4, 8, 12)
            qr(x, 1, 5, 9, 13)
            qr(x, 2, 6, 10, 14)
            qr(x, 3, 7, 11, 15)
            qr(x, 0, 5, 10, 15)
            qr(x, 1, 6, 11, 12)
            qr(x, 2, 7, 8, 13)
            qr(x, 3, 4, 9, 14)
        ks_state = [(x[i] + state[i]) & 0xFFFFFFFF for i in range(16)]
        ks = b"".join(struct.pack("<I", v) for v in ks_state)
        chunk = ciphertext[pos : pos + 64]
        out.extend(b ^ ks[i] for i, b in enumerate(chunk))
        counter += 1

    return bytes(out)


def test_roundtrip() -> None:
    plaintext = os.urandom(1024)
    key = os.urandom(32)
    nonce, ciphertext, mac = encrypt_payload(plaintext, key)

    # HMAC over ciphertext
    expected_mac = hmac.new(key, ciphertext, hashlib.sha256).digest()
    assert mac == expected_mac, "HMAC mismatch"

    # Decrypt with pycryptodome
    dec_pcd = ChaCha20.new(key=key, nonce=nonce).decrypt(ciphertext)
    assert dec_pcd == plaintext, "pycryptodome decrypt mismatch"

    # Decrypt with the standalone IETF implementation
    dec_py = chacha20_ietf_decrypt(key, nonce, ciphertext)
    assert dec_py == plaintext, "pure-python decrypt mismatch"


def test_payload_sizes() -> None:
    for size in (0, 1, 63, 64, 65, 1023, 1024, 1025, 65535, 65536, 100000):
        plaintext = os.urandom(size)
        key = os.urandom(32)
        nonce, ciphertext, mac = encrypt_payload(plaintext, key)
        assert len(nonce) == 12
        assert len(ciphertext) == size
        assert len(mac) == 32
        assert ChaCha20.new(key=key, nonce=nonce).decrypt(ciphertext) == plaintext


if __name__ == "__main__":
    test_roundtrip()
    test_payload_sizes()
    print("[+] all crypto tests passed")
