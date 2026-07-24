#!/usr/bin/env python3
"""sim_register.py - simulate a NoNameAx implant well enough to exercise the
server-side REGISTER path without booting a Windows VM.

Usage:
    pip install --user cryptography
    ./extender/tools/sim_register.py \
        --url http://127.0.0.1:8080/api/v1/status \
        --key <32-hex-char encrypt_key from your listener UI>

What it does:
    1. Generates a fake X-Beacon-Id (16 hex chars).
    2. Builds a wire-v0 REGISTER body (hostname, username, arch, pid, sleep).
    3. Wraps it in the 4-byte frame header.
    4. AES-128-CBC encrypts with a random IV.
    5. POSTs to the listener URI with the X-Beacon-Id header.
    6. Decrypts the response, verifies it's a NO_TASKS frame.

Exits 0 on success, nonzero with a printed reason on failure.
"""
import argparse
import os
import secrets
import struct
import sys

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import urllib.request
import urllib.error


WIRE_TYPE_REGISTER = 0x01
WIRE_TYPE_NO_TASKS = 0x80


def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    ct = cipher.encryptor()
    return iv + ct.update(padded) + ct.finalize()


def aes_decrypt(key: bytes, envelope: bytes) -> bytes:
    iv, body = envelope[:16], envelope[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(body) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def build_register_body(hostname: str, username: str, pid: int, sleep_ms: int) -> bytes:
    hb = hostname.encode()
    ub = username.encode()
    return (
        struct.pack("<H", len(hb)) + hb +
        struct.pack("<H", len(ub)) + ub +
        bytes([0x01]) +  # arch x64
        struct.pack("<I", pid) +
        struct.pack("<I", sleep_ms)
    )


def build_frame(msg_type: int, body: bytes) -> bytes:
    return bytes([msg_type, 0x00]) + struct.pack("<H", len(body)) + body


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True, help="full beacon URL")
    ap.add_argument("--key", required=True, help="32 hex chars (16 byte AES key)")
    ap.add_argument("--hostname", default="SIM-HOST")
    ap.add_argument("--username", default="simuser")
    ap.add_argument("--pid", type=int, default=1337)
    ap.add_argument("--sleep-ms", type=int, default=10000)
    args = ap.parse_args()

    try:
        key = bytes.fromhex(args.key)
    except ValueError:
        sys.exit("ERR: --key must be hex")
    if len(key) != 16:
        sys.exit("ERR: --key must decode to exactly 16 bytes")

    beacon_id = secrets.token_hex(8)  # 16 hex chars
    body = build_register_body(args.hostname, args.username, args.pid, args.sleep_ms)
    frame = build_frame(WIRE_TYPE_REGISTER, body)
    envelope = aes_encrypt(key, frame)

    print(f"sim: POST {args.url}")
    print(f"sim: X-Beacon-Id: {beacon_id}")
    print(f"sim: plaintext frame ({len(frame)} bytes): {frame.hex()}")
    print(f"sim: envelope ({len(envelope)} bytes): {envelope.hex()[:64]}...")

    req = urllib.request.Request(args.url, data=envelope, method="POST")
    req.add_header("X-Beacon-Id", beacon_id)
    req.add_header("Content-Type", "application/octet-stream")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = resp.status
            reply = resp.read()
    except urllib.error.HTTPError as e:
        sys.exit(f"ERR: HTTP {e.code}: {e.read()[:200]!r}")
    except urllib.error.URLError as e:
        sys.exit(f"ERR: network: {e}")

    if status != 200:
        sys.exit(f"ERR: expected 200, got {status}")
    if len(reply) < 20:
        sys.exit(f"ERR: response too short ({len(reply)} bytes); expected IV+ciphertext")

    try:
        plaintext = aes_decrypt(key, reply)
    except Exception as e:
        sys.exit(f"ERR: response failed to decrypt: {e}")

    if len(plaintext) != 4 or plaintext[0] != WIRE_TYPE_NO_TASKS:
        sys.exit(f"ERR: response frame was not NO_TASKS: {plaintext.hex()}")

    print(f"sim: response OK (NO_TASKS).")
    print(f"sim: agentId {beacon_id} should now appear in the Adaptix Sessions tab.")


if __name__ == "__main__":
    main()
