#!/usr/bin/env python3
"""
Chain validation script.

Usage:
    python3 tests/validate_chain.py --chain "xor:KEY=0xAA,rc4:KEY=hello,rot:N=13"
    python3 tests/validate_chain.py --chain "aes256:KEY=MySecret" --input shellcode.bin
    python3 tests/validate_chain.py --all

Verifies that encrypt→decrypt round-trip returns the original data for every
algorithm combination used in the chain.  Exits 0 on success, 1 on failure.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.chain import parse_chain_spec, apply_chain, build_single_stage
from modules import crypto


DEFAULT_PLAINTEXT = b'\x90\xcc\x41\x42\x43' * 20  # 100 bytes of mixed data


def decrypt_chain(ciphertext: bytes, metadata: list[dict]) -> bytes:
    """Apply reverse-order decryption matching the chain metadata."""
    result = ciphertext
    for stage in reversed(metadata):
        algo = stage['algo']
        if algo == 'xor':
            result = crypto.xor_decrypt(result, stage['key'])
        elif algo == 'rc4':
            result = crypto.rc4_decrypt(result, stage['key'])
        elif algo == 'aes256':
            result = crypto.aes256_cbc_decrypt(result, stage['key'], stage['iv'])
        elif algo == 'rot':
            result = crypto.rot_decrypt(result, stage['n'])
        else:
            raise ValueError(f"Unknown algo in metadata: {algo}")
    return result


def validate_single_chain(chain_str: str, plaintext: bytes) -> bool:
    print(f"\n{'='*60}")
    print(f"Chain: {chain_str}")
    print(f"Input: {len(plaintext)} bytes")

    try:
        stages = parse_chain_spec(chain_str)
        ct, metadata = apply_chain(plaintext, stages)
        print(f"Encrypted: {len(ct)} bytes")

        for i, m in enumerate(metadata):
            algo = m['algo']
            if algo in ('xor', 'rc4'):
                print(f"  Stage {i+1}: {algo.upper()} key={m['key'].hex()}")
            elif algo == 'aes256':
                print(f"  Stage {i+1}: AES-256-CBC key={m['key'].hex()} iv={m['iv'].hex()}")
            elif algo == 'rot':
                print(f"  Stage {i+1}: ROT-N N={m['n']}")

        recovered = decrypt_chain(ct, metadata)
        if recovered == plaintext:
            print(f"[PASS] Decrypt -> original data matches")
            return True
        else:
            print(f"[FAIL] Decrypt -> mismatch!")
            print(f"  Expected: {plaintext[:16].hex()}...")
            print(f"  Got:      {recovered[:16].hex()}...")
            return False

    except Exception as e:
        print(f"[ERROR] {e}")
        return False


def run_all_validations(plaintext: bytes) -> bool:
    test_chains = [
        # Single algorithms
        "xor:KEY=0xAA",
        "xor:KEY=0xDEADBEEF",
        "rc4:KEY=TestKey123",
        "rot:N=13",
        "rot:N=255",
        "rot:N=1",

        # Two-layer chains
        "xor:KEY=0xAA,rot:N=13",
        "rc4:KEY=hello,xor:KEY=0xBB",
        "rot:N=7,xor:KEY=0xCC",

        # Three-layer chains
        "xor:KEY=0xAA,rc4:KEY=chainkey,rot:N=42",
        "rot:N=13,xor:KEY=0x1F,rc4:KEY=finalkey",

        # Random keys (no KEY param)
        "xor",
        "rc4",
        "xor,rot:N=5",
    ]

    # Add AES if available
    try:
        from Crypto.Cipher import AES
        test_chains += [
            "aes256:KEY=MySecretKey",
            "aes256:KEY=s3cr3t,xor:KEY=0xAA",
            "xor:KEY=0xBB,aes256:KEY=layered",
        ]
        print("[+] pycryptodome available – AES chains included")
    except ImportError:
        print("[!] pycryptodome not installed – skipping AES chains")

    results = []
    for chain in test_chains:
        ok = validate_single_chain(chain, plaintext)
        results.append(ok)

    passed = sum(results)
    total  = len(results)
    print(f"\n{'='*60}")
    print(f"Results: {passed}/{total} chains passed")
    if passed == total:
        print("[ALL PASS]")
    else:
        print("[FAILURES DETECTED]")
    return passed == total


def main():
    parser = argparse.ArgumentParser(description="Validate encryption chain round-trips")
    parser.add_argument('--chain', help='Chain spec to validate, e.g. "xor:KEY=0xAA,rot:N=13"')
    parser.add_argument('--input', help='Input file (binary). Uses built-in test data if omitted.')
    parser.add_argument('--all', action='store_true', help='Run all built-in validation chains')
    args = parser.parse_args()

    if args.input:
        with open(args.input, 'rb') as f:
            plaintext = f.read()
        print(f"[*] Loaded {len(plaintext)} bytes from {args.input}")
    else:
        plaintext = DEFAULT_PLAINTEXT
        print(f"[*] Using built-in test data ({len(plaintext)} bytes)")

    if args.all:
        ok = run_all_validations(plaintext)
    elif args.chain:
        ok = validate_single_chain(args.chain, plaintext)
    else:
        parser.print_help()
        sys.exit(1)

    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
