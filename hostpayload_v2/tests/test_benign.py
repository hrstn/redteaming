#!/usr/bin/env python3
"""
Build a benign PIC test payload that exits cleanly.

This is useful for safe lab testing of the dropper without running the real
NaX beacon. The shellcode is a tiny 64-bit Windows PIC stub that calls
NtTerminateThread on the current thread with status 0.

Usage:
    python3 tests/test_benign.py --output tests/benign.x64.bin
"""

import argparse
import struct
import sys
from pathlib import Path


def build_benign_payload() -> bytes:
    """
    64-bit PIC stub that calls NtTerminateThread(NtCurrentThread(), 0).
    SSN for NtTerminateThread differs by Windows build, so this uses a
    small embedded PEB walk to locate ntdll!NtTerminateThread dynamically.
    For testing purposes we instead use a hardcoded ExitProcess via kernel32
    resolved from the PEB, but that is longer. Simpler: RtlExitUserThread
    is exported from ntdll and is SSN-independent; we can find it by export
    walk if we know the hash. However the dropper just executes the payload
    as a thread start routine, so we can return cleanly and the thread ends.

    A thread start routine returning 0 is enough. The simplest shellcode:
        xor eax, eax
        ret
    That is 3 bytes and returns 0 as thread exit code.
    """
    return bytes([
        0x31, 0xC0,  # xor eax, eax
        0xC3,        # ret
    ])


def main() -> int:
    parser = argparse.ArgumentParser(description="Build benign PIC test payload")
    parser.add_argument("--output", type=Path, required=True, help="output .bin path")
    args = parser.parse_args()

    payload = build_benign_payload()
    args.output.write_bytes(payload)
    print(f"[+] wrote {args.output} ({len(payload)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
