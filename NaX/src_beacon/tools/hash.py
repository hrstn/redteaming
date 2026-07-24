#!/usr/bin/env python3
"""FNV1a-32 hash for NaX beacon API/module names - matches NaxHashStr in Ldr.c."""
import sys

def fnv1a32(s: str) -> int:
    h = 0x811C9DC5
    for c in s.upper():
        h ^= ord(c)
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} Name [Name ...]", file=sys.stderr)
        sys.exit(1)
    for name in sys.argv[1:]:
        key = name.upper().replace(".", "_").replace("-", "_")
        print(f"#define H_{key:<36}  0x{fnv1a32(name):08X}u  /* {name} */")
