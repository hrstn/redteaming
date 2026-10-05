#!/usr/bin/env python3
"""
Inspect a packed NaX binary (nax_adv.x64.bin) and print the NaxHeader v2 layout.

Usage:
    python3 scripts/inspect_nax.py bin/nax_adv.x64.bin
"""

import argparse
import struct
import sys
from pathlib import Path


NAX_HDR_MAGIC = 0x4E415832
NAX_HDR_SIZE = 160
FLAG_NAMES = {
    0x0001: "MODULE_STOMP",
    0x0002: "STOMP_PDATA",
}


def flag_strings(flags: int) -> list[str]:
    out = []
    for bit, name in FLAG_NAMES.items():
        if flags & bit:
            out.append(name)
    if not out:
        out.append("(none)")
    return out


def inspect(path: Path) -> int:
    data = path.read_bytes()
    if len(data) < NAX_HDR_SIZE + 4:
        print(f"[!] file too small: {len(data)} bytes", file=sys.stderr)
        return 1

    # Find NAX2 magic anywhere in the file
    magic_off = None
    for off in range(0, len(data) - 4, 16):
        if struct.unpack_from("<I", data, off)[0] == NAX_HDR_MAGIC:
            magic_off = off
            break

    if magic_off is None:
        print("[!] NaxHeader v2 magic (NAX2) not found", file=sys.stderr)
        return 1

    hdr = struct.unpack_from("<IIIIII", data, magic_off)
    magic, beacon_sz, pdata_sz, xdata_sz, text_rva, flags = hdr
    dll_raw = data[magic_off + 24 : magic_off + 24 + 128]
    dll_name = dll_raw.decode("utf-16-le", errors="replace").split("\x00")[0]

    loader_sz = magic_off
    beacon_off = magic_off + NAX_HDR_SIZE
    pdata_off = beacon_off + beacon_sz
    xdata_off = pdata_off + pdata_sz
    total_sz = len(data)

    print(f"[+] {path}")
    print(f"    total size      : {total_sz} bytes")
    print(f"    loader size     : {loader_sz} bytes (ends at 0x{magic_off:x})")
    print(f"    header offset   : 0x{magic_off:x}")
    print(f"    magic           : 0x{magic:08X} ({bytes.fromhex(f'{magic:08x}')[::-1].decode('ascii', errors='replace')})")
    print(f"    beacon size     : {beacon_sz} bytes @ 0x{beacon_off:x}")
    print(f"    pdata size      : {pdata_sz} bytes @ 0x{pdata_off:x} ({pdata_sz // 12} entries)")
    print(f"    xdata size      : {xdata_sz} bytes @ 0x{xdata_off:x}")
    print(f"    .text RVA       : 0x{text_rva:08X}")
    print(f"    flags           : 0x{flags:04X} ({', '.join(flag_strings(flags))})")
    print(f"    stomp DLL       : {dll_name}")
    print(f"    computed total  : {magic_off + NAX_HDR_SIZE + beacon_sz + pdata_sz + xdata_sz} bytes")

    if total_sz != magic_off + NAX_HDR_SIZE + beacon_sz + pdata_sz + xdata_sz:
        print("[!] WARNING: computed total does not match file size", file=sys.stderr)
        return 1

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect a packed NaX binary")
    parser.add_argument("path", type=Path, help="path to nax_adv.x64.bin")
    args = parser.parse_args()

    if not args.path.exists():
        print(f"[!] file not found: {args.path}", file=sys.stderr)
        return 1

    return inspect(args.path)


if __name__ == "__main__":
    sys.exit(main())
