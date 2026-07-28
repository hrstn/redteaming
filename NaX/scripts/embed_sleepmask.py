#!/usr/bin/env python3
"""Embed the sleepmask BOF COFF object into a C header for the beacon.

Reads src_sleepmask/dist/sleepmask.x64.o and writes
src_beacon/include/Config_sleepmask.h, which defines NAX_SLEEPMASK_WRITE(p) --
a `do { ... } while(0)` block that copies the raw COFF bytes into a buffer `p`
via qword writes (little-endian) with a per-byte tail for the final <8 bytes.

Also prints the NAX_SLEESMASK_LEN value to update src_beacon/include/Config.h
(kept separate so Config.h stays hand-edited).

Usage:
    python3 scripts/embed_sleepmask.py            # writes the header
    python3 scripts/embed_sleepmask.py --check    # only verify the .o matches
"""

import os
import sys
import struct

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BOF  = os.path.join(ROOT, "src_sleepmask", "dist", "sleepmask.x64.o")
OUT  = os.path.join(ROOT, "src_beacon", "include", "Config_sleepmask.h")


def main():
    check = "--check" in sys.argv
    if not os.path.exists(BOF):
        sys.exit(f"sleepmask BOF not found: {BOF} (build it first: make -C src_sleepmask debug)")
    with open(BOF, "rb") as f:
        data = f.read()
    n = len(data)

    if check:
        print(f"BOF size = {n}")
        return

    full = n // 8
    tail = n % 8

    lines = []
    lines.append("/* Config_sleepmask.h - auto-generated sleepmask BOF embed")
    lines.append(f" * {n} bytes, included by Config.h */")
    lines.append("")
    lines.append("#define NAX_SLEEPMASK_WRITE( p ) do { \\")
    for i in range(full):
        off = i * 8
        qw = struct.unpack_from("<Q", data, off)[0]
        lines.append(f"    *(unsigned long long*)((p)+{off}) = 0x{qw:016X}ULL; \\")
    for j in range(tail):
        off = full * 8 + j
        b = data[off]
        lines.append(f"    (p)[{off}]=0x{b:02X}; \\")
    lines.append("} while(0)")
    lines.append("")

    with open(OUT, "w", newline="\n") as f:
        f.write("\n".join(lines))

    print(f"[+] wrote {OUT} ({n} bytes, {full} qwords + {tail} tail bytes)")
    print(f"[+] update src_beacon/include/Config.h:  #define NAX_SLEEPMASK_LEN  {n}u")


if __name__ == "__main__":
    main()