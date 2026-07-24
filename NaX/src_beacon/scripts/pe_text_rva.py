#!/usr/bin/env python3
"""Print the .text section VirtualAddress (RVA) from a PE file as 8 hex chars."""
import struct, sys

with open(sys.argv[1], "rb") as f:
    f.seek(0x3C)
    pe_off = struct.unpack("<I", f.read(4))[0]

    f.seek(pe_off + 4)  # skip "PE\0\0"
    num_sections = struct.unpack("<HH", f.read(4))[1]  # machine, num_sections
    f.read(12)  # skip rest of COFF timestamps etc
    opt_size = struct.unpack("<H", f.read(2))[0]
    f.read(2)  # characteristics

    sec_table = pe_off + 4 + 20 + opt_size

    for i in range(num_sections):
        f.seek(sec_table + i * 40)
        name = f.read(8).rstrip(b"\x00").decode("ascii", errors="replace")
        vsize, vaddr = struct.unpack("<II", f.read(8))
        if name == ".text":
            print(f"{vaddr:08x}")
            sys.exit(0)

print("ERROR: .text section not found", file=sys.stderr)
sys.exit(1)
