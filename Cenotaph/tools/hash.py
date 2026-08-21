#!/usr/bin/env python3
"""
Cenotaph hash verifier — confirms the FNV1a-32 constants Cenotaph uses.

FNV1a-32, case-insensitive (uppercased before hashing), seed 0x811c9dc5,
prime 0x01000193.  This is byte-identical to NaX's src_loader hashing
(Constexpr.h / Utils.c).  The wide-path null handling matches NaX's
Utils.c exactly (verified against H_MODULE_NTDLL / H_MODULE_KERNEL32).

Usage:
  python3 tools/hash.py                 # print module + API hashes
  python3 tools/hash.py NtAllocateVirtualMemory TpAllocWork ...
"""
import sys

KEY, PRIME = 0x811c9dc5, 0x01000193
MASK = 0xFFFFFFFF

def fnv_ascii(s):
    h = KEY
    for ch in s.upper():
        h = ((h ^ ord(ch)) * PRIME) & MASK
    return h

def fnv_wide(name):
    # UTF-16LE; reproduce NaX Utils.c: on a 0 byte, do (h*prime) [xor 0]
    # and advance ONE byte, then the loop's trailing ++ advances another.
    data = name.encode('utf-16-le')
    h = KEY
    i = 0
    n = len(data)
    while True:
        if i >= n:
            break
        c = data[i]
        # the null-half case: ++Ptr (skip this byte), then hash stale Char(0)+++Ptr
        if c == 0:
            i += 1           # if(!*Ptr) ++Ptr;
            h = (h * PRIME) & MASK   # Hash ^= 0; Hash *= prime
            i += 1           # ++Ptr (loop tail)
            continue
        if c >= ord('a'):
            c -= 0x20
        h = ((h ^ c) * PRIME) & MASK
        i += 1
    return h

MODULES = {"ntdll.dll": 0x318a7963, "kernel32.dll": 0x04a1a06a}
APIS = ["NtAllocateVirtualMemory","NtProtectVirtualMemory","NtQuerySystemInformation",
        "TpAllocWork","TpPostWork","TpReleaseWork","GetModuleFileNameW",
        "CreateFileW","ReadFile","GetFileSize"]

def main():
    args = sys.argv[1:]
    names = args if args else (list(MODULES) + APIS)
    for nm in names:
        if nm.lower().endswith(".dll"):
            got, tgt = fnv_wide(nm.lower()), MODULES.get(nm.lower())
            tag = f"  target=0x{tgt:08x} {'OK' if tgt==got else 'MISMATCH'}" if tgt else ""
            print(f"{nm:24s} wide  = 0x{got:08x}{tag}")
        else:
            print(f"{nm:24s} ascii = 0x{fnv_ascii(nm):08x}")

if __name__ == "__main__":
    main()