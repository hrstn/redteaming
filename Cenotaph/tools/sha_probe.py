#!/usr/bin/env python3
"""Explain a nonstandard SHA-256 digest computed by cenotaph-debug.exe.

The debug build prints sha-abc = SHA256("abc") using its own C implementation.
This tool re-implements the same C code with deviation knobs and brute-forces
which knob combination (if any) reproduces the observed digest, on the
1-block input "abc".

Usage: sha_probe.py <calc-mac-or-sha-abc-hex>   # 64 hex chars
       sha_probe.py                              # sweeps everything, prints table
"""
import hashlib
import itertools
import re
import struct
import sys
from pathlib import Path

HOST = Path(__file__).resolve().parent.parent / "src" / "Host.c"
EXE = Path.home() / "Downloads" / "cenotaph-debug.exe"

STD_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

STD_H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
         0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

M32 = 0xFFFFFFFF


def load_K_table():
    """Parse CenK256[] from Host.c src AND every 256-byte aligned dword run in
    the debug exe, returning candidate name -> tuple-of-64 table."""
    tables = {"src": None, "std": tuple(STD_K)}

    txt = HOST.read_text()
    m = re.search(r"CenK256\[64\]\s*=\s*\{(.*?)\}", txt, re.S)
    if m:
        vals = [int(x, 16) & M32 for x in re.findall(r"0x[0-9a-fA-F]+", m.group(1))]
        if len(vals) == 64:
            tables["src"] = tuple(vals)

    blob = EXE.read_bytes() if EXE.exists() else b""
    le = b"".join(struct.pack("<I", v) for v in STD_K)
    for off in range(0, len(blob) - 256):
        if blob[off:off + 12] == le[:12]:
            tables[f"exe@0x{off:x}"] = struct.unpack_from("<64I", blob, off)
    return tables


def ror(x, n): return ((x >> n) | (x << (32 - n))) & M32
def rol(x, n): return ((x << n) | (x >> (32 - n))) & M32


def rotr(x, n, neg): return rol(x, n) if neg else ror(x, n)


def sha256_c(msg, k_table, sched_le, write_le, len_le, swap_ep, swap_sig,
             h0=None, k_off=0):
    """Mirror of CenSha256*() in Host.c with deviation knobs."""
    st = list(h0 if h0 is not None else STD_H)
    total = len(msg)

    def transform(block):
        read = struct.unpack("<16I", block) if sched_le else struct.unpack(">16I", block)
        m = list(read)
        for i in range(16, 64):
            s1 = rotr(m[i - 2], 17, swap_sig) ^ rotr(m[i - 2], 19, swap_sig) ^ (m[i - 2] >> 10)
            s0 = rotr(m[i - 15], 7, swap_sig) ^ rotr(m[i - 15], 18, swap_sig) ^ (m[i - 15] >> 3)
            m.append((s1 + m[i - 7] + s0 + m[i - 16]) & M32)
        a, b, c, d, e, f, g, h = st
        for i in range(64):
            ep1 = rotr(e, 6, swap_ep) ^ rotr(e, 11, swap_ep) ^ rotr(e, 25, swap_ep)
            ch = (e & f) ^ (~e & g)
            t1 = (h + ep1 + ch + k_table[(i + k_off) & 63] + m[i]) & M32
            ep0 = rotr(a, 2, swap_ep) ^ rotr(a, 13, swap_ep) ^ rotr(a, 22, swap_ep)
            mj = (a & b) ^ (a & c) ^ (b & c)
            t2 = (ep0 + mj) & M32
            h, g, f, e, d, c, b, a = g, f, e, (d + t1) & M32, c, b, a, (t1 + t2) & M32
        st[0] = (st[0] + a) & M32; st[1] = (st[1] + b) & M32
        st[2] = (st[2] + c) & M32; st[3] = (st[3] + d) & M32
        st[4] = (st[4] + e) & M32; st[5] = (st[5] + f) & M32
        st[6] = (st[6] + g) & M32; st[7] = (st[7] + h) & M32

    # Final() inline: copy CenSha256Final exactly — 0x80, pad to 56, length.
    cur = list(msg) + [0x80]
    while len(cur) % 64 != 56:
        cur.append(0)
    tot_bits = total * 8
    lens = struct.pack("<Q", tot_bits) if len_le else struct.pack(">Q", tot_bits)
    padded = bytes(cur) + lens
    for off in range(0, len(padded), 64):
        transform(padded[off:off + 64])

    fmt = "<8I" if write_le else ">8I"
    return struct.pack(fmt, *st)


def sweep(target):
    """target: hex str or None (print full table). Returns matches or rows."""
    k_tabs = load_K_table()
    rows = []
    idperm = tuple(range(8))
    perms = [idperm] + list(itertools.permutations(range(8))) if target else [idperm]
    for kname, ktab in k_tabs.items():
        if ktab is None or len(ktab) != 64:
            continue
        for sched_le, write_le, len_le, swap_ep, swap_sig in itertools.product(
                (False, True), repeat=5):
            for h0p in perms:
                h0v = [STD_H[i] for i in h0p]
                dg = sha256_c(b"abc", ktab, sched_le, write_le, len_le,
                              swap_ep, swap_sig, h0=h0v)
                tag = f"{kname} sched={'LE' if sched_le else 'BE'} wr={'LE' if write_le else 'BE'} "
                tag += f"len={'LE' if len_le else 'BE'} epswap={int(swap_ep)} sigswap={int(swap_sig)}"
                if h0p != idperm:
                    tag += f" H0perm={h0p}"
                if target is None:
                    if idperm == h0p:
                        rows.append((dg.hex(), tag))
                elif dg.hex() == target:
                    rows.append((dg.hex(), tag))
    return rows


def main():
    if len(sys.argv) > 1:
        obs = sys.argv[1].strip().lower().replace(" ", "")
        obs = bytes.fromhex(obs)
        # accept either the 32B sha-abc digest or a 32B hmac/other print
        rows = sweep(obs.hex())
        if rows:
            print("MATCH:")
            for dg, tag in rows:
                print(f"  {dg}  {tag}")
        else:
            print(f"no knob combo matches {obs.hex()} (len={len(obs)})")
            print("canonical sha256('abc') =", hashlib.sha256(b"abc").hexdigest())
    else:
        rows = sweep(None)
        print(f"sha256('abc') canonical = {hashlib.sha256(b'abc').hexdigest()}")
        print(f"{len(rows)} knob combos:")
        for dg, tag in rows:
            print(f"  {dg}  {tag}")


if __name__ == "__main__":
    main()